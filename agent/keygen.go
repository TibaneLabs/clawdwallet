package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/KarpelesLab/tss-lib/v2/eddsatss"
	"github.com/KarpelesLab/tss-lib/v2/tss"

	"github.com/TibaneLabs/clawdwallet/solana"
	"github.com/TibaneLabs/clawdwallet/store"
)

// onInit handles an inbound `<my_spot_id>/walletsign/<sid>/init` message.
//
// Per Stage 1 the agent is JOIN-only: it accepts the server-issued session id,
// runs the appropriate `eddsatss` ceremony, and persists the result. Stage-2
// reshare and any other initiator-side flow are deferred.
func (a *Agent) onInit(sid, from string, ip *InitPayload) ([]byte, error) {
	switch ip.Kind {
	case SessionKeygen:
		go a.joinKeygen(sid, ip)
		return []byte(`{"accepted":true}`), nil
	case SessionSign:
		go a.joinSign(sid, ip)
		return []byte(`{"accepted":true}`), nil
	case SessionReshare:
		// Stage 2: reshare is flag-gated; reject early so the demo path is
		// deterministic. The reshare driver is still present but unwired.
		return nil, errors.New("reshare ceremonies are not enabled in Stage 1")
	default:
		return nil, fmt.Errorf("unknown session kind %q", ip.Kind)
	}
}

// joinKeygen drives an `eddsatss.NewKeygen` party for the server-issued sid.
//
// The InitPayload carries the full peer set and threshold; the agent sorts
// them deterministically and dispatches outbound JsonMessages over Spot using
// the walletsign recipient convention.
func (a *Agent) joinKeygen(sid string, ip *InitPayload) {
	ctx, cancel := context.WithTimeout(a.ctx, 5*time.Minute)
	defer cancel()

	if !containsSpotID(ip.Peers, a.SpotID()) {
		a.log.Error("joinKeygen: this agent is not in the peer set", "sid", sid)
		return
	}

	share, err := a.runKeygen(ctx, sid, ip)
	if err != nil {
		a.log.Error("joinKeygen", "sid", sid, "err", err)
		return
	}

	a.cfg.WalletID = share.WalletID
	a.cfg.SolanaAddress, _ = solana.AddressFromPubKey(share.SolanaAddressBytes())
	if err := a.cfg.Save(); err != nil {
		a.log.Warn("joinKeygen: persist config", "err", err)
	}
	if err := a.SetShare(share); err != nil {
		a.log.Error("joinKeygen: persist share", "err", err)
	}
	a.log.Info("keygen complete", "sid", sid, "address", a.cfg.SolanaAddress)
}

// runKeygen instantiates an eddsatss.NewKeygen tied to a per-session
// spotBroker. The broker bridges the protocol's outbound JsonMessages to the
// walletsign Spot path, and feeds inbound peer frames back into the protocol.
func (a *Agent) runKeygen(ctx context.Context, sid string, ip *InitPayload) (*store.Share, error) {
	sortedIDs := SortedPartyIDs(ip.Peers)
	myID := findMyPartyID(sortedIDs, a.SpotID())
	if myID == nil {
		return nil, errors.New("keygen: this agent's PartyID could not be located")
	}
	peerCtx := tss.NewPeerContext(sortedIDs)
	params := tss.NewParameters(tss.Edwards(), peerCtx, myID, len(sortedIDs), ip.Threshold)

	session := &Session{
		ID:     sid,
		Kind:   SessionKeygen,
		Peers:  ip.Peers,
		Self:   myID,
		doneCh: make(chan struct{}),
	}
	session.broker = newSpotBroker(myID, a.makeWireSend(session))
	params.SetBroker(session.broker)

	a.registry.Put(session)
	defer a.registry.Drop(sid)

	kg, err := eddsatss.NewKeygen(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("eddsatss keygen start: %w", err)
	}

	select {
	case k := <-kg.Done:
		session.finish(nil)
		return saveDataFromKey(sid, ip, k), nil
	case err := <-kg.Err:
		session.finish(err)
		return nil, err
	case <-session.doneCh:
		return nil, session.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// makeWireSend returns the outbound JsonMessage publisher closure used by the
// session broker. Broadcasts fan out to every peer except self with suffix
// `broadcast`; p2p messages target a single peer with suffix `single`.
//
// Sender format follows the wdrone convention: `<my_spot_id>/<sid>/<my_party_id>`.
func (a *Agent) makeWireSend(s *Session) func(context.Context, *tss.JsonMessage) {
	return func(ctx context.Context, jm *tss.JsonMessage) {
		body, err := json.Marshal(jm)
		if err != nil {
			a.log.Error("walletsign: marshal outbound", "sid", s.ID, "err", err)
			return
		}
		partyID := ""
		if jm.From != nil {
			partyID = jm.From.Id
		}
		if jm.To == nil {
			for _, p := range s.Peers {
				if p.SpotID == a.SpotID() {
					continue
				}
				if err := a.sendWalletSign(ctx, p.SpotID, s.ID, "broadcast", partyID, body); err != nil {
					a.log.Error("walletsign: broadcast", "to", p.SpotID, "sid", s.ID, "err", err)
				}
			}
			return
		}
		// p2p: msg.To.Id is the peer's Spot id (PartyID.Id == SpotID).
		if jm.To.Id == a.SpotID() {
			return
		}
		if err := a.sendWalletSign(ctx, jm.To.Id, s.ID, "single", partyID, body); err != nil {
			a.log.Error("walletsign: p2p", "to", jm.To.Id, "sid", s.ID, "err", err)
		}
	}
}

// saveDataFromKey wraps an eddsatss.Key plus session metadata in our on-disk
// share schema. The `WalletID` is left as the server-issued sid for traceability;
// callers may overwrite it with the canonical crws- id when known.
func saveDataFromKey(sid string, ip *InitPayload, k *eddsatss.Key) *store.Share {
	if k == nil {
		return nil
	}
	keys := make([]*big.Int, 0, len(ip.Peers))
	spotIDs := make([]string, 0, len(ip.Peers))
	sorted := SortedPartyIDs(ip.Peers)
	for _, p := range sorted {
		keys = append(keys, p.KeyInt())
		spotIDs = append(spotIDs, p.Id)
	}
	walletID := ip.WalletID
	if walletID == "" {
		walletID = sid
	}
	sh := &store.Share{
		WalletID:    walletID,
		PeerKeys:    keys,
		PeerSpotIDs: spotIDs,
		Threshold:   ip.Threshold,
		EDKey:       k,
	}
	if k.EDDSAPub != nil {
		sh.PubKey = store.EdPointBytes(k.EDDSAPub)
	}
	return sh
}

func containsSpotID(peers []PeerSpec, id string) bool {
	for _, p := range peers {
		if p.SpotID == id {
			return true
		}
	}
	return false
}

func findMyPartyID(sorted tss.SortedPartyIDs, mySpot string) *tss.PartyID {
	for _, p := range sorted {
		if p.Id == mySpot {
			return p
		}
	}
	return nil
}
