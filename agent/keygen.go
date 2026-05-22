package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/KarpelesLab/tss-lib/v2/dklstss"
	"github.com/KarpelesLab/tss-lib/v2/frosttss"
	"github.com/KarpelesLab/tss-lib/v2/tss"

	"github.com/TibaneLabs/clawdwallet/solana"
	"github.com/TibaneLabs/clawdwallet/store"
)

// onInit handles an inbound `<my_spot_id>/walletsign/<sid>/init` message.
//
// The agent is JOIN-only: it accepts the server-issued session id, runs the
// `(curve, protocol)`-dispatched ceremony, and persists the result. Stage-2
// reshare is still gated.
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
		// deterministic.
		return nil, errors.New("reshare ceremonies are not enabled in Stage 1")
	default:
		return nil, fmt.Errorf("unknown session kind %q", ip.Kind)
	}
}

// joinKeygen drives a FROST or DKLs23 keygen for the server-issued sid.
//
// The InitPayload carries the full peer set, curve, protocol, and threshold;
// the agent sorts the peers deterministically and dispatches outbound
// JsonMessages over Spot using the walletsign recipient convention.
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
	if addrBytes := share.SolanaAddressBytes(); addrBytes != nil {
		a.cfg.SolanaAddress, _ = solana.AddressFromPubKey(addrBytes)
	}
	if err := a.cfg.Save(); err != nil {
		a.log.Warn("joinKeygen: persist config", "err", err)
	}
	if err := a.SetShare(share); err != nil {
		a.log.Error("joinKeygen: persist share", "err", err)
	}
	a.log.Info("keygen complete",
		"sid", sid,
		"schema", share.Schema,
		"address", a.cfg.SolanaAddress,
	)
}

// runKeygen sets up the broker and tss.Parameters, then dispatches to the
// FROST or DKLs23 runner per the InitPayload's (curve, protocol).
func (a *Agent) runKeygen(ctx context.Context, sid string, ip *InitPayload) (*store.Share, error) {
	curve, curveName, protocolName, err := resolveCurveProtocol(ip.Curve, ip.Protocol)
	if err != nil {
		return nil, fmt.Errorf("keygen: %w", err)
	}

	sortedIDs := SortedPartyIDs(ip.Peers)
	myID := findMyPartyID(sortedIDs, a.SpotID())
	if myID == nil {
		return nil, errors.New("keygen: this agent's PartyID could not be located")
	}
	peerCtx := tss.NewPeerContext(sortedIDs)
	params := tss.NewParameters(curve, peerCtx, myID, len(sortedIDs), ip.Threshold)

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

	a.log.Info("keygen starting",
		"sid", sid, "curve", curveName, "protocol", protocolName,
		"parties", len(sortedIDs), "threshold", ip.Threshold,
	)

	switch protocolName {
	case ProtocolFrost:
		return a.runKeygenFrost(ctx, sid, ip, session, params)
	case ProtocolDkls23:
		return a.runKeygenDkls(ctx, sid, ip, session, params)
	default:
		return nil, fmt.Errorf("keygen: protocol %q is not wired", protocolName)
	}
}

// runKeygenFrost runs a FROST(Ed25519) DKG (Pedersen DKG per RFC 9591
// Appendix D) and returns a SchemaFrost share.
func (a *Agent) runKeygenFrost(ctx context.Context, sid string, ip *InitPayload, session *Session, params *tss.Parameters) (*store.Share, error) {
	kg, err := frosttss.NewKeygen(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("frosttss keygen start: %w", err)
	}
	select {
	case k := <-kg.Done:
		session.finish(nil)
		return saveFrostShare(sid, ip, k), nil
	case err := <-kg.Err:
		session.finish(err)
		return nil, err
	case <-session.doneCh:
		return nil, session.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// runKeygenDkls runs a DKLs23 DKG (Feldman VSS) and returns a SchemaDkls23
// share. The dklstss.Key is serialised via Save() and stored verbatim — see
// store.Share.DklsBlob.
func (a *Agent) runKeygenDkls(ctx context.Context, sid string, ip *InitPayload, session *Session, params *tss.Parameters) (*store.Share, error) {
	kg, err := dklstss.NewKeygen(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("dklstss keygen start: %w", err)
	}
	select {
	case k := <-kg.Done:
		session.finish(nil)
		return saveDklsShare(sid, ip, k)
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

// saveFrostShare wraps a frosttss.Key plus session metadata in our on-disk
// SchemaFrost share. The Solana address is derived from GroupPublicKey.
func saveFrostShare(sid string, ip *InitPayload, k *frosttss.Key) *store.Share {
	if k == nil {
		return nil
	}
	sh := &store.Share{
		WalletID:    walletIDOrSid(ip, sid),
		Schema:      store.SchemaFrost,
		PeerKeys:    sharedPeerKeys(ip.Peers),
		PeerSpotIDs: sharedPeerSpotIDs(ip.Peers),
		Threshold:   ip.Threshold,
		FrostKey:    k,
	}
	if k.GroupPublicKey != nil {
		sh.PubKey = store.EdPointBytes(k.GroupPublicKey)
	}
	return sh
}

// saveDklsShare wraps a dklstss.Key plus session metadata in our on-disk
// SchemaDkls23 share. The secp256k1 public key is recorded as the
// SEC1-compressed (33-byte) form so callers can derive Bitcoin / Ethereum
// addresses without re-loading the share.
func saveDklsShare(sid string, ip *InitPayload, k *dklstss.Key) (*store.Share, error) {
	if k == nil {
		return nil, errors.New("dklstss keygen returned nil key")
	}
	var buf bytes.Buffer
	if err := k.Save(&buf); err != nil {
		return nil, fmt.Errorf("dklstss.Key.Save: %w", err)
	}
	sh := &store.Share{
		WalletID:    walletIDOrSid(ip, sid),
		Schema:      store.SchemaDkls23,
		PeerKeys:    sharedPeerKeys(ip.Peers),
		PeerSpotIDs: sharedPeerSpotIDs(ip.Peers),
		Threshold:   ip.Threshold,
		DklsBlob:    buf.Bytes(),
	}
	if k.ECDSAPub != nil {
		if pub := k.ECDSAPub.ToSecp256k1PubKey(); pub != nil {
			sh.Secp256k1Pub = pub.SerializeCompressed()
		}
	}
	return sh, nil
}

// walletIDOrSid prefers the policy-issued wallet id, falling back to the sid
// so a freshly generated share still has a stable identifier.
func walletIDOrSid(ip *InitPayload, sid string) string {
	if ip.WalletID != "" {
		return ip.WalletID
	}
	return sid
}

// sharedPeerKeys is the per-peer big.Int slot list both share schemas hold.
func sharedPeerKeys(peers []PeerSpec) []*big.Int {
	out := make([]*big.Int, 0, len(peers))
	for _, p := range SortedPartyIDs(peers) {
		out = append(out, p.KeyInt())
	}
	return out
}

// sharedPeerSpotIDs is the per-peer Spot identity list both share schemas hold.
func sharedPeerSpotIDs(peers []PeerSpec) []string {
	out := make([]string, 0, len(peers))
	for _, p := range SortedPartyIDs(peers) {
		out = append(out, p.Id)
	}
	return out
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
