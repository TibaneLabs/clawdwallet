package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/KarpelesLab/tss-lib/v2/eddsa/keygen"
	"github.com/KarpelesLab/tss-lib/v2/tss"
	"github.com/google/uuid"

	"github.com/TibaneLabs/clawdwallet/solana"
	"github.com/TibaneLabs/clawdwallet/store"
)

// Keygen runs a 3-party EdDSA keygen ceremony with the given peers (which
// must include this agent) and persists the resulting share on success.
//
// threshold is t in t-of-n; for the canonical 2-of-3 wallet this is 1.
func (a *Agent) Keygen(ctx context.Context, peers []PeerSpec, threshold int) (*store.Share, error) {
	if a.client == nil {
		return nil, errors.New("agent not started")
	}
	if !containsSpotID(peers, a.SpotID()) {
		return nil, errors.New("keygen: this agent is not in the peer set")
	}
	sid := "kg-" + uuid.NewString()

	// Tell every remote peer to spin up its party for this session.
	if err := a.broadcastInit(ctx, sid, peers, &InitPayload{
		Kind:      SessionKeygen,
		Peers:     peers,
		Threshold: threshold,
	}); err != nil {
		return nil, fmt.Errorf("broadcast init: %w", err)
	}

	// Run our own keygen party locally and wait for its end channel.
	share, err := a.runKeygen(ctx, sid, peers, threshold)
	if err != nil {
		return nil, err
	}

	a.cfg.WalletID = share.WalletID
	a.cfg.SolanaAddress, _ = solana.AddressFromPubKey(share.SolanaAddressBytes())
	_ = a.cfg.Save()
	return share, a.SetShare(share)
}

// runKeygen instantiates a keygen.LocalParty and pumps its channels until done.
func (a *Agent) runKeygen(ctx context.Context, sid string, peers []PeerSpec, threshold int) (*store.Share, error) {
	sortedIDs := SortedPartyIDs(peers)
	myID := findMyPartyID(sortedIDs, a.SpotID())
	if myID == nil {
		return nil, errors.New("keygen: this agent's PartyID could not be located")
	}
	peerCtx := tss.NewPeerContext(sortedIDs)
	params := tss.NewParameters(tss.Edwards(), peerCtx, myID, len(sortedIDs), threshold)

	outCh := make(chan tss.Message, 4*len(sortedIDs))
	endCh := make(chan *keygen.LocalPartySaveData, 1)

	party := keygen.NewLocalParty(params, outCh, endCh)
	session := newSession(sid, SessionKeygen, peers, outCh)
	session.party = party
	a.registry.Put(session)
	defer a.registry.Drop(sid)

	go a.pumpOutbound(session)

	go func() {
		if err := party.Start(); err != nil {
			session.finish(err)
		}
	}()

	select {
	case data := <-endCh:
		session.finish(nil)
		return saveDataToShare(sid, peers, threshold, data), nil
	case <-session.doneCh:
		if session.err != nil {
			return nil, session.err
		}
		return nil, errors.New("keygen ended without producing share")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// onInit handles an inbound "init" message from a peer. We accept it, spin up
// a matching party, and pump.
func (a *Agent) onInit(sid, from string, ip *InitPayload) ([]byte, error) {
	switch ip.Kind {
	case SessionKeygen:
		go a.joinKeygen(sid, ip)
		return []byte(`{"accepted":true}`), nil
	case SessionSign:
		go a.joinSign(sid, ip)
		return []byte(`{"accepted":true}`), nil
	case SessionReshare:
		go a.joinReshare(sid, ip)
		return []byte(`{"accepted":true}`), nil
	default:
		return nil, fmt.Errorf("unknown session kind %q", ip.Kind)
	}
}

func (a *Agent) joinKeygen(sid string, ip *InitPayload) {
	ctx, cancel := context.WithTimeout(a.ctx, 5*time.Minute)
	defer cancel()
	share, err := a.runKeygen(ctx, sid, ip.Peers, ip.Threshold)
	if err != nil {
		a.log.Error("joinKeygen", "sid", sid, "err", err)
		return
	}
	a.cfg.WalletID = share.WalletID
	a.cfg.SolanaAddress, _ = solana.AddressFromPubKey(share.SolanaAddressBytes())
	_ = a.cfg.Save()
	if err := a.SetShare(share); err != nil {
		a.log.Error("persist share", "err", err)
	}
}

// saveDataToShare wraps tss-lib's output in our on-disk schema.
func saveDataToShare(sid string, peers []PeerSpec, threshold int, data *keygen.LocalPartySaveData) *store.Share {
	keys := make([]*big.Int, 0, len(peers))
	spotIDs := make([]string, 0, len(peers))
	sorted := SortedPartyIDs(peers)
	for _, p := range sorted {
		keys = append(keys, p.KeyInt())
		spotIDs = append(spotIDs, p.Id)
	}
	sh := &store.Share{
		WalletID:    sid,
		PartyKey:    nil, // filled by caller via findMyPartyID if needed
		PeerKeys:    keys,
		PeerSpotIDs: spotIDs,
		Threshold:   threshold,
		SaveData:    data,
	}
	if data != nil && data.EDDSAPub != nil {
		sh.PubKey = store.EdPointBytes(data.EDDSAPub)
	}
	return sh
}

// broadcastInit sends the InitPayload to every peer except us.
func (a *Agent) broadcastInit(ctx context.Context, sid string, peers []PeerSpec, payload *InitPayload) error {
	pb, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	body, err := json.Marshal(WalletEnvelope{
		Action:     WalletInit,
		SessionID:  sid,
		FromSpotID: a.SpotID(),
		Payload:    pb,
	})
	if err != nil {
		return err
	}
	for _, p := range peers {
		if p.SpotID == a.SpotID() {
			continue
		}
		sendCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := a.client.SendToWithFrom(sendCtx, p.SpotID+"/wallet", body, "wallet")
		cancel()
		if err != nil {
			return fmt.Errorf("init send to %s: %w", p.SpotID, err)
		}
	}
	return nil
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

