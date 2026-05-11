package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/eddsa/signing"
	"github.com/KarpelesLab/tss-lib/v2/tss"
	"github.com/google/uuid"

	"github.com/TibaneLabs/clawdwallet/store"
)

// SignDigest runs a 2-of-3 TSS signing ceremony over the given 32-byte digest
// using the persisted share. The returned signature is a standard 64-byte
// Ed25519 signature.
//
// signers must list exactly t+1 peers (so 2 for the default config) including
// this agent. If the caller doesn't care which co-signer is used, leave it
// nil and the agent will default to the policy evaluator.
func (a *Agent) SignDigest(ctx context.Context, digest []byte, signers []PeerSpec) ([]byte, error) {
	if a.client == nil {
		return nil, errors.New("agent not started")
	}
	sh := a.Share()
	if sh == nil {
		return nil, errors.New("no share on disk; run keygen first")
	}
	if len(digest) == 0 {
		return nil, errors.New("empty digest")
	}

	if signers == nil {
		policyID := a.cfg.PolicyID
		if policyID == "" {
			return nil, errors.New("no policy evaluator configured")
		}
		signers = []PeerSpec{
			{SpotID: a.SpotID(), Moniker: a.cfg.Moniker},
			{SpotID: policyID, Moniker: "policy"},
		}
	}
	if !containsSpotID(signers, a.SpotID()) {
		return nil, errors.New("this agent must be in the signer set")
	}
	if len(signers) < sh.Threshold+1 {
		return nil, fmt.Errorf("need at least %d signers, got %d", sh.Threshold+1, len(signers))
	}

	sid := "sg-" + uuid.NewString()
	digestB64 := base64.StdEncoding.EncodeToString(digest)

	if err := a.broadcastInit(ctx, sid, signers, &InitPayload{
		Kind:      SessionSign,
		Peers:     signers,
		Threshold: sh.Threshold,
		Message:   digestB64,
	}); err != nil {
		return nil, fmt.Errorf("broadcast sign init: %w", err)
	}

	return a.runSign(ctx, sid, signers, sh, digest)
}

func (a *Agent) joinSign(sid string, ip *InitPayload) {
	ctx, cancel := context.WithTimeout(a.ctx, 2*time.Minute)
	defer cancel()
	sh := a.Share()
	if sh == nil {
		a.log.Error("joinSign: no share")
		return
	}
	digest, err := base64.StdEncoding.DecodeString(ip.Message)
	if err != nil {
		a.log.Error("joinSign decode digest", "err", err)
		return
	}
	if _, err := a.runSign(ctx, sid, ip.Peers, sh, digest); err != nil {
		a.log.Error("joinSign", "err", err)
	}
}

// runSign instantiates a signing.LocalParty with the share and digest, then
// runs it to completion. Returns the 64-byte signature.
func (a *Agent) runSign(ctx context.Context, sid string, signers []PeerSpec, sh *store.Share, digest []byte) ([]byte, error) {
	if sh.SaveData == nil {
		return nil, errors.New("share missing tss save data")
	}
	sortedIDs := SortedPartyIDs(signers)
	myID := findMyPartyID(sortedIDs, a.SpotID())
	if myID == nil {
		return nil, errors.New("sign: this agent's PartyID could not be located")
	}
	peerCtx := tss.NewPeerContext(sortedIDs)
	params := tss.NewParameters(tss.Edwards(), peerCtx, myID, len(sortedIDs), sh.Threshold)

	outCh := make(chan tss.Message, 4*len(sortedIDs))
	endCh := make(chan *common.SignatureData, 1)

	msgInt := new(big.Int).SetBytes(digest)
	party := signing.NewLocalParty(msgInt, params, *sh.SaveData, outCh, endCh)
	session := newSession(sid, SessionSign, signers, outCh)
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
	case sd := <-endCh:
		session.finish(nil)
		if sd == nil {
			return nil, errors.New("sign: empty signature data")
		}
		sig := sd.Signature
		if len(sig) != 64 {
			return nil, fmt.Errorf("sign: unexpected signature length %d", len(sig))
		}
		return sig, nil
	case <-session.doneCh:
		if session.err != nil {
			return nil, session.err
		}
		return nil, errors.New("sign ended without producing signature")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// asJSON small helper for log lines.
func asJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
