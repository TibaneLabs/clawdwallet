package agent

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/KarpelesLab/tss-lib/v2/tss"

	"github.com/TibaneLabs/clawdwallet/store"
)

// wdroneTxsignInit is the wire shape wdrone's walletsign session.init parses
// for a `txsign` ceremony (see wdrone/walletsign.go:77 walletSignTxsignInit).
//
// We construct this per-recipient (Name is the recipient's own PartyID) before
// posting `<peer>/walletsign/<sid>/init`. The Peers list is the same sorted
// set for every recipient.
type wdroneTxsignInit struct {
	Peers     tss.SortedPartyIDs `json:"peers"`
	Name      *tss.PartyID       `json:"name"`
	Threshold int                `json:"threshold"`
	Curve     string             `json:"curve"`
	Digest    string             `json:"digest,omitempty"`
	// SID is informational; wdrone reads it from the path.
	SID string `json:"sid,omitempty"`
	// Type is informational; wdrone takes the session type from checkKey.
	Type string `json:"type,omitempty"`
}

// SignDigest runs a t+1-of-n TSS signing ceremony over the given digest using
// the persisted share. The returned signature is a standard 64-byte Ed25519
// signature.
//
// `sid` is the session id issued by the phplatform policy module's
// `:signRequest` response (derived from the crwsv- portion of `remote_key`).
// `signers` must list exactly t+1 peers including this agent (Stage-1 default
// is agent + wdrone; mobile sits out of signing).
//
// Per the integration-phase contract the **agent leads the sign ceremony**:
// it registers its own walletsign handler (statically armed at construction;
// the broker is wired by runSign before any peer can know the sid), sends
// `<peer>/walletsign/<sid>/init` to every co-signer with a wdrone-compatible
// init payload, then drives the local eddsatss.Signing to completion.
func (a *Agent) SignDigest(ctx context.Context, sid string, digest []byte, signers []PeerSpec) ([]byte, error) {
	if a.client == nil {
		return nil, errors.New("agent not started")
	}
	if sid == "" {
		return nil, errors.New("sign: empty session id")
	}
	if len(digest) == 0 {
		return nil, errors.New("sign: empty digest")
	}
	sh := a.Share()
	if sh == nil {
		return nil, errors.New("sign: no share on disk; run keygen first")
	}
	if !containsSpotID(signers, a.SpotID()) {
		return nil, errors.New("sign: this agent must be in the signer set")
	}
	if len(signers) < sh.Threshold+1 {
		return nil, fmt.Errorf("sign: need at least %d signers, got %d", sh.Threshold+1, len(signers))
	}

	// Build the sorted PartyID list once: every recipient gets the same Peers
	// list, only the `name` field changes (it's the recipient's own PartyID).
	sortedIDs := SortedPartyIDs(signers)
	myID := findMyPartyID(sortedIDs, a.SpotID())
	if myID == nil {
		return nil, errors.New("sign: this agent's PartyID could not be located")
	}

	// Pre-register the session BEFORE shipping init messages so the global
	// walletsign handler has a broker to route inbound frames into. Without
	// this, a fast wdrone could broadcast round-1 frames before runSign
	// publishes the session, and the agent's handler would reject them with
	// "unknown session". The broker is wired here; runSign attaches it to
	// the eddsatss params and drives the protocol.
	session := &Session{
		ID:     sid,
		Kind:   SessionSign,
		Peers:  signers,
		Self:   myID,
		doneCh: make(chan struct{}),
	}
	session.broker = newSpotBroker(myID, a.makeWireSend(session))
	a.registry.Put(session)

	for _, p := range signers {
		if p.SpotID == a.SpotID() {
			continue
		}
		peerPid := findMyPartyID(sortedIDs, p.SpotID)
		if peerPid == nil {
			a.registry.Drop(sid)
			return nil, fmt.Errorf("sign: peer %s not present in sorted party list", p.SpotID)
		}
		init := wdroneTxsignInit{
			Peers:     sortedIDs,
			Name:      peerPid,
			Threshold: sh.Threshold,
			Curve:     "ed25519",
			// wdrone's decodeDigest accepts hex (with or without 0x prefix)
			// or base64url — we emit hex so it round-trips through the
			// legacy "<hash_hex>:<il_hex>:<curve>" fallback parser too.
			Digest: hex.EncodeToString(digest),
			SID:    sid,
			Type:   string(SessionSign),
		}
		body, err := json.Marshal(init)
		if err != nil {
			a.registry.Drop(sid)
			return nil, fmt.Errorf("marshal init for %s: %w", p.SpotID, err)
		}
		if err := a.sendWalletSign(ctx, p.SpotID, sid, "init", "", body); err != nil {
			a.registry.Drop(sid)
			return nil, fmt.Errorf("init send to %s: %w", p.SpotID, err)
		}
		a.log.Info("walletsign txsign init sent",
			"sid", sid, "to", p.SpotID, "moniker", p.Moniker,
			"peers", len(sortedIDs), "threshold", sh.Threshold)
	}

	return a.runSignWithSession(ctx, session, sortedIDs, myID, sh, digest)
}

// marshalLeaderInit is exported via test-build seam for unit tests: it
// produces the exact JSON body the leader posts to a single recipient.
func marshalLeaderInit(sid string, signers []PeerSpec, recipient PeerSpec, threshold int, digest []byte) ([]byte, error) {
	sortedIDs := SortedPartyIDs(signers)
	peerPid := findMyPartyID(sortedIDs, recipient.SpotID)
	if peerPid == nil {
		return nil, fmt.Errorf("recipient %s not in signer set", recipient.SpotID)
	}
	init := wdroneTxsignInit{
		Peers:     sortedIDs,
		Name:      peerPid,
		Threshold: threshold,
		Curve:     "ed25519",
		Digest:    hex.EncodeToString(digest),
		SID:       sid,
		Type:      string(SessionSign),
	}
	return json.Marshal(init)
}

// joinSign accepts an inbound init for a `txsign` session driven by a peer
// initiator. Per the Stage-1 integration contract the agent is the sign
// LEADER (see SignDigest); joinSign exists as a safety net for the inverse
// case where another peer happens to lead a sign ceremony the agent has been
// invited into (e.g. a test harness). The resulting signature is not returned
// here — callers that need it must observe the session via the registry.
func (a *Agent) joinSign(sid string, ip *InitPayload) {
	ctx, cancel := context.WithTimeout(a.ctx, 2*time.Minute)
	defer cancel()
	sh := a.Share()
	if sh == nil {
		a.log.Error("joinSign: no share", "sid", sid)
		return
	}
	digest, err := decodeSignDigest(ip.Digest)
	if err != nil {
		a.log.Error("joinSign: decode digest", "sid", sid, "err", err)
		return
	}
	if _, err := a.runSign(ctx, sid, ip.Peers, sh, digest); err != nil {
		a.log.Error("joinSign", "sid", sid, "err", err)
	}
}

// decodeSignDigest mirrors wdrone's decodeDigest: accept hex (with or without
// `0x` prefix), base64-std, or base64-url. Returns the raw digest bytes.
func decodeSignDigest(in string) ([]byte, error) {
	if in == "" {
		return nil, errors.New("empty digest")
	}
	hexCand := in
	if len(hexCand) >= 2 && hexCand[0] == '0' && (hexCand[1] == 'x' || hexCand[1] == 'X') {
		hexCand = hexCand[2:]
	}
	if b, err := hex.DecodeString(hexCand); err == nil && len(b) > 0 {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(in); err == nil && len(b) > 0 {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(in); err == nil && len(b) > 0 {
		return b, nil
	}
	return nil, fmt.Errorf("undecodable digest %q", in)
}

// runSign is the joiner-side entry: instantiate session + broker, then drive
// the eddsatss.Signing to completion. Used by joinSign for inbound-led sign
// ceremonies (test harnesses / future Stage 2 flows).
func (a *Agent) runSign(ctx context.Context, sid string, signers []PeerSpec, sh *store.Share, digest []byte) ([]byte, error) {
	if sh.EDKey == nil {
		return nil, errors.New("sign: share missing eddsa key data")
	}
	sortedIDs := SortedPartyIDs(signers)
	myID := findMyPartyID(sortedIDs, a.SpotID())
	if myID == nil {
		return nil, errors.New("sign: this agent's PartyID could not be located")
	}
	session := &Session{
		ID:     sid,
		Kind:   SessionSign,
		Peers:  signers,
		Self:   myID,
		doneCh: make(chan struct{}),
	}
	session.broker = newSpotBroker(myID, a.makeWireSend(session))
	a.registry.Put(session)
	return a.runSignWithSession(ctx, session, sortedIDs, myID, sh, digest)
}

// runSignWithSession runs the eddsatss.Signing using a session that is
// already registered with its broker wired. Used by the leader path
// (SignDigest) so the session is published *before* init messages go out,
// closing the handler-vs-frame race for fast joiners.
func (a *Agent) runSignWithSession(ctx context.Context, session *Session, sortedIDs tss.SortedPartyIDs, myID *tss.PartyID, sh *store.Share, digest []byte) ([]byte, error) {
	if sh.EDKey == nil {
		a.registry.Drop(session.ID)
		return nil, errors.New("sign: share missing eddsa key data")
	}
	defer a.registry.Drop(session.ID)

	peerCtx := tss.NewPeerContext(sortedIDs)
	params := tss.NewParameters(tss.Edwards(), peerCtx, myID, len(sortedIDs), sh.Threshold)
	params.SetBroker(session.broker)

	msgInt := new(big.Int).SetBytes(digest)
	sg, err := sh.EDKey.NewSigning(ctx, msgInt, params)
	if err != nil {
		return nil, fmt.Errorf("eddsatss signing start: %w", err)
	}

	select {
	case sd := <-sg.Done:
		session.finish(nil)
		if sd == nil || len(sd.Signature) != 64 {
			return nil, fmt.Errorf("sign: unexpected signature length %d", len(sd.Signature))
		}
		return sd.Signature, nil
	case err := <-sg.Err:
		session.finish(err)
		return nil, err
	case <-session.doneCh:
		return nil, session.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
