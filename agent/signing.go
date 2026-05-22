package agent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/KarpelesLab/tss-lib/v2/dklstss"
	"github.com/KarpelesLab/tss-lib/v2/tss"

	"github.com/TibaneLabs/clawdwallet/store"
)

// wdroneTxsignInit is the wire shape wdrone's walletsign session.init parses
// for a `txsign` ceremony (see wdrone/walletsign.go walletSignTxsignInit).
//
// We construct this per-recipient (Name is the recipient's own PartyID)
// before posting `<peer>/walletsign/<sid>/init`. The Peers list is the same
// sorted set for every recipient. Protocol selects FROST vs DKLs23 on the
// receiver side (clawdwallet only speaks those two; the legacy GG18 paths
// are absent here).
type wdroneTxsignInit struct {
	Peers     tss.SortedPartyIDs `json:"peers"`
	Name      *tss.PartyID       `json:"name"`
	Threshold int                `json:"threshold"`
	Curve     string             `json:"curve"`
	Protocol  string             `json:"protocol,omitempty"`
	Digest    string             `json:"digest,omitempty"`
	// SID is informational; wdrone reads it from the path.
	SID string `json:"sid,omitempty"`
	// Type is informational; wdrone takes the session type from checkKey.
	Type string `json:"type,omitempty"`
}

// SignDigest runs a t+1-of-n TSS signing ceremony over the given digest
// using the persisted share. The result encoding depends on the share's
// schema:
//
//   - FROST(Ed25519): 64-byte R||S, identical to a standard Ed25519
//     signature; verifiable by any Ed25519 verifier under the share's
//     GroupPublicKey (the Solana address).
//   - DKLs23(secp256k1): 65-byte R||S||V (V is the public recovery byte),
//     matching wdrone's compact format for Ethereum-style verifiers.
//
// `sid` is the session id issued by the phplatform policy module's
// `:signRequest` response. `signers` lists exactly t+1 peers including this
// agent. The agent leads the ceremony: it registers its broker before any
// peer can know the sid, posts `<peer>/walletsign/<sid>/init` with a
// wdrone-compatible payload (including the matching `protocol`), then drives
// the local signer to completion.
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

	curveName, protocolName, err := protocolForSchema(sh.Schema)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	// Build the sorted PartyID list once: every recipient gets the same
	// Peers list, only the `name` field changes (it's the recipient's own
	// PartyID).
	sortedIDs := SortedPartyIDs(signers)
	myID := findMyPartyID(sortedIDs, a.SpotID())
	if myID == nil {
		return nil, errors.New("sign: this agent's PartyID could not be located")
	}

	// Pre-register the session BEFORE shipping init messages so the global
	// walletsign handler has a broker to route inbound frames into. Without
	// this, a fast peer could broadcast round-1 frames before runSign
	// publishes the session, and the agent's handler would reject them with
	// "unknown session". The broker is wired here; runSign attaches it to
	// the params and drives the protocol.
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
			Curve:     curveName,
			Protocol:  protocolName,
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
			"protocol", protocolName, "curve", curveName,
			"peers", len(sortedIDs), "threshold", sh.Threshold)
	}

	return a.runSignWithSession(ctx, session, sortedIDs, myID, sh, digest)
}

// protocolForSchema maps a Share.Schema to the (curve, protocol) pair the
// wire init payload should advertise. Mirrors the matrix in
// resolveCurveProtocol.
func protocolForSchema(schema string) (curve, protocol string, err error) {
	switch schema {
	case store.SchemaFrost:
		return CurveEd25519, ProtocolFrost, nil
	case store.SchemaDkls23:
		return CurveSecp256k1, ProtocolDkls23, nil
	default:
		return "", "", fmt.Errorf("unsupported share schema %q", schema)
	}
}

// marshalLeaderInit is exposed for unit tests: it produces the exact JSON
// body the leader posts to a single recipient. Defaults to a FROST(Ed25519)
// envelope when no protocol is supplied (matches the Solana-default share
// schema).
func marshalLeaderInit(sid string, signers []PeerSpec, recipient PeerSpec, threshold int, digest []byte) ([]byte, error) {
	return marshalLeaderInitFor(sid, signers, recipient, threshold, digest, CurveEd25519, ProtocolFrost)
}

// marshalLeaderInitFor lets callers pick the (curve, protocol) pair
// advertised in the wire init body. Used by tests and by SignDigest when
// dispatching DKLs23 leaders.
func marshalLeaderInitFor(sid string, signers []PeerSpec, recipient PeerSpec, threshold int, digest []byte, curve, protocol string) ([]byte, error) {
	sortedIDs := SortedPartyIDs(signers)
	peerPid := findMyPartyID(sortedIDs, recipient.SpotID)
	if peerPid == nil {
		return nil, fmt.Errorf("recipient %s not in signer set", recipient.SpotID)
	}
	init := wdroneTxsignInit{
		Peers:     sortedIDs,
		Name:      peerPid,
		Threshold: threshold,
		Curve:     curve,
		Protocol:  protocol,
		Digest:    hex.EncodeToString(digest),
		SID:       sid,
		Type:      string(SessionSign),
	}
	return json.Marshal(init)
}

// joinSign accepts an inbound init for a `txsign` session driven by a peer
// initiator. clawdwallet is normally the sign LEADER (see SignDigest);
// joinSign exists as a safety net for the inverse case where another peer
// happens to lead a sign ceremony the agent has been invited into (e.g. a
// test harness). The resulting signature is not returned here — callers
// that need it must observe the session via the registry.
func (a *Agent) joinSign(sid string, ip *InitPayload) {
	ctx, cancel := context.WithTimeout(a.ctx, 2*time.Minute)
	defer cancel()
	sh := a.Share()
	if sh == nil {
		a.log.Error("joinSign: no share", "sid", sid)
		return
	}
	digest, err := decodeDigestBytes(ip.Digest)
	if err != nil {
		a.log.Error("joinSign: decode digest", "sid", sid, "err", err)
		return
	}
	if _, err := a.runSign(ctx, sid, ip.Peers, sh, digest); err != nil {
		a.log.Error("joinSign", "sid", sid, "err", err)
	}
}

// runSign is the joiner-side entry: instantiate session + broker, then
// dispatch to the protocol-specific runner. Used by joinSign for
// inbound-led sign ceremonies (test harnesses / future Stage 2 flows).
func (a *Agent) runSign(ctx context.Context, sid string, signers []PeerSpec, sh *store.Share, digest []byte) ([]byte, error) {
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

// runSignWithSession drives the schema-matched signing runner using a
// session that is already registered with its broker wired. Used by the
// leader path (SignDigest) so the session is published *before* init
// messages go out, closing the handler-vs-frame race for fast joiners.
func (a *Agent) runSignWithSession(ctx context.Context, session *Session, sortedIDs tss.SortedPartyIDs, myID *tss.PartyID, sh *store.Share, digest []byte) ([]byte, error) {
	defer a.registry.Drop(session.ID)

	curveName, protocolName, err := protocolForSchema(sh.Schema)
	if err != nil {
		return nil, err
	}
	curve, _, _, err := resolveCurveProtocol(curveName, protocolName)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	peerCtx := tss.NewPeerContext(sortedIDs)
	params := tss.NewParameters(curve, peerCtx, myID, len(sortedIDs), sh.Threshold)
	params.SetBroker(session.broker)

	switch protocolName {
	case ProtocolFrost:
		return a.runSignFrost(ctx, session, params, sh, digest)
	case ProtocolDkls23:
		return a.runSignDkls(ctx, session, params, sortedIDs, sh, digest)
	default:
		return nil, fmt.Errorf("sign: protocol %q is not wired", protocolName)
	}
}

// runSignFrost drives a FROST(Ed25519) signing to completion. The result is
// the standard 64-byte (R || S) Ed25519 signature.
func (a *Agent) runSignFrost(ctx context.Context, session *Session, params *tss.Parameters, sh *store.Share, digest []byte) ([]byte, error) {
	if sh.FrostKey == nil {
		return nil, errors.New("sign: share missing frost key data")
	}
	sg, err := sh.FrostKey.NewSigning(ctx, digest, params)
	if err != nil {
		return nil, fmt.Errorf("frosttss signing start: %w", err)
	}
	select {
	case sd := <-sg.Done:
		session.finish(nil)
		if sd == nil || len(sd.Signature) != 64 {
			return nil, fmt.Errorf("sign: unexpected frost signature length %d", len(sd.Signature))
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

// runSignDkls drives a DKLs23 ECDSA signing to completion. The result is the
// 65-byte compact form `R || S || V` matching wdrone's reporting format —
// ready for Ethereum-style recovery verifiers.
func (a *Agent) runSignDkls(ctx context.Context, session *Session, params *tss.Parameters, sortedIDs tss.SortedPartyIDs, sh *store.Share, digest []byte) ([]byte, error) {
	key, err := sh.LoadDkls()
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	sp, err := dklstss.NewSigning(ctx, params, key, digest, sortedIDs, nil)
	if err != nil {
		return nil, fmt.Errorf("dklstss signing start: %w", err)
	}
	select {
	case s := <-sp.Done:
		session.finish(nil)
		r := bigIntToFixed(s.R, 32)
		ss := bigIntToFixed(s.S, 32)
		out := make([]byte, 0, 65)
		out = append(out, r...)
		out = append(out, ss...)
		out = append(out, s.V)
		return out, nil
	case err := <-sp.Err:
		session.finish(err)
		return nil, err
	case <-session.doneCh:
		return nil, session.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
