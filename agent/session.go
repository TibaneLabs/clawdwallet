package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// SessionKind names the TSS ceremony a session is running.
//
// String values follow the canonical wdrone/phplatform vocabulary so that
// JSON-serialised InitPayloads round-trip across the three TSS parties:
// `txsign` (NOT `sign`) is the Stage-1 EdDSA signing ceremony, distinct from
// the legacy wdrone `sign` SMS flow.
type SessionKind string

const (
	SessionKeygen  SessionKind = "keygen"
	SessionSign    SessionKind = "txsign"
	SessionReshare SessionKind = "reshare"
)

// InitPayload is the bare body of a `<peer>/walletsign/<sid>/init` message.
//
// Wire shape:
//
//	{
//	  "sid":  "<crwsv-...>",
//	  "type": "keygen" | "txsign",
//	  "curve": "ed25519" | "secp256k1",
//	  "protocol": "frost" | "dkls23",
//	  "threshold": 1,
//	  "peers": [
//	    {"spot_id": "k.<base64>", "moniker": "...",
//	     "key": "<base64url pubkey bytes>"}
//	  ],
//	  "digest": "<base64 32 bytes, txsign only>"
//	}
//
// The legacy `kind` and `wallet_id` aliases are tolerated for backward
// compatibility with the original Stage-1 scaffolding. UnmarshalJSON coerces
// `kind`/`type` into Kind and applies sensible defaults (curve=ed25519,
// protocol=frost, threshold=1) when the policy module omits them.
//
// Legacy GG18 (`protocol == "legacy"` with curve `secp256k1`/`ed25519`) is
// rejected by [resolveCurveProtocol] — clawdwallet only speaks the modern
// FROST(Ed25519) and DKLs23(secp256k1) protocols.
type InitPayload struct {
	// Kind is the canonical session type ("keygen", "txsign", "reshare").
	// Encoded as `type` on the wire; `kind` is accepted on input.
	Kind SessionKind `json:"type,omitempty"`

	// SID is the server-issued session id; carried for self-contained
	// payloads (the recipient also has it in the URL path).
	SID string `json:"sid,omitempty"`

	// Curve is "ed25519" (default) or "secp256k1".
	Curve string `json:"curve,omitempty"`

	// Protocol selects the TSS algorithm: "frost" (Ed25519, default) or
	// "dkls23" (secp256k1). May be omitted when the curve alone is
	// unambiguous; see [resolveCurveProtocol].
	Protocol string `json:"protocol,omitempty"`

	// Peers is the full participant set (sorted by KeyInt before
	// constructing tss PartyIDs).
	Peers []PeerSpec `json:"peers"`

	// Threshold is t in t-of-n (signing needs t+1 peers).
	Threshold int `json:"threshold,omitempty"`

	// Digest is base64 of the 32-byte digest to sign over (txsign only).
	// Wdrone tolerates hex and base64; we always emit base64 on the wire.
	Digest string `json:"digest,omitempty"`

	// WalletID is the crws- identifier on the server side. Carried for
	// traceability; the agent only needs the sid for routing.
	WalletID string `json:"wallet_id,omitempty"`

	// Reshare-only fields, kept for forward-compat with the gated reshare path.
	NewPeers     []PeerSpec `json:"new_peers,omitempty"`
	NewThreshold int        `json:"new_threshold,omitempty"`
}

// UnmarshalJSON accepts the canonical `type` field as well as the original
// `kind` alias used by the Stage-1 scaffolding. It also defaults Curve to
// "ed25519" when absent, matching the policy module's omit-empty behaviour.
// Protocol is left empty on input — the resolver in protocol.go derives it
// from (curve, protocol) at dispatch time.
func (ip *InitPayload) UnmarshalJSON(data []byte) error {
	type raw struct {
		Kind         SessionKind `json:"kind,omitempty"`
		Type         SessionKind `json:"type,omitempty"`
		SID          string      `json:"sid,omitempty"`
		Curve        string      `json:"curve,omitempty"`
		Protocol     string      `json:"protocol,omitempty"`
		Peers        []PeerSpec  `json:"peers"`
		Threshold    int         `json:"threshold,omitempty"`
		Digest       string      `json:"digest,omitempty"`
		Message      string      `json:"message,omitempty"`
		WalletID     string      `json:"wallet_id,omitempty"`
		NewPeers     []PeerSpec  `json:"new_peers,omitempty"`
		NewThreshold int         `json:"new_threshold,omitempty"`
	}
	var r raw
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	ip.Kind = r.Type
	if ip.Kind == "" {
		ip.Kind = r.Kind
	}
	// Tolerate the older "sign" value as an alias for "txsign".
	if ip.Kind == "sign" {
		ip.Kind = SessionSign
	}
	ip.SID = r.SID
	ip.Curve = r.Curve
	if ip.Curve == "" {
		ip.Curve = CurveEd25519
	}
	ip.Protocol = r.Protocol
	ip.Peers = r.Peers
	ip.Threshold = r.Threshold
	ip.Digest = r.Digest
	if ip.Digest == "" {
		// Some integrators (notably the policy module's stage 1 stub) use
		// `message` for the 32-byte sign target. Accept both — they are
		// the same field semantically.
		ip.Digest = r.Message
	}
	ip.WalletID = r.WalletID
	ip.NewPeers = r.NewPeers
	ip.NewThreshold = r.NewThreshold
	return nil
}

// Session is one in-flight TSS ceremony driven through a JsonMessage broker.
//
// The broker is shared by the local party and the outbound wireSend closure:
// the protocol calls broker.Receive on outbound messages (which the broker
// recognises as `fromSelf` and routes via send), and the agent's inbound spot
// handler calls broker.dispatchInbound to feed remote frames into the same
// broker for local dispatch.
type Session struct {
	ID    string
	Kind  SessionKind
	Peers []PeerSpec
	Self  *tss.PartyID

	broker *spotBroker

	doneCh chan struct{}
	err    error
	once   sync.Once

	// Result is populated when the ceremony completes.
	Result any
}

func (s *Session) finish(err error) {
	s.once.Do(func() {
		s.err = err
		close(s.doneCh)
	})
}

// Wait blocks until the session terminates and returns the final error (if any).
func (s *Session) Wait(ctx context.Context) error {
	select {
	case <-s.doneCh:
		return s.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// SessionRegistry tracks all live ceremonies for the agent.
type SessionRegistry struct {
	mu sync.Mutex
	m  map[string]*Session
}

func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{m: make(map[string]*Session)}
}

func (r *SessionRegistry) Get(sid string) *Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.m[sid]
}

func (r *SessionRegistry) Put(s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[s.ID] = s
}

func (r *SessionRegistry) Drop(sid string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, sid)
}

// spotBroker implements tss.MessageBroker for a single Session, mirroring the
// wdrone/libwallet broker design: the protocol calls Receive in both directions
// and we distinguish outbound vs inbound by checking msg.From against the
// session's own KeyInt. Outbound goes to wireSend; inbound is dispatched to the
// registered MessageReceiver (or queued under pending if Connect hasn't fired
// yet for that type).
type spotBroker struct {
	selfKey  *tss.PartyID
	send     func(ctx context.Context, msg *tss.JsonMessage)
	mu       sync.Mutex
	handlers map[string]tss.MessageReceiver
	pending  map[string][]*tss.JsonMessage
}

func newSpotBroker(self *tss.PartyID, send func(context.Context, *tss.JsonMessage)) *spotBroker {
	return &spotBroker{
		selfKey:  self,
		send:     send,
		handlers: make(map[string]tss.MessageReceiver),
		pending:  make(map[string][]*tss.JsonMessage),
	}
}

func (b *spotBroker) Connect(typ string, dest tss.MessageReceiver) {
	b.mu.Lock()
	b.handlers[typ] = dest
	queued := b.pending[typ]
	delete(b.pending, typ)
	b.mu.Unlock()
	for _, msg := range queued {
		if err := dest.Receive(msg); err != nil {
			log.Printf("spotBroker: queued delivery of %s failed: %s", typ, err)
		}
	}
}

func (b *spotBroker) Receive(msg *tss.JsonMessage) error {
	toSelf := msg.To != nil && msg.To.KeyInt().Cmp(b.selfKey.KeyInt()) == 0
	fromSelf := msg.From != nil && msg.From.KeyInt().Cmp(b.selfKey.KeyInt()) == 0
	if fromSelf && !toSelf {
		b.send(context.Background(), msg)
		return nil
	}
	return b.dispatch(msg)
}

func (b *spotBroker) dispatch(msg *tss.JsonMessage) error {
	b.mu.Lock()
	h, ok := b.handlers[msg.Type]
	if !ok {
		b.pending[msg.Type] = append(b.pending[msg.Type], msg)
		b.mu.Unlock()
		return nil
	}
	b.mu.Unlock()
	return h.Receive(msg)
}

// dispatchInbound parses a raw JSON tss.JsonMessage payload received over Spot
// and feeds it through Receive for local handler dispatch.
func (b *spotBroker) dispatchInbound(data []byte) error {
	var jm tss.JsonMessage
	if err := json.Unmarshal(data, &jm); err != nil {
		return fmt.Errorf("parse JsonMessage: %w", err)
	}
	if jm.From == nil {
		return errors.New("incoming JsonMessage has no From")
	}
	return b.Receive(&jm)
}
