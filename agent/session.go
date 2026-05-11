package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// SessionKind describes which TSS ceremony a session is running.
type SessionKind string

const (
	SessionKeygen  SessionKind = "keygen"
	SessionSign    SessionKind = "sign"
	SessionReshare SessionKind = "reshare"
)

// WalletAction names the sub-protocol multiplexed onto the single "wallet"
// Spot endpoint. (spotlib only routes by the first path segment, so we
// re-introduce structure inside the payload.)
type WalletAction string

const (
	WalletInit      WalletAction = "init"
	WalletBroadcast WalletAction = "broadcast"
)

// WalletEnvelope is the outer JSON sent on every "wallet" message.
type WalletEnvelope struct {
	Action     WalletAction    `json:"action"`
	SessionID  string          `json:"sid"`
	FromSpotID string          `json:"from"`
	Payload    json.RawMessage `json:"payload"`
}

// InitPayload describes a ceremony to join.
type InitPayload struct {
	Kind         SessionKind `json:"kind"`
	Peers        []PeerSpec  `json:"peers"`
	Threshold    int         `json:"threshold,omitempty"`
	Message      string      `json:"message,omitempty"` // base64 digest, sign only
	NewPeers     []PeerSpec  `json:"new_peers,omitempty"`
	NewThreshold int         `json:"new_threshold,omitempty"`
}

// BroadcastPayload carries one tss-lib wire frame.
type BroadcastPayload struct {
	IsBroadcast bool   `json:"bcast"`
	Bytes       string `json:"bytes"` // base64 wire bytes
}

// Session is one in-flight TSS ceremony with a single tss.Party driver.
type Session struct {
	ID    string
	Kind  SessionKind
	Peers []PeerSpec

	party    tss.Party
	doneCh   chan struct{}
	err      error
	once     sync.Once
	out      chan tss.Message
	peerByID map[string]*tss.PartyID

	// Result is populated when the ceremony completes.
	Result any
}

func newSession(id string, kind SessionKind, peers []PeerSpec, out chan tss.Message) *Session {
	idx := make(map[string]*tss.PartyID, len(peers))
	for _, p := range peers {
		idx[p.SpotID] = PartyIDFromPeer(p)
	}
	return &Session{
		ID:       id,
		Kind:     kind,
		Peers:    peers,
		doneCh:   make(chan struct{}),
		out:      out,
		peerByID: idx,
	}
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

// pumpOutbound reads per-round TSS messages from the session's out channel and
// publishes them as WalletEnvelope/BroadcastPayload frames over Spot.
func (a *Agent) pumpOutbound(s *Session) {
	for {
		select {
		case <-s.doneCh:
			return
		case msg, ok := <-s.out:
			if !ok {
				return
			}
			if err := a.sendTSSMessage(s, msg); err != nil {
				s.finish(fmt.Errorf("outbound TSS: %w", err))
				return
			}
		}
	}
}

func (a *Agent) sendTSSMessage(s *Session, msg tss.Message) error {
	bz, routing, err := msg.WireBytes()
	if err != nil {
		return err
	}
	bp := BroadcastPayload{
		IsBroadcast: routing.IsBroadcast,
		Bytes:       base64.StdEncoding.EncodeToString(bz),
	}
	payloadJSON, err := json.Marshal(bp)
	if err != nil {
		return err
	}
	env := WalletEnvelope{
		Action:     WalletBroadcast,
		SessionID:  s.ID,
		FromSpotID: a.SpotID(),
		Payload:    payloadJSON,
	}
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}

	if !routing.IsBroadcast && len(routing.To) > 0 {
		for _, to := range routing.To {
			if to.Id == a.SpotID() {
				continue
			}
			if err := a.sendToWallet(to.Id, body); err != nil {
				return err
			}
		}
		return nil
	}
	for _, p := range s.Peers {
		if p.SpotID == a.SpotID() {
			continue
		}
		if err := a.sendToWallet(p.SpotID, body); err != nil {
			return err
		}
	}
	return nil
}

// dispatchWire feeds an inbound BroadcastPayload into the session's tss.Party.
func (s *Session) dispatchWire(fromSpotID string, bp *BroadcastPayload) error {
	if s.party == nil {
		return errors.New("session has no party")
	}
	bz, err := base64.StdEncoding.DecodeString(bp.Bytes)
	if err != nil {
		return fmt.Errorf("decode wire bytes: %w", err)
	}
	from := s.peerByID[fromSpotID]
	if from == nil {
		return fmt.Errorf("unknown sender %s", fromSpotID)
	}
	if _, err := s.party.UpdateFromBytes(bz, from, bp.IsBroadcast); err != nil {
		return fmt.Errorf("party update: %w", err)
	}
	return nil
}

// sendToWallet pushes an envelope to <target>/wallet.
func (a *Agent) sendToWallet(target string, body []byte) error {
	ctx, cancel := context.WithTimeout(a.ctx, 15*time.Second)
	defer cancel()
	return a.client.SendToWithFrom(ctx, target+"/wallet", body, "wallet")
}
