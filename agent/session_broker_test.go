package agent

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// captureReceiver records every JsonMessage delivered to it.
type captureReceiver struct {
	mu   sync.Mutex
	msgs []*tss.JsonMessage
}

func (c *captureReceiver) Receive(m *tss.JsonMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgs = append(c.msgs, m)
	return nil
}

func (c *captureReceiver) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.msgs)
}

func pid(id string, key int64) *tss.PartyID {
	return tss.NewPartyID(id, id, big.NewInt(key))
}

func TestSpotBrokerOutboundGoesToSend(t *testing.T) {
	self := pid("k.self", 1)
	var sent []*tss.JsonMessage
	var mu sync.Mutex
	b := newSpotBroker(self, func(_ context.Context, m *tss.JsonMessage) {
		mu.Lock()
		sent = append(sent, m)
		mu.Unlock()
	})

	// From self, To==nil (broadcast) → routed to send, not dispatched.
	out := &tss.JsonMessage{Type: "round1", From: self, To: nil}
	if err := b.Receive(out); err != nil {
		t.Fatalf("Receive: %s", err)
	}
	mu.Lock()
	n := len(sent)
	mu.Unlock()
	if n != 1 {
		t.Errorf("outbound broadcast: want 1 send, got %d", n)
	}
}

func TestSpotBrokerInboundDispatch(t *testing.T) {
	self := pid("k.self", 1)
	peer := pid("k.peer", 2)
	b := newSpotBroker(self, func(context.Context, *tss.JsonMessage) {
		t.Errorf("inbound message must not be routed to send")
	})

	rcv := &captureReceiver{}
	b.Connect("round1", rcv)

	in := &tss.JsonMessage{Type: "round1", From: peer, To: self}
	if err := b.Receive(in); err != nil {
		t.Fatalf("Receive: %s", err)
	}
	if rcv.count() != 1 {
		t.Errorf("inbound dispatch: want 1 delivery, got %d", rcv.count())
	}
}

func TestSpotBrokerQueuesUntilConnect(t *testing.T) {
	self := pid("k.self", 1)
	peer := pid("k.peer", 2)
	b := newSpotBroker(self, func(context.Context, *tss.JsonMessage) {})

	// Frame arrives before the handler is connected → queued.
	in := &tss.JsonMessage{Type: "round2", From: peer, To: self}
	if err := b.Receive(in); err != nil {
		t.Fatalf("Receive: %s", err)
	}

	rcv := &captureReceiver{}
	b.Connect("round2", rcv) // flush should deliver the queued frame
	if rcv.count() != 1 {
		t.Errorf("Connect should flush 1 queued frame, got %d", rcv.count())
	}
}

func TestSpotBrokerDispatchInbound(t *testing.T) {
	self := pid("k.self", 1)
	peer := pid("k.peer", 2)
	b := newSpotBroker(self, func(context.Context, *tss.JsonMessage) {})
	rcv := &captureReceiver{}
	b.Connect("round1", rcv)

	raw, _ := json.Marshal(&tss.JsonMessage{Type: "round1", From: peer, To: self})
	if err := b.dispatchInbound(raw); err != nil {
		t.Fatalf("dispatchInbound: %s", err)
	}
	if rcv.count() != 1 {
		t.Errorf("dispatchInbound should deliver 1, got %d", rcv.count())
	}

	// Malformed JSON is rejected.
	if err := b.dispatchInbound([]byte("{not json")); err == nil {
		t.Errorf("dispatchInbound should reject malformed JSON")
	}

	// A frame with no From is rejected.
	noFrom, _ := json.Marshal(&tss.JsonMessage{Type: "round1", To: self})
	if err := b.dispatchInbound(noFrom); err == nil {
		t.Errorf("dispatchInbound should reject a frame with no From")
	}
}

func TestSessionRegistry(t *testing.T) {
	r := NewSessionRegistry()
	if r.Get("missing") != nil {
		t.Errorf("Get on empty registry should be nil")
	}
	s := &Session{ID: "sid-1"}
	r.Put(s)
	if r.Get("sid-1") != s {
		t.Errorf("Get should return the stored session")
	}
	r.Drop("sid-1")
	if r.Get("sid-1") != nil {
		t.Errorf("Drop should remove the session")
	}
}

func TestSessionFinishAndWait(t *testing.T) {
	s := &Session{ID: "sid", doneCh: make(chan struct{})}
	wantErr := errors.New("boom")
	s.finish(wantErr)
	// Second finish is a no-op (once).
	s.finish(errors.New("ignored"))

	if err := s.Wait(context.Background()); !errors.Is(err, wantErr) {
		t.Errorf("Wait: want %v got %v", wantErr, err)
	}
}

func TestSessionWaitContextCancel(t *testing.T) {
	s := &Session{ID: "sid", doneCh: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Wait(ctx); err == nil {
		t.Errorf("Wait should return the context error when cancelled")
	}
}
