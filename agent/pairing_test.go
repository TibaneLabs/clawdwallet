package agent

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KarpelesLab/spotproto"

	"github.com/TibaneLabs/clawdwallet/config"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func stubConfig(moniker string) *config.Config {
	return &config.Config{Moniker: moniker}
}

// newTestRegistry builds a registry whose clock and GC the test fully
// controls. The background GC is disabled; tests call gc() directly.
func newTestRegistry(now func() time.Time) *PairingRegistry {
	r := &PairingRegistry{
		entries: make(map[string]*pairEntry),
		now:     now,
		stop:    make(chan struct{}),
	}
	close(r.stop) // no background goroutine
	return r
}

func TestPairingIssueProducesValidToken(t *testing.T) {
	r := newTestRegistry(time.Now)
	tok, done, err := r.Issue()
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if done == nil {
		t.Fatal("done channel is nil")
	}
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatalf("token is not base64url-no-padding: %v", err)
	}
	if len(raw) != 16 {
		t.Fatalf("token entropy = %d bytes, want 16", len(raw))
	}
}

func TestPairingConsumeHappyPath(t *testing.T) {
	r := newTestRegistry(time.Now)
	tok, done, _ := r.Issue()
	if code := r.Consume(tok, "k.mobile"); code != "" {
		t.Fatalf("Consume returned %q, want success", code)
	}
	select {
	case c, ok := <-done:
		if !ok {
			t.Fatal("done closed without value")
		}
		if c.MobileSpotID != "k.mobile" {
			t.Fatalf("MobileSpotID = %q", c.MobileSpotID)
		}
	default:
		t.Fatal("done was not signalled")
	}
}

func TestPairingSecondConsumeReturnsConsumed(t *testing.T) {
	r := newTestRegistry(time.Now)
	tok, _, _ := r.Issue()
	if code := r.Consume(tok, "k.mobile1"); code != "" {
		t.Fatalf("first Consume = %q", code)
	}
	if code := r.Consume(tok, "k.mobile2"); code != PairTokenConsumed {
		t.Fatalf("second Consume = %q, want %q", code, PairTokenConsumed)
	}
}

func TestPairingUnknownTokenIsInvalid(t *testing.T) {
	r := newTestRegistry(time.Now)
	if code := r.Consume("never-existed", "k.mobile"); code != PairTokenInvalid {
		t.Fatalf("Consume = %q, want %q", code, PairTokenInvalid)
	}
	if code := r.Consume("", "k.mobile"); code != PairTokenInvalid {
		t.Fatalf("empty Consume = %q, want %q", code, PairTokenInvalid)
	}
}

func TestPairingExpiredTokenReturnsExpired(t *testing.T) {
	clock := time.Now()
	r := newTestRegistry(func() time.Time { return clock })
	tok, _, _ := r.Issue()

	// Advance past the TTL but before the GC grace period.
	clock = clock.Add(pairingTokenTTL + time.Second)
	if code := r.Consume(tok, "k.mobile"); code != PairTokenExpired {
		t.Fatalf("Consume after TTL = %q, want %q", code, PairTokenExpired)
	}
}

func TestPairingExpiredIsDistinguishableFromInvalid(t *testing.T) {
	clock := time.Now()
	r := newTestRegistry(func() time.Time { return clock })
	tokExpired, _, _ := r.Issue()
	clock = clock.Add(pairingTokenTTL + time.Second)
	if code := r.Consume(tokExpired, "m"); code != PairTokenExpired {
		t.Fatalf("expired path returned %q", code)
	}
	if code := r.Consume("never-issued-token", "m"); code != PairTokenInvalid {
		t.Fatalf("invalid path returned %q", code)
	}
}

func TestPairingGCRemovesExpiredEntries(t *testing.T) {
	clock := time.Now()
	r := newTestRegistry(func() time.Time { return clock })
	tok, _, _ := r.Issue()

	// Past TTL but inside the grace window: entry must remain.
	clock = clock.Add(pairingTokenTTL + time.Second)
	r.gc()
	r.mu.Lock()
	_, present := r.entries[tok]
	r.mu.Unlock()
	if !present {
		t.Fatal("entry GC'd inside grace window")
	}

	// Past grace window: entry should be gone.
	clock = clock.Add(pairingExpiredGrace + time.Second)
	r.gc()
	r.mu.Lock()
	_, present = r.entries[tok]
	r.mu.Unlock()
	if present {
		t.Fatal("entry not GC'd past grace window")
	}
	if code := r.Consume(tok, "m"); code != PairTokenInvalid {
		t.Fatalf("post-GC Consume = %q, want %q", code, PairTokenInvalid)
	}
}

func TestPairingConcurrentConsumeFirstWins(t *testing.T) {
	r := newTestRegistry(time.Now)
	tok, _, _ := r.Issue()

	const racers = 32
	var (
		wg          sync.WaitGroup
		success     atomic.Int32
		consumed    atomic.Int32
		other       atomic.Int32
		startSignal = make(chan struct{})
	)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startSignal
			switch r.Consume(tok, "k.mobile") {
			case "":
				success.Add(1)
			case PairTokenConsumed:
				consumed.Add(1)
			default:
				other.Add(1)
			}
		}()
	}
	close(startSignal)
	wg.Wait()

	if success.Load() != 1 {
		t.Fatalf("successes = %d, want 1", success.Load())
	}
	if consumed.Load() != racers-1 {
		t.Fatalf("consumed = %d, want %d", consumed.Load(), racers-1)
	}
	if other.Load() != 0 {
		t.Fatalf("unexpected other outcomes: %d", other.Load())
	}
}

func TestPairingURL(t *testing.T) {
	got := PairingURL("k.agent-id", "tok-abc")
	want := "tibane://pair?agent=k.agent-id&token=tok-abc"
	if got != want {
		t.Fatalf("PairingURL = %q, want %q", got, want)
	}
}

// pairing handler tests: drive handlePair directly with synthesised Spot
// messages and validate the contract response shape.

func newHandlerAgent(t *testing.T) *Agent {
	t.Helper()
	return &Agent{
		cfg:     stubConfig("test-agent"),
		pairing: newTestRegistry(time.Now),
		log:     testLogger(),
	}
}

func TestPairHandlerRejectsBadVersion(t *testing.T) {
	a := newHandlerAgent(t)
	body := mustJSON(t, pairRequest{V: 99, Token: "x", MobileSpotID: "k.m"})
	resp, err := a.handlePair(&spotproto.Message{Body: body})
	if err != nil {
		t.Fatalf("handlePair err: %v", err)
	}
	checkErrorResponse(t, resp, PairBadRequest)
}

func TestPairHandlerRejectsMalformed(t *testing.T) {
	a := newHandlerAgent(t)
	resp, err := a.handlePair(&spotproto.Message{Body: []byte("{not json")})
	if err != nil {
		t.Fatalf("handlePair err: %v", err)
	}
	checkErrorResponse(t, resp, PairBadRequest)
}

func TestPairHandlerRejectsMissingFields(t *testing.T) {
	a := newHandlerAgent(t)
	for name, body := range map[string][]byte{
		"missing token":  mustJSON(t, pairRequest{V: 1, MobileSpotID: "k.m"}),
		"missing mobile": mustJSON(t, pairRequest{V: 1, Token: "abc"}),
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := a.handlePair(&spotproto.Message{Body: body})
			if err != nil {
				t.Fatalf("handlePair err: %v", err)
			}
			checkErrorResponse(t, resp, PairBadRequest)
		})
	}
}

func TestPairHandlerInvalidToken(t *testing.T) {
	a := newHandlerAgent(t)
	body := mustJSON(t, pairRequest{V: 1, Token: "never-issued", MobileSpotID: "k.m"})
	resp, err := a.handlePair(&spotproto.Message{Body: body})
	if err != nil {
		t.Fatalf("handlePair err: %v", err)
	}
	checkErrorResponse(t, resp, PairTokenInvalid)
}

func TestPairHandlerSuccessAndConsumed(t *testing.T) {
	a := newHandlerAgent(t)
	tok, _, _ := a.pairing.Issue()

	req := mustJSON(t, pairRequest{V: 1, Token: tok, MobileSpotID: "k.mobile"})
	resp, err := a.handlePair(&spotproto.Message{Body: req})
	if err != nil {
		t.Fatalf("handlePair err: %v", err)
	}
	var ok PairResponse
	if err := json.Unmarshal(resp, &ok); err != nil {
		t.Fatalf("decode success response: %v", err)
	}
	if ok.V != PairingProtocolVersion {
		t.Fatalf("V = %d", ok.V)
	}
	if ok.SuggestedName != "test-agent" {
		t.Fatalf("SuggestedName = %q", ok.SuggestedName)
	}
	if ok.Capabilities == nil {
		t.Fatal("Capabilities must be present (non-nil) even if empty")
	}

	// Second use of the same token → token_consumed.
	resp2, err := a.handlePair(&spotproto.Message{Body: req})
	if err != nil {
		t.Fatalf("second handlePair err: %v", err)
	}
	checkErrorResponse(t, resp2, PairTokenConsumed)
}

func TestPairHandlerExpired(t *testing.T) {
	clock := time.Now()
	a := &Agent{
		cfg:     stubConfig("test-agent"),
		pairing: newTestRegistry(func() time.Time { return clock }),
		log:     testLogger(),
	}
	tok, _, _ := a.pairing.Issue()
	clock = clock.Add(pairingTokenTTL + time.Second)

	req := mustJSON(t, pairRequest{V: 1, Token: tok, MobileSpotID: "k.m"})
	resp, err := a.handlePair(&spotproto.Message{Body: req})
	if err != nil {
		t.Fatalf("handlePair err: %v", err)
	}
	checkErrorResponse(t, resp, PairTokenExpired)
}

func checkErrorResponse(t *testing.T, body []byte, want PairingError) {
	t.Helper()
	var e PairErrorResponse
	if err := json.Unmarshal(body, &e); err != nil {
		t.Fatalf("decode error response: %v (body=%s)", err, body)
	}
	if e.V != PairingProtocolVersion {
		t.Fatalf("error V = %d", e.V)
	}
	if e.Error != want {
		t.Fatalf("error = %q, want %q", e.Error, want)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
