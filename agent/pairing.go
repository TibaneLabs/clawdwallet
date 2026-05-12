package agent

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"github.com/KarpelesLab/spotproto"
)

// Pairing handshake — see tibaneapp/docs/clawdwallet-pairing.md for the
// wire-level contract. The agent emits a `tibane://pair?agent=...&token=...`
// URL via the `pair` CLI subcommand; the mobile app posts a pair-request to
// the agent's `pair` Spot endpoint and gets back the agent's identity (or one
// of the four contract error codes).

// PairingProtocolVersion is the contract version Stage 1 implements.
const PairingProtocolVersion = 1

// Token lifetimes. Tokens are valid for TTL from issuance; we keep expired
// records around for an additional grace window so a late tap reports
// token_expired rather than the less-useful token_invalid.
const (
	pairingTokenTTL     = 5 * time.Minute
	pairingExpiredGrace = 30 * time.Minute
	pairingGCInterval   = 1 * time.Minute
)

// PairingError is the closed set of error codes the pair endpoint may return.
type PairingError string

const (
	PairTokenInvalid  PairingError = "token_invalid"
	PairTokenExpired  PairingError = "token_expired"
	PairTokenConsumed PairingError = "token_consumed"
	PairBadRequest    PairingError = "bad_request"
)

// PairingConsumption is delivered on the done channel when a token is
// successfully claimed by a mobile.
type PairingConsumption struct {
	MobileSpotID string
	At           time.Time
}

type pairEntry struct {
	issuedAt time.Time
	consumed bool
	done     chan PairingConsumption
}

// PairingRegistry is the in-memory token store. Tokens die with the process.
type PairingRegistry struct {
	mu      sync.Mutex
	entries map[string]*pairEntry
	now     func() time.Time
	stop    chan struct{}
	once    sync.Once
}

// NewPairingRegistry returns a registry with a background GC goroutine.
// Call Close to terminate the goroutine.
func NewPairingRegistry() *PairingRegistry {
	r := &PairingRegistry{
		entries: make(map[string]*pairEntry),
		now:     time.Now,
		stop:    make(chan struct{}),
	}
	go r.gcLoop(pairingGCInterval)
	return r
}

// Close stops the registry's background GC.
func (r *PairingRegistry) Close() {
	r.once.Do(func() { close(r.stop) })
}

// Issue mints a fresh single-use token (16 bytes of entropy, base64url, no
// padding) and stores it. The returned channel receives one value when the
// token is successfully consumed; it is closed at the same time. The caller
// is responsible for its own TTL-based timeout — the registry never signals
// expiry on the channel.
func (r *PairingRegistry) Issue() (string, <-chan PairingConsumption, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", nil, fmt.Errorf("pairing token entropy: %w", err)
	}
	tok := base64.RawURLEncoding.EncodeToString(buf[:])
	ch := make(chan PairingConsumption, 1)
	r.mu.Lock()
	r.entries[tok] = &pairEntry{
		issuedAt: r.now(),
		done:     ch,
	}
	r.mu.Unlock()
	return tok, ch, nil
}

// Consume attempts to claim a token. It returns the empty string on success,
// or one of the contract error codes (token_invalid / token_expired /
// token_consumed). Consume is atomic: in a race between two callers for the
// same token, exactly one sees success and the other sees token_consumed.
func (r *PairingRegistry) Consume(token, mobileSpotID string) PairingError {
	if token == "" {
		return PairTokenInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[token]
	if !ok {
		return PairTokenInvalid
	}
	if e.consumed {
		return PairTokenConsumed
	}
	if r.now().Sub(e.issuedAt) > pairingTokenTTL {
		return PairTokenExpired
	}
	e.consumed = true
	e.done <- PairingConsumption{MobileSpotID: mobileSpotID, At: r.now()}
	close(e.done)
	return ""
}

func (r *PairingRegistry) gcLoop(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-t.C:
			r.gc()
		}
	}
}

func (r *PairingRegistry) gc() {
	cutoff := r.now().Add(-(pairingTokenTTL + pairingExpiredGrace))
	r.mu.Lock()
	for k, e := range r.entries {
		if e.issuedAt.Before(cutoff) {
			delete(r.entries, k)
		}
	}
	r.mu.Unlock()
}

// pairRequest is the body shape mobile sends to the `pair` endpoint.
type pairRequest struct {
	V            int    `json:"v"`
	Token        string `json:"token"`
	MobileSpotID string `json:"mobile_spot_id"`
}

// PairResponse is the success body returned on the `pair` endpoint.
type PairResponse struct {
	V             int            `json:"v"`
	AgentSpotID   string         `json:"agent_spot_id"`
	SuggestedName string         `json:"suggested_name,omitempty"`
	AgentVersion  string         `json:"agent_version,omitempty"`
	Capabilities  map[string]any `json:"capabilities"`
}

// PairErrorResponse is the error body returned on the `pair` endpoint.
type PairErrorResponse struct {
	V       int          `json:"v"`
	Error   PairingError `json:"error"`
	Message string       `json:"message,omitempty"`
}

// handlePair serves the `pair` Spot endpoint. It returns body+nil for every
// contract-defined response (success and the four error codes), so the
// mobile always receives a JSON envelope it can decode.
func (a *Agent) handlePair(msg *spotproto.Message) ([]byte, error) {
	if msg == nil {
		return pairErrorBody(PairBadRequest, "empty message"), nil
	}
	var req pairRequest
	if err := json.Unmarshal(msg.Body, &req); err != nil {
		return pairErrorBody(PairBadRequest, "malformed body"), nil
	}
	if req.V != PairingProtocolVersion {
		return pairErrorBody(PairBadRequest, fmt.Sprintf("unsupported v=%d", req.V)), nil
	}
	if req.Token == "" || req.MobileSpotID == "" {
		return pairErrorBody(PairBadRequest, "missing required field"), nil
	}

	if code := a.pairing.Consume(req.Token, req.MobileSpotID); code != "" {
		return pairErrorBody(code, ""), nil
	}

	resp := PairResponse{
		V:             PairingProtocolVersion,
		AgentSpotID:   a.SpotID(),
		SuggestedName: a.cfg.Moniker,
		AgentVersion:  agentVersion(),
		Capabilities:  map[string]any{},
	}
	body, err := json.Marshal(resp)
	if err != nil {
		return pairErrorBody(PairBadRequest, "encode response"), nil
	}
	a.log.Info("paired with mobile",
		"mobile_spot_id", req.MobileSpotID,
		"agent_spot_id", resp.AgentSpotID,
	)
	return body, nil
}

func pairErrorBody(code PairingError, msg string) []byte {
	body, _ := json.Marshal(PairErrorResponse{
		V:       PairingProtocolVersion,
		Error:   code,
		Message: msg,
	})
	return body
}

// PairingURL builds the `tibane://pair?agent=...&token=...` URL for the given
// agent Spot id and token. Both values are inserted verbatim — Spot ids and
// base64url tokens are already URL-safe.
func PairingURL(agentSpotID, token string) string {
	return "tibane://pair?agent=" + agentSpotID + "&token=" + token
}

// agentVersion returns a short version string for the running binary, taken
// from the Go build info (VCS revision, truncated). Empty if unavailable —
// the contract makes this field optional.
func agentVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && s.Value != "" {
			if len(s.Value) > 7 {
				return s.Value[:7]
			}
			return s.Value
		}
	}
	return ""
}
