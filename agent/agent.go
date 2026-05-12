// Package agent is the ClawdWallet agent process runtime.
//
// It owns:
//   - a Spot identity and a connection to the Spot relay network
//   - this party's TSS share (Share 1 of 3)
//   - in-flight TSS ceremonies (keygen, sign, reshare)
//   - the Solana RPC connection used to fetch blockhashes and submit TXs
//
// The agent exposes its functionality both as a long-running daemon listening
// on the Spot network and as a request/response API the local CLI/MCP layer
// can call into.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/BottleFmt/gobottle"
	"github.com/KarpelesLab/spotlib"
	"github.com/KarpelesLab/spotproto"

	"github.com/TibaneLabs/clawdwallet/config"
	"github.com/TibaneLabs/clawdwallet/solana"
	"github.com/TibaneLabs/clawdwallet/store"
)

// Agent is the central runtime. Exactly one Agent exists per process.
type Agent struct {
	cfg     *config.Config
	client  *spotlib.Client
	disk    interface {
		Keychain() *gobottle.Keychain
	}
	store    *store.Store
	rpc      *solana.Client
	registry *SessionRegistry

	mu     sync.RWMutex
	share  *store.Share // nil until keygen completes / on disk-load
	locked bool         // soft "kill switch" mirror, set by policy/lock callbacks

	ctx    context.Context
	cancel context.CancelFunc

	log *slog.Logger
}

// Options configures a new Agent.
type Options struct {
	Config *config.Config
	Logger *slog.Logger
}

// New constructs an Agent without starting it. Call Start to dial Spot.
func New(opts Options) (*Agent, error) {
	if opts.Config == nil {
		return nil, errors.New("agent: nil config")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	dir, err := config.Dir()
	if err != nil {
		return nil, err
	}
	disk, err := spotlib.NewDiskStoreWithPath(filepath.Join(dir, "spot"))
	if err != nil {
		return nil, fmt.Errorf("spot disk store: %w", err)
	}

	st := store.New(dir, disk.Keychain())

	ctx, cancel := context.WithCancel(context.Background())

	a := &Agent{
		cfg:      opts.Config,
		disk:     disk,
		store:    st,
		rpc:      solana.NewClient(opts.Config.SolanaRPC),
		registry: NewSessionRegistry(),
		ctx:      ctx,
		cancel:   cancel,
		log:      opts.Logger,
	}

	// Best-effort: load existing share so signing works without a separate import step.
	if st.Has() {
		if sh, err := st.Load(); err != nil {
			a.log.Warn("could not decrypt stored share", "err", err)
		} else {
			a.share = sh
		}
	}
	return a, nil
}

// Start dials Spot and registers handlers. It does not block.
func (a *Agent) Start() error {
	cli, err := spotlib.New(a.disk.Keychain(), a.handlers())
	if err != nil {
		return fmt.Errorf("spot connect: %w", err)
	}
	a.client = cli
	a.log.Info("agent online",
		"spot_id", a.SpotID(),
		"solana", a.SolanaAddress(),
	)
	return nil
}

// Stop shuts down the agent, closing the Spot client and cancelling in-flight work.
func (a *Agent) Stop() {
	a.cancel()
	if a.client != nil {
		_ = a.client.Close()
	}
}

// Ctx returns the agent's context. It is cancelled by Stop.
func (a *Agent) Ctx() context.Context { return a.ctx }

// Client returns the underlying Spot client (used by subsystems that need it directly).
func (a *Agent) Client() *spotlib.Client { return a.client }

// RPC returns the Solana RPC client.
func (a *Agent) RPC() *solana.Client { return a.rpc }

// Config returns the agent configuration (read-only).
func (a *Agent) Config() *config.Config { return a.cfg }

// Store returns the encrypted share store.
func (a *Agent) Store() *store.Store { return a.store }

// SpotID returns this agent's Spot identity (k.<base64>).
func (a *Agent) SpotID() string {
	if a.client == nil {
		return ""
	}
	return a.client.TargetId()
}

// Share returns the agent's TSS share (nil if keygen has not completed).
func (a *Agent) Share() *store.Share {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.share
}

// SetShare persists a freshly produced share both in-memory and on disk.
func (a *Agent) SetShare(s *store.Share) error {
	a.mu.Lock()
	a.share = s
	a.mu.Unlock()
	return a.store.Save(s)
}

// Locked reports whether the agent has received a lock command from the owner.
// This is purely advisory; the cryptographic guarantee still relies on the
// policy evaluator refusing to co-sign.
func (a *Agent) Locked() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.locked
}

// SetLocked toggles the soft lock flag.
func (a *Agent) SetLocked(v bool) {
	a.mu.Lock()
	a.locked = v
	a.mu.Unlock()
}

// sendWalletSign delivers `body` to `<target>/walletsign/<sid>/<suffix>` with
// a sender path matching the wdrone convention (`<my_spot_id>/<sid>/<my_party_id>`
// for routed frames, `<my_spot_id>/walletsign/<sid>` otherwise).
//
// `partyID` may be empty (e.g. init), in which case the sender path is the
// bare walletsign form.
func (a *Agent) sendWalletSign(ctx context.Context, target, sid, suffix, partyID string, body []byte) error {
	if a.client == nil {
		return errors.New("agent not started")
	}
	mySpot := a.SpotID()
	tgt := target + "/walletsign/" + sid
	if suffix != "" {
		tgt += "/" + suffix
	}
	sender := mySpot + "/walletsign/" + sid
	if partyID != "" {
		sender = mySpot + "/" + sid + "/" + partyID
	}
	callCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return a.client.SendToWithFrom(callCtx, tgt, body, sender)
}

// SolanaAddress returns the base58 Solana wallet address, or "" if not yet known.
func (a *Agent) SolanaAddress() string {
	sh := a.Share()
	if sh != nil {
		if addr, err := solana.AddressFromPubKey(sh.SolanaAddressBytes()); err == nil {
			return addr
		}
	}
	return a.cfg.SolanaAddress
}

// handlers returns the static Spot handler set registered at client construction.
//
// `walletsign` is the canonical TSS-over-Spot endpoint shared with wdrone and
// libwallet (see CLAWDWALLET_STAGE1.md §"Cross-component contracts").
// `agent`, `policy`, `owner` remain Stage-2 placeholders kept registered so a
// stale peer gets a useful error rather than dropped traffic.
func (a *Agent) handlers() map[string]spotlib.MessageHandler {
	return map[string]spotlib.MessageHandler{
		"walletsign": a.handleWalletSign,
		"agent":      a.handleAgent,
		"policy":     a.handlePolicy,
		"owner":      a.handleOwner,
	}
}

// handleWalletSign processes inbound TSS messages.
//
// The recipient path is `<my_spot_id>/walletsign/<sid>[/<init|broadcast|single>]`
// (see wdrone/walletsign.go for the canonical implementation we mirror).
// `init` carries a bare InitPayload JSON. `broadcast` and `single` (and any
// other trailing segment) carry a bare `tss.JsonMessage` JSON which we feed
// straight into the session's broker for local dispatch.
func (a *Agent) handleWalletSign(msg *spotproto.Message) ([]byte, error) {
	if msg == nil {
		return nil, nil
	}
	parts := strings.Split(msg.Recipient, "/")
	// expect at minimum <id>/walletsign/<sid>
	if len(parts) < 3 {
		return nil, fmt.Errorf("walletsign: bad recipient %q", msg.Recipient)
	}
	sid := parts[2]
	if sid == "" {
		return nil, fmt.Errorf("walletsign: empty sid in recipient %q", msg.Recipient)
	}

	// Init message: bare InitPayload JSON, body decoded and dispatched per kind.
	if len(parts) >= 4 && parts[3] == "init" {
		var ip InitPayload
		if err := json.Unmarshal(msg.Body, &ip); err != nil {
			return nil, fmt.Errorf("decode init payload: %w", err)
		}
		return a.onInit(sid, msg.Sender, &ip)
	}

	// Otherwise this is a wire frame for an already-initialised session.
	s := a.registry.Get(sid)
	if s == nil {
		return nil, fmt.Errorf("walletsign: unknown session %s", sid)
	}
	if s.broker == nil {
		return nil, fmt.Errorf("walletsign: session %s has no broker", sid)
	}
	if err := s.broker.dispatchInbound(msg.Body); err != nil {
		return nil, fmt.Errorf("walletsign: dispatch %s: %w", sid, err)
	}
	return nil, nil
}

// AgentEnvelope is the JSON shape for control messages on the "agent" endpoint.
type AgentEnvelope struct {
	Action string          `json:"action"`
	Body   json.RawMessage `json:"body,omitempty"`
}

// AgentStatus is returned by the "status" agent action.
type AgentStatus struct {
	SpotID    string `json:"spot_id"`
	Address   string `json:"solana_address"`
	WalletID  string `json:"wallet_id,omitempty"`
	HasShare  bool   `json:"has_share"`
	Locked    bool   `json:"locked"`
	BootedAt  string `json:"booted_at"`
	Moniker   string `json:"moniker"`
}

var bootedAt = time.Now().UTC().Format(time.RFC3339)

// handleAgent answers "status" and "clarify" requests.
func (a *Agent) handleAgent(msg *spotproto.Message) ([]byte, error) {
	var env AgentEnvelope
	if err := json.Unmarshal(msg.Body, &env); err != nil {
		return nil, fmt.Errorf("decode agent envelope: %w", err)
	}
	switch env.Action {
	case "status":
		var wid string
		if sh := a.Share(); sh != nil {
			wid = sh.WalletID
		}
		return json.Marshal(AgentStatus{
			SpotID:   a.SpotID(),
			Address:  a.SolanaAddress(),
			WalletID: wid,
			HasShare: a.Share() != nil,
			Locked:   a.Locked(),
			BootedAt: bootedAt,
			Moniker:  a.cfg.Moniker,
		})
	case "clarify":
		// Stage 2: clarification dialog (Grok-driven escalation) is deferred.
		// Stage 1 has no Grok evaluator, no skill manifest, and no owner
		// dialog flow; the policy module decides hard-rules-only and never
		// asks the agent to elaborate. We return a deterministic stub so an
		// older policy peer doesn't spin on an empty response.
		return nil, fmt.Errorf("clarify is Stage 2 — not enabled")
	default:
		return nil, fmt.Errorf("unknown agent action %q", env.Action)
	}
}

// handlePolicy: inbound notifications from the policy evaluator (e.g. lock toggles).
func (a *Agent) handlePolicy(msg *spotproto.Message) ([]byte, error) {
	var env AgentEnvelope
	if err := json.Unmarshal(msg.Body, &env); err != nil {
		return nil, fmt.Errorf("decode policy envelope: %w", err)
	}
	switch env.Action {
	case "lock":
		a.SetLocked(true)
		return []byte(`{"ok":true}`), nil
	case "unlock":
		a.SetLocked(false)
		return []byte(`{"ok":true}`), nil
	default:
		return nil, fmt.Errorf("unknown policy action %q", env.Action)
	}
}

// handleOwner: inbound notifications from the owner mobile app.
func (a *Agent) handleOwner(msg *spotproto.Message) ([]byte, error) {
	// The agent doesn't currently take direct owner pushes -- approval responses
	// flow back to the policy evaluator, which then drives the TSS round. We
	// still register the endpoint so an owner peer with stale routing gets a
	// useful error rather than dropped traffic.
	return []byte(`{"note":"owner messages go to the policy evaluator"}`), nil
}
