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
	"sync"
	"time"

	"github.com/BottleFmt/gobottle"
	"github.com/KarpelesLab/spotlib"
	"github.com/KarpelesLab/spotproto"

	"github.com/TibaneLabs/clawdwallet/internal/config"
	"github.com/TibaneLabs/clawdwallet/internal/solana"
	"github.com/TibaneLabs/clawdwallet/internal/store"
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
// (SetHandler can also be called later if needed.)
func (a *Agent) handlers() map[string]spotlib.MessageHandler {
	return map[string]spotlib.MessageHandler{
		"wallet": a.handleWallet,
		"agent":  a.handleAgent,
		"policy": a.handlePolicy,
		"owner":  a.handleOwner,
	}
}

// handleWallet dispatches TSS init/broadcast messages.
func (a *Agent) handleWallet(msg *spotproto.Message) ([]byte, error) {
	var env WalletEnvelope
	if err := json.Unmarshal(msg.Body, &env); err != nil {
		return nil, fmt.Errorf("decode wallet envelope: %w", err)
	}
	switch env.Action {
	case WalletInit:
		var ip InitPayload
		if err := json.Unmarshal(env.Payload, &ip); err != nil {
			return nil, fmt.Errorf("decode init payload: %w", err)
		}
		return a.onInit(env.SessionID, env.FromSpotID, &ip)
	case WalletBroadcast:
		var bp BroadcastPayload
		if err := json.Unmarshal(env.Payload, &bp); err != nil {
			return nil, fmt.Errorf("decode broadcast payload: %w", err)
		}
		s := a.registry.Get(env.SessionID)
		if s == nil {
			return nil, fmt.Errorf("unknown session %s", env.SessionID)
		}
		if err := s.dispatchWire(env.FromSpotID, &bp); err != nil {
			return nil, err
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown wallet action %q", env.Action)
	}
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
		// In production this would be plumbed into the agent's planning loop
		// so the model can produce a contextual explanation. For now we echo a
		// minimal acknowledgement so the policy evaluator can proceed.
		return json.Marshal(map[string]any{
			"answer": "agent operating within configured skill manifest; no additional context available",
		})
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
