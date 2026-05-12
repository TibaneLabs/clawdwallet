// Package policy is the agent's client for the phplatform `Crypto/ClawdWallet`
// REST module.
//
// Stage 1 talks to phplatform over HTTPS using `github.com/KarpelesLab/rest`.
// The agent does not authenticate to `:signRequest` — per Decision 7, identity
// is enforced cryptographically downstream by the TSS share check. Other
// endpoints (`:create`, `:lock`, `:policy`, `:get`, `:activity`) are
// owner-authenticated and called by the mobile, not this client.
package policy

// Intent is the agent's self-reported reason for the transaction.
type Intent struct {
	Description string `json:"description"`
	Skill       string `json:"skill,omitempty"`
	Reason      string `json:"reason"`
}

// ParsedEffects is the agent's best-effort breakdown of what the transaction
// will do. Per Decision 8, Stage 1 trusts this self-report; Stage 2 adds a
// PHP-side decoder that re-derives the effects from `tx_bytes`.
type ParsedEffects struct {
	SOLDelta         int64        `json:"sol_delta"`
	TokenDeltas      []TokenDelta `json:"token_deltas"`
	ProgramsInvoked  []string     `json:"programs_invoked"`
	AccountsCreated  []string     `json:"accounts_created"`
	ProgramsDeployed []string     `json:"programs_deployed"`
}

// TokenDelta describes movement of one SPL token.
type TokenDelta struct {
	Mint     string `json:"mint"`
	Symbol   string `json:"symbol,omitempty"`
	Delta    int64  `json:"delta"`
	Decimals uint8  `json:"decimals"`
}

// X402Context provides x402-specific metadata when applicable.
//
// Stage-2: this struct lives on for the x402 path which is flag-gated.
type X402Context struct {
	Endpoint string `json:"endpoint"`
	Resource string `json:"resource"`
}
