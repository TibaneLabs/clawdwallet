// Package policy lets the agent talk to the policy evaluator over Spot.
package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/KarpelesLab/spotlib"
)

// SignRequest is sent on policy/sign-request. The shape mirrors the schema in
// ARCHITECTURE.md (the full JSON envelope the policy evaluator inspects).
type SignRequest struct {
	RequestID     string         `json:"request_id"`
	TxBytes       string         `json:"tx_bytes"` // base64
	TxType        string         `json:"tx_type"`
	Intent        Intent         `json:"intent"`
	ParsedEffects ParsedEffects  `json:"parsed_effects"`
	X402Context   *X402Context   `json:"x402_context,omitempty"`
}

// Intent is the agent's self-reported reason for the transaction.
type Intent struct {
	Description string `json:"description"`
	Skill       string `json:"skill,omitempty"`
	Reason      string `json:"reason"`
}

// ParsedEffects is the agent's best-effort breakdown of what the transaction will do.
type ParsedEffects struct {
	SOLDelta          int64        `json:"sol_delta"`
	TokenDeltas       []TokenDelta `json:"token_deltas"`
	ProgramsInvoked   []string     `json:"programs_invoked"`
	AccountsCreated   []string     `json:"accounts_created"`
	ProgramsDeployed  []string     `json:"programs_deployed"`
}

// TokenDelta describes movement of one SPL token.
type TokenDelta struct {
	Mint     string `json:"mint"`
	Symbol   string `json:"symbol,omitempty"`
	Delta    int64  `json:"delta"`
	Decimals uint8  `json:"decimals"`
}

// X402Context provides x402-specific metadata when applicable.
type X402Context struct {
	Endpoint string `json:"endpoint"`
	Resource string `json:"resource"`
}

// SignResponse is what the policy evaluator returns when it has reached a decision.
type SignResponse struct {
	// SessionID is the TSS session ID the agent should join to complete the signature.
	SessionID string `json:"sid,omitempty"`

	// Approved is true if the policy evaluator agreed to co-sign.
	Approved bool `json:"approved"`

	// Reason is filled when Approved is false or when escalation occurred.
	Reason string `json:"reason,omitempty"`

	// Question is set when the evaluator wants a clarification from the agent.
	// The agent should reply on policy/clarify-response with the SessionID.
	Question string `json:"question,omitempty"`

	// EscalatedToOwner is true if the request was bounced to the owner mobile.
	EscalatedToOwner bool `json:"escalated_to_owner"`

	// Signature is set when the policy evaluator returns the signature inline
	// (i.e. it produced the TSS round bytes synchronously). Base64 64-byte sig.
	Signature string `json:"signature,omitempty"`
}

// Client talks to the policy evaluator.
type Client struct {
	spot     *spotlib.Client
	policyID string
}

// New constructs a Client targeting the given policy evaluator Spot ID.
func New(spot *spotlib.Client, policyID string) *Client {
	return &Client{spot: spot, policyID: policyID}
}

// PolicyID returns the configured policy evaluator identity.
func (c *Client) PolicyID() string { return c.policyID }

// Submit posts a SignRequest and waits for the SignResponse.
//
// Note: the policy evaluator does not produce signatures directly; it either
// approves and co-signs in a TSS round (which the agent runs in parallel after
// receiving the wallet/init message), or declines/escalates. The returned
// SignResponse tells the agent which path was taken.
func (c *Client) Submit(ctx context.Context, req *SignRequest) (*SignResponse, error) {
	if c.spot == nil {
		return nil, errors.New("policy: nil spot client")
	}
	if c.policyID == "" {
		return nil, errors.New("policy: no policy id configured")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	raw, err := c.spot.Query(callCtx, c.policyID+"/policy", body)
	if err != nil {
		return nil, fmt.Errorf("policy query: %w", err)
	}
	var resp SignResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("decode policy response: %w", err)
	}
	return &resp, nil
}

// SendLock toggles the policy evaluator's lock state. Used by the owner CLI
// path; included here so the agent can also relay an emergency lock from a
// recovery flow.
func (c *Client) SendLock(ctx context.Context, locked bool) error {
	action := "lock"
	if !locked {
		action = "unlock"
	}
	body, _ := json.Marshal(map[string]any{"action": action})
	callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return c.spot.SendToWithFrom(callCtx, c.policyID+"/policy", body, "policy")
}
