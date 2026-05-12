package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/KarpelesLab/rest"
)

// jsonUnmarshal is an internal seam so the type's UnmarshalJSON can route
// through encoding/json without naming-import clashes.
var jsonUnmarshal = json.Unmarshal

// SignRequest is the JSON body of `POST Crypto/ClawdWallet/<walletID>:signRequest`.
type SignRequest struct {
	TxBytes       string         `json:"tx_bytes"` // base64
	TxType        string         `json:"tx_type"`
	Intent        Intent         `json:"intent"`
	ParsedEffects ParsedEffects  `json:"parsed_effects"`
	X402Context   *X402Context   `json:"x402_context,omitempty"`
}

// SignResponse is the decoded `Crypto/ClawdWallet/<walletID>:signRequest` reply.
//
//	{
//	  "remote_key": "<crws>:<crwsv>",
//	  "approved":   bool,
//	  "reason":     "<text>",
//	  "peers":      ["k.<base64>", ...],
//	  "init_payload": { sid, type, curve, threshold, peers, digest }
//	}
//
// `RemoteKey` is the canonical `Crypto_WalletSign__:Crypto_WalletSign_Verify__`
// pair (matches `Crypto/WalletSign:verify`). The crwsv- portion is the session
// id the agent uses for the TSS round path; we expose it as `SessionID` for
// convenience.
//
// `InitPayload` carries the full agent→wdrone init body per the Stage-1
// integration contract. The phplatform stub may omit it (older builds), in
// which case BuildAndPay synthesizes a minimal init from `Peers` + the local
// digest. Field name verification with the policy module is the remaining
// open item: legacy phplatform agent output called this field `init`; both
// are tolerated via UnmarshalJSON below.
type SignResponse struct {
	RemoteKey string `json:"remote_key"`
	Approved  bool   `json:"approved"`
	Reason    string `json:"reason,omitempty"`

	// Peers is the co-signer set for the sign ceremony, returned by the policy
	// module so the agent doesn't have to look it up separately. Each entry is
	// a Spot id; the agent itself is included. Two transport shapes are
	// accepted: a bare list of spot ids (legacy) or an array of
	// {spot_id,moniker,key} records (canonical Stage-1 shape carried inside
	// InitPayload). When the latter is used the bare `peers` array MAY also
	// be present for callers that only need the spot ids.
	Peers []string `json:"peers,omitempty"`

	// InitPayload is the canonical agent-leader-to-wdrone init body for the
	// sign ceremony. Optional — see UnmarshalJSON.
	InitPayload *InitPayload `json:"init_payload,omitempty"`
}

// InitPayload is the policy-issued sign-ceremony init body. The agent
// re-serialises it (with per-recipient `name`) onto `<peer>/walletsign/<sid>/init`.
//
// Mirrors agent.InitPayload but lives in the policy package so REST clients
// don't need to import agent. Field tags are the canonical Stage-1 shape
// (`type` not `kind`).
type InitPayload struct {
	SID       string     `json:"sid,omitempty"`
	Type      string     `json:"type,omitempty"`
	Curve     string     `json:"curve,omitempty"`
	Threshold int        `json:"threshold,omitempty"`
	Peers     []PeerInit `json:"peers,omitempty"`
	Digest    string     `json:"digest,omitempty"`
	Message   string     `json:"message,omitempty"`
	WalletID  string     `json:"wallet_id,omitempty"`
}

// PeerInit is one participant in InitPayload.Peers.
type PeerInit struct {
	SpotID  string `json:"spot_id"`
	Moniker string `json:"moniker"`
	Key     string `json:"key,omitempty"`
}

// UnmarshalJSON tolerates the `init` field name alongside the canonical
// `init_payload`. The phplatform integration agent is still settling on the
// exact name; the agent accepts either rather than gating on a specific one.
func (r *SignResponse) UnmarshalJSON(data []byte) error {
	type raw struct {
		RemoteKey    string       `json:"remote_key"`
		Approved     bool         `json:"approved"`
		Reason       string       `json:"reason,omitempty"`
		Peers        []string     `json:"peers,omitempty"`
		InitPayload  *InitPayload `json:"init_payload,omitempty"`
		InitPayload2 *InitPayload `json:"init,omitempty"`
	}
	var x raw
	if err := jsonUnmarshal(data, &x); err != nil {
		return err
	}
	r.RemoteKey = x.RemoteKey
	r.Approved = x.Approved
	r.Reason = x.Reason
	r.Peers = x.Peers
	if x.InitPayload != nil {
		r.InitPayload = x.InitPayload
	} else if x.InitPayload2 != nil {
		r.InitPayload = x.InitPayload2
	}
	return nil
}

// SessionID returns the crwsv- portion of RemoteKey (the TSS session id).
//
// Returns the empty string if RemoteKey is malformed.
func (r *SignResponse) SessionID() string {
	if r == nil {
		return ""
	}
	if idx := strings.IndexByte(r.RemoteKey, ':'); idx >= 0 {
		return r.RemoteKey[idx+1:]
	}
	return ""
}

// Submit posts a SignRequest to the phplatform policy module and returns the
// decoded response.
//
// Path: `Crypto/ClawdWallet/<walletID>:signRequest`. Per Decision 7 the call
// is unauthenticated — the policy module only gates which sessions get opened
// based on its own DB; the agent cannot forge a valid `Crypto_WalletSign_Verify`
// row and therefore cannot fake an approval. Sender authentication is enforced
// downstream by the TSS round failing for an agent that doesn't actually hold
// the wallet's Share 1.
func Submit(ctx context.Context, walletID string, txBytes []byte, intent Intent, parsed ParsedEffects) (*SignResponse, error) {
	if walletID == "" {
		return nil, errors.New("policy: empty walletID")
	}
	if len(txBytes) == 0 {
		return nil, errors.New("policy: empty tx bytes")
	}
	path := fmt.Sprintf("Crypto/ClawdWallet/%s:signRequest", walletID)
	req := SignRequest{
		TxBytes:       base64StdEnc(txBytes),
		TxType:        "transfer", // Stage 1: only USDC TransferChecked is supported.
		Intent:        intent,
		ParsedEffects: parsed,
	}
	var resp SignResponse
	if err := rest.Apply(ctx, path, "POST", req, &resp); err != nil {
		return nil, fmt.Errorf("policy submit: %w", err)
	}
	return &resp, nil
}
