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

// SignRequest is the JSON body of `POST Crypto/WalletSign:signByPolicy`.
//
// The phplatform endpoint expects the legacy WalletSign signing-flow shape:
// `key`, `hash`, `object_type`, `object`, `il`, `curve`. For ClawdWallet
// agent-type wallets, the policy engine reads `object` (the JSON of the
// agent's parsed_effects) to apply hard rules; `hash` is the hex-encoded
// Solana message bytes that ultimately get signed by the TSS ceremony.
type SignRequest struct {
	Key        string `json:"key"`              // <crws-id>:<crwsv-id> (the wallet handle libwallet stored on keygen)
	Hash       string `json:"hash"`             // hex of Solana message bytes
	ObjectType string `json:"object_type"`      // e.g. "solana_tx"
	Object     string `json:"object"`           // JSON of parsed_effects + intent + x402 context
	IL         string `json:"il,omitempty"`     // not used for EdDSA
	Curve      string `json:"curve"`            // "ed25519"
}

// SignResponse is the decoded `Crypto/WalletSign:signByPolicy` reply.
//
//	{
//	  "session":      "<crwsv-id>",
//	  "format":       "all-digits",
//	  "length":       6,
//	  "remote_key":   "<crws>:<crwsv>",
//	  "wdrone_spot_id": "k.<base64>",
//	  "init_payload": { type, curve, threshold, peers, digest }
//	}
//
// `RemoteKey` is the canonical `Crypto_WalletSign__:Crypto_WalletSign_Verify__`
// pair. The crwsv- portion is the session id the agent uses for the TSS round
// path; exposed as `SessionID` for convenience.
//
// `InitPayload` carries the canonical agent→wdrone init body. The phplatform
// endpoint produces it for agent-type wallets; for legacy user-type wallets
// (signed locally via libwallet, no wdrone) the field is absent and a
// successful response just means the legacy SMS-free auto-policy path
// validated. ClawdWallet always uses agent-type so InitPayload is expected.
//
// `Approved` is synthesised: a successful response (no HTTP error) implies
// the policy approved. The phplatform endpoint throws on rejection, so the
// presence of a session in the response is itself the approval signal.
type SignResponse struct {
	Session      string `json:"session"`
	RemoteKey    string `json:"remote_key"`
	WdroneSpotID string `json:"wdrone_spot_id,omitempty"`

	// InitPayload is the canonical sign-ceremony init body. Absent for legacy
	// user-type wallets (they sign locally without wdrone).
	InitPayload *InitPayload `json:"init_payload,omitempty"`

	// Approved is true whenever the call succeeded (phplatform throws on
	// rejection). Kept as a field for caller ergonomics.
	Approved bool `json:"-"`

	// Reason carries any wrapping error text the caller surfaces. Phplatform
	// errors surface via the rest.Apply error path, not this field.
	Reason string `json:"-"`
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

// UnmarshalJSON decodes the phplatform response and synthesises `Approved`
// from the presence of a session id (phplatform throws on rejection).
func (r *SignResponse) UnmarshalJSON(data []byte) error {
	type raw struct {
		Session      string       `json:"session"`
		RemoteKey    string       `json:"remote_key"`
		WdroneSpotID string       `json:"wdrone_spot_id"`
		InitPayload  *InitPayload `json:"init_payload,omitempty"`
	}
	var x raw
	if err := jsonUnmarshal(data, &x); err != nil {
		return err
	}
	r.Session = x.Session
	r.RemoteKey = x.RemoteKey
	r.WdroneSpotID = x.WdroneSpotID
	r.InitPayload = x.InitPayload
	r.Approved = x.Session != ""
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

// Submit posts a SignRequest to phplatform's WalletSign policy engine and
// returns the decoded response.
//
// Path: `Crypto/WalletSign:signByPolicy`. Per Decision 7 the call is
// unauthenticated for agent-type wallets — the policy module only gates which
// sessions get opened based on its own DB; the agent cannot forge a valid
// `Crypto_WalletSign_Verify` row and therefore cannot fake an approval.
// Sender authentication is enforced downstream by the TSS round failing for
// an agent that doesn't actually hold the wallet's Share 1.
//
// `remoteKey` is the libwallet RemoteKey format `<crws-id>:<crwsv-id>` that
// the agent stored at keygen completion. `hashHex` is the Solana message
// bytes to sign (hex-encoded). `parsed` is the JSON of the agent's parsed
// effects + intent that the policy engine examines.
func Submit(ctx context.Context, remoteKey string, hashHex string, parsed []byte) (*SignResponse, error) {
	if remoteKey == "" {
		return nil, errors.New("policy: empty remoteKey")
	}
	if hashHex == "" {
		return nil, errors.New("policy: empty hash")
	}
	if len(parsed) == 0 {
		return nil, errors.New("policy: empty parsed effects")
	}
	req := SignRequest{
		Key:        remoteKey,
		Hash:       hashHex,
		ObjectType: "solana_tx",
		Object:     string(parsed),
		Curve:      "ed25519",
	}
	var resp SignResponse
	if err := rest.Apply(ctx, "Crypto/WalletSign:signByPolicy", "POST", req, &resp); err != nil {
		return nil, fmt.Errorf("policy submit: %w", err)
	}
	return &resp, nil
}
