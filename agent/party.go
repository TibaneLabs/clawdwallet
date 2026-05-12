package agent

import (
	"crypto/sha256"
	"encoding/base64"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// PeerSpec describes a participating party at the protocol layer.
//
// `Key` is the canonical PartyID key bytes — per the Stage-1 integration
// contract these are the raw Ed25519 pubkey bytes behind each peer's Spot
// identity, base64url-encoded on the wire (matches wdrone's `party.go`
// derivation). When `Key` is present, KeyInt() returns big.NewInt(0)
// .SetBytes(<raw>); when absent we fall back to a sha256(spot_id) digest so
// older callers and standalone tests still produce a deterministic value.
type PeerSpec struct {
	// SpotID is the routable Spot identity (e.g. "k.<base64>").
	SpotID string `json:"spot_id"`

	// Moniker is the human-friendly tag carried inside the PartyID.
	Moniker string `json:"moniker"`

	// Key is the base64url-encoded raw Ed25519 pubkey bytes used by tss-lib
	// as the PartyID key. May be empty when constructed by callers that do
	// not yet have the canonical bytes (e.g. the sha256 fallback path).
	Key string `json:"key,omitempty"`
}

// PartyKey returns a deterministic *big.Int that all parties will compute the
// same way for a given Spot identity. tss-lib uses this to slot participants
// in a canonical order.
//
// Deprecated for new ClawdWallet code: prefer PeerSpec.KeyInt() so the bigint
// matches the canonical raw-pubkey bytes wdrone/libwallet use. Kept for
// backward compatibility with the original tests and any sha256-only callers.
func PartyKey(spotID string) *big.Int {
	h := sha256.Sum256([]byte(spotID))
	// Use bytes 1..32 to keep the high bit clear; this stays positive and well
	// inside the modulus tss-lib uses for comparison.
	bi := new(big.Int).SetBytes(h[:])
	return bi
}

// KeyInt returns the canonical *big.Int that tss-lib should slot this peer
// under. When PeerSpec.Key carries the base64url-encoded raw Ed25519 pubkey
// bytes (the Stage-1 contract), we decode and SetBytes those — matching the
// wdrone derivation in wdrone/party.go:124-135. Otherwise we fall back to
// PartyKey(SpotID) so legacy callers still get a deterministic value.
func (p PeerSpec) KeyInt() *big.Int {
	if p.Key != "" {
		if b, err := base64.RawURLEncoding.DecodeString(p.Key); err == nil && len(b) > 0 {
			return new(big.Int).SetBytes(b)
		}
	}
	return PartyKey(p.SpotID)
}

// KeyBytes returns the canonical key bytes for the PartyID (raw Ed25519
// pubkey when known, otherwise the sha256 fallback). Used to build wire
// PartyID JSON objects whose `key` field is base64 of these bytes.
func (p PeerSpec) KeyBytes() []byte {
	if p.Key != "" {
		if b, err := base64.RawURLEncoding.DecodeString(p.Key); err == nil && len(b) > 0 {
			return b
		}
	}
	return PartyKey(p.SpotID).Bytes()
}

// PartyIDFromPeer converts a PeerSpec into a tss-lib *PartyID using the
// canonical KeyInt derivation.
func PartyIDFromPeer(p PeerSpec) *tss.PartyID {
	return tss.NewPartyID(p.SpotID, p.Moniker, p.KeyInt())
}

// SortedPartyIDs builds and sorts the *PartyID list for a peer set.
func SortedPartyIDs(peers []PeerSpec) tss.SortedPartyIDs {
	unsorted := make(tss.UnSortedPartyIDs, 0, len(peers))
	for _, p := range peers {
		unsorted = append(unsorted, PartyIDFromPeer(p))
	}
	return tss.SortPartyIDs(unsorted)
}
