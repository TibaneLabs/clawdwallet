package agent

import (
	"crypto/sha256"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// PeerSpec describes a participating party at the protocol layer.
type PeerSpec struct {
	// SpotID is the routable Spot identity (e.g. "k.<base64>").
	SpotID string `json:"spot_id"`

	// Moniker is the human-friendly tag carried inside the PartyID.
	Moniker string `json:"moniker"`
}

// PartyKey returns a deterministic *big.Int that all parties will compute the
// same way for a given Spot identity. tss-lib uses this to slot participants
// in a canonical order.
func PartyKey(spotID string) *big.Int {
	h := sha256.Sum256([]byte(spotID))
	// Use bytes 1..32 to keep the high bit clear; this stays positive and well
	// inside the modulus tss-lib uses for comparison.
	bi := new(big.Int).SetBytes(h[:])
	return bi
}

// PartyIDFromPeer converts a PeerSpec into a tss-lib *PartyID using PartyKey.
func PartyIDFromPeer(p PeerSpec) *tss.PartyID {
	return tss.NewPartyID(p.SpotID, p.Moniker, PartyKey(p.SpotID))
}

// SortedPartyIDs builds and sorts the *PartyID list for a peer set.
func SortedPartyIDs(peers []PeerSpec) tss.SortedPartyIDs {
	unsorted := make(tss.UnSortedPartyIDs, 0, len(peers))
	for _, p := range peers {
		unsorted = append(unsorted, PartyIDFromPeer(p))
	}
	return tss.SortPartyIDs(unsorted)
}
