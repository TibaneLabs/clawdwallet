package agent

import (
	"testing"
)

// TestPartyKeyDeterministic asserts that every party computes the same big.Int
// key for a given Spot ID — the protocol relies on this to slot peers
// canonically without out-of-band coordination.
func TestPartyKeyDeterministic(t *testing.T) {
	const spotID = "k.AAAA-test-id-1234567890"
	a := PartyKey(spotID)
	b := PartyKey(spotID)
	if a.Cmp(b) != 0 {
		t.Fatalf("PartyKey not deterministic: %s vs %s", a, b)
	}
}

// TestSortedPartyIDsOrder verifies that sorted party IDs are consistent
// regardless of the order of the input slice.
func TestSortedPartyIDsOrder(t *testing.T) {
	peers := []PeerSpec{
		{SpotID: "k.alpha", Moniker: "a"},
		{SpotID: "k.bravo", Moniker: "b"},
		{SpotID: "k.charlie", Moniker: "c"},
	}
	reordered := []PeerSpec{peers[2], peers[0], peers[1]}
	a := SortedPartyIDs(peers)
	b := SortedPartyIDs(reordered)
	if len(a) != len(b) {
		t.Fatal("length mismatch")
	}
	for i := range a {
		if a[i].Id != b[i].Id {
			t.Fatalf("order mismatch at %d: %s vs %s", i, a[i].Id, b[i].Id)
		}
	}
}
