package agent

import (
	"encoding/base64"
	"math/big"
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

func TestKeyIntFromKeyBytes(t *testing.T) {
	raw := []byte{0x01, 0x02, 0x03, 0x04}
	p := PeerSpec{SpotID: "k.x", Key: base64.RawURLEncoding.EncodeToString(raw)}
	want := new(big.Int).SetBytes(raw)
	if p.KeyInt().Cmp(want) != 0 {
		t.Errorf("KeyInt from key bytes: want %s got %s", want, p.KeyInt())
	}
}

func TestKeyIntFallback(t *testing.T) {
	// No Key → sha256(spot_id) fallback. Must equal PartyKey(spot_id).
	p := PeerSpec{SpotID: "k.fallback"}
	if p.KeyInt().Cmp(PartyKey("k.fallback")) != 0 {
		t.Errorf("KeyInt fallback should equal PartyKey(spot_id)")
	}
}

func TestKeyBytes(t *testing.T) {
	raw := []byte{0xaa, 0xbb}
	p := PeerSpec{SpotID: "k.x", Key: base64.RawURLEncoding.EncodeToString(raw)}
	if got := p.KeyBytes(); string(got) != string(raw) {
		t.Errorf("KeyBytes: want %x got %x", raw, got)
	}
	pf := PeerSpec{SpotID: "k.y"}
	if got := pf.KeyBytes(); string(got) != string(PartyKey("k.y").Bytes()) {
		t.Errorf("KeyBytes fallback mismatch")
	}
}

func TestPartyIDFromPeer(t *testing.T) {
	pid := PartyIDFromPeer(PeerSpec{SpotID: "k.z", Moniker: "zed"})
	if pid.Id != "k.z" || pid.Moniker != "zed" {
		t.Errorf("PartyID: got id=%q moniker=%q", pid.Id, pid.Moniker)
	}
}
