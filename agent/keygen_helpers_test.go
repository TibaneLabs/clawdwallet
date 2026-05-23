package agent

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/KarpelesLab/tss-lib/v2/dklstss"
	"github.com/KarpelesLab/tss-lib/v2/frosttss"
	"github.com/KarpelesLab/tss-lib/v2/tss"

	"github.com/TibaneLabs/clawdwallet/store"
)

func testPeers() []PeerSpec {
	return []PeerSpec{
		{SpotID: "k.agent", Moniker: "agent"},
		{SpotID: "k.wdrone", Moniker: "wdrone"},
		{SpotID: "k.mobile", Moniker: "mobile"},
	}
}

func TestContainsSpotID(t *testing.T) {
	peers := testPeers()
	if !containsSpotID(peers, "k.wdrone") {
		t.Errorf("containsSpotID should find k.wdrone")
	}
	if containsSpotID(peers, "k.absent") {
		t.Errorf("containsSpotID should not find k.absent")
	}
}

func TestFindMyPartyID(t *testing.T) {
	sorted := SortedPartyIDs(testPeers())
	if pid := findMyPartyID(sorted, "k.mobile"); pid == nil || pid.Id != "k.mobile" {
		t.Errorf("findMyPartyID should locate k.mobile, got %v", pid)
	}
	if pid := findMyPartyID(sorted, "k.absent"); pid != nil {
		t.Errorf("findMyPartyID should return nil for an absent id")
	}
}

func TestWalletIDOrSid(t *testing.T) {
	if got := walletIDOrSid(&InitPayload{WalletID: "crws-1"}, "sid-x"); got != "crws-1" {
		t.Errorf("walletIDOrSid should prefer WalletID, got %q", got)
	}
	if got := walletIDOrSid(&InitPayload{}, "sid-x"); got != "sid-x" {
		t.Errorf("walletIDOrSid should fall back to sid, got %q", got)
	}
}

func TestSharedPeerKeysAndSpotIDs(t *testing.T) {
	peers := testPeers()
	keys := sharedPeerKeys(peers)
	ids := sharedPeerSpotIDs(peers)
	if len(keys) != 3 || len(ids) != 3 {
		t.Fatalf("expected 3 keys/ids, got %d/%d", len(keys), len(ids))
	}
	// Both lists must be in the same canonical (sorted) order, so the i-th
	// key belongs to the i-th spot id.
	sorted := SortedPartyIDs(peers)
	for i, p := range sorted {
		if ids[i] != p.Id {
			t.Errorf("spot id order mismatch at %d: %q vs %q", i, ids[i], p.Id)
		}
		if keys[i].Cmp(p.KeyInt()) != 0 {
			t.Errorf("key order mismatch at %d", i)
		}
	}
}

func TestSaveFrostShare(t *testing.T) {
	priv, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	priv.Add(priv, big.NewInt(1))
	pid := tss.NewPartyID("k.agent", "agent", big.NewInt(1))
	fk, err := frosttss.ImportKey(priv, pid)
	if err != nil {
		t.Fatalf("ImportKey: %s", err)
	}
	ip := &InitPayload{WalletID: "crws-frost", Threshold: 1, Peers: testPeers()}
	sh := saveFrostShare("sid-1", ip, fk)
	if sh == nil {
		t.Fatalf("saveFrostShare returned nil")
	}
	if sh.Schema != store.SchemaFrost {
		t.Errorf("schema: want frost got %q", sh.Schema)
	}
	if sh.WalletID != "crws-frost" {
		t.Errorf("wallet id: got %q", sh.WalletID)
	}
	if len(sh.PubKey) != 32 {
		t.Errorf("pubkey: want 32 bytes got %d", len(sh.PubKey))
	}
	if sh.FrostKey == nil {
		t.Errorf("frost key not attached")
	}
	if len(sh.DklsBlob) != 0 {
		t.Errorf("dkls blob should be empty for a frost share")
	}
}

func TestSaveDklsShare(t *testing.T) {
	ecPriv, err := ecdsa.GenerateKey(tss.S256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %s", err)
	}
	pid := tss.NewPartyID("k.agent", "agent", big.NewInt(1))
	dk, err := dklstss.ImportKey(ecPriv, pid)
	if err != nil {
		t.Fatalf("ImportKey: %s", err)
	}
	ip := &InitPayload{WalletID: "crws-eth", Threshold: 1, Peers: testPeers()}
	sh, err := saveDklsShare("sid-2", ip, dk)
	if err != nil {
		t.Fatalf("saveDklsShare: %s", err)
	}
	if sh.Schema != store.SchemaDkls23 {
		t.Errorf("schema: want dkls23 got %q", sh.Schema)
	}
	if len(sh.DklsBlob) == 0 {
		t.Errorf("dkls blob should be populated")
	}
	if len(sh.Secp256k1Pub) != 33 {
		t.Errorf("secp256k1 pub: want 33 bytes got %d", len(sh.Secp256k1Pub))
	}
	if sh.SolanaAddressBytes() != nil {
		t.Errorf("dkls share should have no Solana address")
	}
	// Round-trips back to a usable key.
	if _, err := sh.LoadDkls(); err != nil {
		t.Errorf("LoadDkls on freshly-saved dkls share: %s", err)
	}
}

func TestSaveFrostShareNil(t *testing.T) {
	if saveFrostShare("sid", &InitPayload{}, nil) != nil {
		t.Errorf("saveFrostShare(nil) should return nil")
	}
}

func TestSaveDklsShareNil(t *testing.T) {
	if _, err := saveDklsShare("sid", &InitPayload{}, nil); err == nil {
		t.Errorf("saveDklsShare(nil) should error")
	}
}
