package store

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/KarpelesLab/tss-lib/v2/dklstss"
	"github.com/KarpelesLab/tss-lib/v2/frosttss"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestShareJSONRoundTrip_Frost verifies that a SchemaFrost share survives a
// JSON round-trip with the GroupPublicKey and peer table intact. The Save /
// Load (bottle) path serialises this exact JSON payload — testing JSON
// directly lets us check the schema discriminator without dragging a
// keychain into the test.
func TestShareJSONRoundTrip_Frost(t *testing.T) {
	priv, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	priv.Add(priv, big.NewInt(1)) // ensure non-zero
	partyID := tss.NewPartyID("party-1", "party-1", big.NewInt(1))
	fk, err := frosttss.ImportKey(priv, partyID)
	if err != nil {
		t.Fatalf("frosttss.ImportKey: %s", err)
	}

	original := &Share{
		WalletID:    "crws-test",
		Schema:      SchemaFrost,
		PeerKeys:    []*big.Int{big.NewInt(1), big.NewInt(2)},
		PeerSpotIDs: []string{"k.alice", "k.bob"},
		Threshold:   1,
		FrostKey:    fk,
		PubKey:      EdPointBytes(fk.GroupPublicKey),
	}

	wire, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %s", err)
	}

	var got Share
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatalf("unmarshal: %s", err)
	}

	if got.Schema != SchemaFrost {
		t.Errorf("schema: want %q got %q", SchemaFrost, got.Schema)
	}
	if got.WalletID != "crws-test" {
		t.Errorf("wallet_id: got %q", got.WalletID)
	}
	if got.Threshold != 1 {
		t.Errorf("threshold: got %d", got.Threshold)
	}
	if got.FrostKey == nil {
		t.Fatalf("frost_key not preserved")
	}
	if got.FrostKey.GroupPublicKey == nil {
		t.Fatalf("frost_key.GroupPublicKey not preserved")
	}
	if !bytes.Equal(EdPointBytes(got.FrostKey.GroupPublicKey), EdPointBytes(fk.GroupPublicKey)) {
		t.Errorf("frost_key.GroupPublicKey diverged across round-trip")
	}
	if !bytes.Equal(got.SolanaAddressBytes(), EdPointBytes(fk.GroupPublicKey)) {
		t.Errorf("SolanaAddressBytes diverged for frost share")
	}
	if len(got.DklsBlob) != 0 {
		t.Errorf("dkls_blob should be empty for frost share")
	}
	if len(got.Secp256k1Pub) != 0 {
		t.Errorf("secp256k1_pub should be empty for frost share")
	}
}

// TestShareJSONRoundTrip_Dkls verifies that a SchemaDkls23 share survives
// JSON round-trip via the opaque DklsBlob bytes, and that the reconstructed
// dklstss.Key matches the original.
func TestShareJSONRoundTrip_Dkls(t *testing.T) {
	ecPriv, err := ecdsa.GenerateKey(tss.S256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %s", err)
	}
	partyID := tss.NewPartyID("party-1", "party-1", big.NewInt(1))
	dk, err := dklstss.ImportKey(ecPriv, partyID)
	if err != nil {
		t.Fatalf("dklstss.ImportKey: %s", err)
	}
	var blob bytes.Buffer
	if err := dk.Save(&blob); err != nil {
		t.Fatalf("dklstss.Key.Save: %s", err)
	}

	original := &Share{
		WalletID:     "crws-test-eth",
		Schema:       SchemaDkls23,
		PeerKeys:     []*big.Int{big.NewInt(1), big.NewInt(2)},
		PeerSpotIDs:  []string{"k.alice", "k.bob"},
		Threshold:    1,
		DklsBlob:     blob.Bytes(),
		Secp256k1Pub: elliptic.MarshalCompressed(tss.S256(), ecPriv.X, ecPriv.Y),
	}

	wire, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %s", err)
	}

	var got Share
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatalf("unmarshal: %s", err)
	}

	if got.Schema != SchemaDkls23 {
		t.Errorf("schema: want %q got %q", SchemaDkls23, got.Schema)
	}
	if got.FrostKey != nil {
		t.Errorf("frost_key should be nil for dkls share")
	}
	if !bytes.Equal(got.DklsBlob, blob.Bytes()) {
		t.Errorf("dkls_blob diverged across round-trip")
	}
	if !bytes.Equal(got.Secp256k1Pub, original.Secp256k1Pub) {
		t.Errorf("secp256k1_pub diverged across round-trip")
	}
	if got.SolanaAddressBytes() != nil {
		t.Errorf("SolanaAddressBytes should be nil for dkls share, got %x", got.SolanaAddressBytes())
	}

	// LoadDkls reconstructs an equivalent key.
	reloaded, err := got.LoadDkls()
	if err != nil {
		t.Fatalf("LoadDkls: %s", err)
	}
	if reloaded.ECDSAPub == nil {
		t.Fatalf("reloaded ECDSAPub is nil")
	}
	if reloaded.ECDSAPub.X().Cmp(ecPriv.X) != 0 || reloaded.ECDSAPub.Y().Cmp(ecPriv.Y) != 0 {
		t.Errorf("reloaded ECDSAPub diverged from original")
	}
}

// TestShareLoadDkls_WrongSchema asserts the schema gate trips when called
// against a non-DKLs share, instead of silently returning a half-populated
// key.
func TestShareLoadDkls_WrongSchema(t *testing.T) {
	sh := &Share{Schema: SchemaFrost, DklsBlob: []byte{0x01, 0x02}}
	if _, err := sh.LoadDkls(); err == nil {
		t.Fatalf("LoadDkls on a frost share should error")
	}
}

// TestShareLoadDkls_EmptyBlob asserts an explicit empty-blob error when the
// schema says dkls23 but no Save bytes are present.
func TestShareLoadDkls_EmptyBlob(t *testing.T) {
	sh := &Share{Schema: SchemaDkls23}
	if _, err := sh.LoadDkls(); err == nil {
		t.Fatalf("LoadDkls on an empty dkls share should error")
	}
}
