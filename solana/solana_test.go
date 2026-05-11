package solana

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/KarpelesLab/outscript"
)

// TestAddressRoundTrip exercises the pubkey -> base58 derivation and back.
func TestAddressRoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := AddressFromPubKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	key, err := KeyFromAddress(addr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key[:], pub) {
		t.Fatalf("round trip mismatch:\n got %x\nwant %x", key[:], pub)
	}
}

// TestTransferCheckedEncoding hard-codes the byte layout we expect for
// instruction 12 (data[0]=12, amount little-endian, decimals trailing).
func TestTransferCheckedEncoding(t *testing.T) {
	src := outscript.SolanaKey{1}
	mint := outscript.SolanaKey{2}
	dst := outscript.SolanaKey{3}
	owner := outscript.SolanaKey{4}
	ix := SPLTransferCheckedInstruction(src, mint, dst, owner, 0x0102030405060708, 6)
	want := "0c080706050403020106"
	got := hex.EncodeToString(ix.Data)
	if got != want {
		t.Fatalf("data layout mismatch:\n got %s\nwant %s", got, want)
	}
	if ix.ProgramID != SolanaTokenProgram {
		t.Fatal("wrong program id")
	}
	if len(ix.Accounts) != 4 {
		t.Fatalf("expected 4 accounts, got %d", len(ix.Accounts))
	}
	if !ix.Accounts[3].IsSigner {
		t.Fatal("owner slot must be signer")
	}
}

// TestAttachSignatureRoundTrip builds a tx, computes the message bytes, signs
// them with ed25519, attaches the signature, and verifies via tx.Verify.
func TestAttachSignatureRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var feePayer outscript.SolanaKey
	copy(feePayer[:], pub)
	var blockhash outscript.SolanaKey
	if _, err := rand.Read(blockhash[:]); err != nil {
		t.Fatal(err)
	}
	dst := outscript.SolanaKey{42}
	ix := outscript.SolanaTransferInstruction(feePayer, dst, 1000)

	tx, err := outscript.NewSolanaTx(feePayer, blockhash, ix)
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, err := MessageBytes(tx)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, msgBytes)
	if err := AttachSignature(tx, feePayer, sig); err != nil {
		t.Fatal(err)
	}
	if err := tx.Verify(); err != nil {
		t.Fatalf("verify after manual attach failed: %v", err)
	}
}
