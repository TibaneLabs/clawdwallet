// Package store persists the agent's TSS share to disk in encrypted form.
//
// The Spot identity itself lives in spotlib's own DiskStore (PEM key files).
// Here we wrap the TSS keygen output in a gobottle so it never lands on disk
// in cleartext.
//
// A persisted share carries a Schema discriminator (`frost` or `dkls23`) plus
// exactly one populated key field. FROST produces a standard Ed25519
// signature, so its public key is the wallet's Solana address. DKLs23
// produces a standard secp256k1 ECDSA signature and is intended for
// multi-chain custody (Ethereum, Bitcoin, …); it has no Solana address.
package store

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/BottleFmt/gobottle"
	tsslibcrypto "github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/dklstss"
	"github.com/KarpelesLab/tss-lib/v2/frosttss"
	"github.com/fxamacker/cbor/v2"
)

const shareFile = "share.bottle"

// Schema values for Share.Schema.
const (
	SchemaFrost  = "frost"
	SchemaDkls23 = "dkls23"
)

// Share holds the persisted TSS keygen output for this party plus the
// metadata needed to reconstruct signing parameters across restarts.
//
// Exactly one of FrostKey / DklsBlob is populated, selected by Schema. The
// peer table (PeerKeys / PeerSpotIDs / Threshold) and WalletID are common to
// both schemas.
type Share struct {
	// WalletID identifies the wallet this share belongs to. In Stage 1 this
	// is the server-issued crws- id (or the session id during initial keygen).
	WalletID string `json:"wallet_id"`

	// Schema discriminates the share's TSS protocol: SchemaFrost (Ed25519,
	// Solana-compatible) or SchemaDkls23 (secp256k1, secondary chains).
	Schema string `json:"schema"`

	// PartyKey is the deterministic big.Int key used to construct this party's PartyID.
	PartyKey *big.Int `json:"party_key,omitempty"`

	// PeerKeys is the deterministic ordered list of party keys (including us).
	// The index of PartyKey within PeerKeys is this party's slot.
	PeerKeys []*big.Int `json:"peer_keys"`

	// PeerSpotIDs maps each PeerKey index to its Spot identity ("k.<base64>").
	PeerSpotIDs []string `json:"peer_spot_ids"`

	// Threshold is t in t-of-n. For 2-of-3, this is 1 (signing requires t+1=2).
	Threshold int `json:"threshold"`

	// FrostKey is the FROST(Ed25519) keygen output. Populated when
	// Schema == SchemaFrost. The struct is JSON-friendly: every field
	// (including the *crypto.ECPoint commitments) has its own MarshalJSON.
	FrostKey *frosttss.Key `json:"frost_key,omitempty"`

	// DklsBlob holds the dklstss.Key.Save() byte string verbatim. The
	// dklstss key carries an elliptic.Curve interface plus per-pair OT
	// extension state that does not round-trip through generic JSON, so we
	// keep the protocol-defined serialisation and reconstruct via
	// dklstss.Load on access. Populated when Schema == SchemaDkls23.
	DklsBlob []byte `json:"dkls_blob,omitempty"`

	// PubKey is the wallet's 32-byte Ed25519 public key (the Solana address)
	// when Schema == SchemaFrost. Empty for SchemaDkls23.
	PubKey []byte `json:"pub_key,omitempty"`

	// Secp256k1Pub is the 33-byte SEC1-compressed secp256k1 public key when
	// Schema == SchemaDkls23. Empty for SchemaFrost.
	Secp256k1Pub []byte `json:"secp256k1_pub,omitempty"`
}

// SolanaAddressBytes returns the 32-byte Ed25519 representation of the
// aggregate public key — the Solana address — when this share is a FROST
// share. Returns nil for DKLs23 shares, which have no Solana address.
func (s *Share) SolanaAddressBytes() []byte {
	if s.Schema != SchemaFrost {
		return nil
	}
	if len(s.PubKey) == 32 {
		out := make([]byte, 32)
		copy(out, s.PubKey)
		return out
	}
	if s.FrostKey == nil || s.FrostKey.GroupPublicKey == nil {
		return nil
	}
	return EdPointBytes(s.FrostKey.GroupPublicKey)
}

// LoadDkls reconstructs the dklstss.Key from DklsBlob. Returns an error if
// the share is not a DKLs23 share or if the blob is missing/corrupt.
//
// The Key is read-only after reconstruction (sign / presign do not mutate
// it), so callers may cache the result across signing rounds. See
// dklstss/doc.go for the threading model.
func (s *Share) LoadDkls() (*dklstss.Key, error) {
	if s.Schema != SchemaDkls23 {
		return nil, fmt.Errorf("share schema is %q, not %q", s.Schema, SchemaDkls23)
	}
	if len(s.DklsBlob) == 0 {
		return nil, errors.New("dkls23 share has empty blob")
	}
	return dklstss.Load(bytes.NewReader(s.DklsBlob))
}

// EdPointBytes serializes an Ed25519 point to its 32-byte compressed form
// (little-endian y with the sign bit of x in the high bit of the last byte).
func EdPointBytes(p *tsslibcrypto.ECPoint) []byte {
	yb := p.Y().Bytes()
	out := make([]byte, 32)
	for i, b := range yb {
		if i >= 32 {
			break
		}
		out[31-i] = b
	}
	if p.X().Bit(0) == 1 {
		out[31] |= 0x80
	}
	return out
}

// Store wraps the on-disk encrypted share storage.
type Store struct {
	dir string
	kc  *gobottle.Keychain
}

// New constructs a Store rooted at dir using the given keychain (typically the same
// one the Spot client is using) to encrypt and decrypt the share bottle.
func New(dir string, kc *gobottle.Keychain) *Store {
	return &Store{dir: dir, kc: kc}
}

func (s *Store) Path() string {
	return filepath.Join(s.dir, shareFile)
}

// Save writes the share encrypted to the first signer in the keychain.
func (s *Store) Save(share *Share) error {
	if s.kc == nil {
		return errors.New("store: nil keychain")
	}
	data, err := json.Marshal(share)
	if err != nil {
		return fmt.Errorf("marshal share: %w", err)
	}
	pub, signer, err := firstSigner(s.kc)
	if err != nil {
		return err
	}

	b := gobottle.NewBottle(data)
	b.Header["ct"] = "json"
	if err := b.Encrypt(rand.Reader, pub); err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	if err := b.BottleUp(); err != nil {
		return fmt.Errorf("bottle up: %w", err)
	}
	if err := b.Sign(rand.Reader, signer); err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	wire, err := cbor.Marshal(b)
	if err != nil {
		return fmt.Errorf("cbor encode: %w", err)
	}
	tmp := s.Path() + ".tmp"
	if err := os.WriteFile(tmp, wire, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path())
}

// Load returns the persisted share or os.ErrNotExist if none is stored yet.
func (s *Store) Load() (*Share, error) {
	if s.kc == nil {
		return nil, errors.New("store: nil keychain")
	}
	raw, err := os.ReadFile(s.Path())
	if err != nil {
		return nil, err
	}
	op, err := gobottle.NewOpener(s.kc)
	if err != nil {
		return nil, fmt.Errorf("opener: %w", err)
	}
	data, _, err := op.OpenCbor(raw)
	if err != nil {
		return nil, fmt.Errorf("open bottle: %w", err)
	}
	var sh Share
	if err := json.Unmarshal(data, &sh); err != nil {
		return nil, fmt.Errorf("decode share: %w", err)
	}
	return &sh, nil
}

// Has reports whether a share file exists, without decrypting it.
func (s *Store) Has() bool {
	_, err := os.Stat(s.Path())
	return err == nil
}

// firstSigner returns the public key + crypto.Signer for the first signing
// key in the keychain. Used to encrypt the share to ourselves and sign it.
func firstSigner(kc *gobottle.Keychain) (crypto.PublicKey, crypto.Signer, error) {
	for s := range kc.Signers {
		return s.Public(), s, nil
	}
	return nil, nil, errors.New("store: keychain has no signers")
}
