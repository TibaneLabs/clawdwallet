// Package store persists the agent's TSS share to disk in encrypted form.
//
// The Spot identity itself lives in spotlib's own DiskStore (PEM key files).
// Here we wrap the EdDSA keygen output in a gobottle so it never lands on
// disk in cleartext.
package store

import (
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
	"github.com/KarpelesLab/tss-lib/v2/eddsa/keygen"
	"github.com/fxamacker/cbor/v2"
)

const shareFile = "share.bottle"

// Share holds the persisted EdDSA TSS keygen output for this party plus the metadata
// needed to reconstruct signing parameters across restarts.
type Share struct {
	// WalletID identifies the wallet this share belongs to.
	WalletID string `json:"wallet_id"`

	// PartyKey is the deterministic big.Int key used to construct this party's PartyID.
	PartyKey *big.Int `json:"party_key"`

	// PeerKeys is the deterministic ordered list of party keys (including us).
	// The index of PartyKey within PeerKeys is this party's slot.
	PeerKeys []*big.Int `json:"peer_keys"`

	// PeerSpotIDs maps each PeerKey index to its Spot identity ("k.<base64>").
	PeerSpotIDs []string `json:"peer_spot_ids"`

	// Threshold is t in t-of-n. For 2-of-3, this is 1 (signing requires t+1=2).
	Threshold int `json:"threshold"`

	// SaveData is the raw EdDSA keygen output. Encoded as JSON so we don't have
	// to write a CBOR mapping for tss-lib's BigInt-laden struct.
	SaveData *keygen.LocalPartySaveData `json:"save_data"`

	// PubKey is the aggregate EdDSA public key (32 bytes Ed25519 encoding).
	// On Solana this is the wallet address.
	PubKey []byte `json:"pub_key"`
}

// SolanaAddressBytes returns the 32-byte representation of the aggregate public key,
// which on Solana is the wallet address.
func (s *Share) SolanaAddressBytes() []byte {
	if len(s.PubKey) == 32 {
		out := make([]byte, 32)
		copy(out, s.PubKey)
		return out
	}
	if s.SaveData == nil || s.SaveData.EDDSAPub == nil {
		return nil
	}
	return EdPointBytes(s.SaveData.EDDSAPub)
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
