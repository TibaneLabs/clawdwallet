package solana

import (
	"errors"

	"github.com/KarpelesLab/outscript"
)

// AddressFromPubKey returns the base58 Solana address for a 32-byte EdDSA
// public key.
func AddressFromPubKey(pub []byte) (string, error) {
	if len(pub) != 32 {
		return "", errors.New("solana: pubkey must be 32 bytes")
	}
	var k outscript.SolanaKey
	copy(k[:], pub)
	return k.String(), nil
}

// KeyFromAddress parses a base58 Solana address into a SolanaKey.
func KeyFromAddress(addr string) (outscript.SolanaKey, error) {
	return outscript.ParseSolanaKey(addr)
}
