package solana

import (
	"errors"
	"fmt"

	"github.com/KarpelesLab/outscript"
)

// MessageBytes returns the serialized message bytes that need to be signed for
// the given transaction. Legacy and V0 messages are both handled. These are the
// bytes the TSS signing protocol takes as input.
func MessageBytes(tx *outscript.SolanaTx) ([]byte, error) {
	if tx == nil {
		return nil, errors.New("solana: nil tx")
	}
	if tx.MessageV0 != nil {
		return tx.MessageV0.MarshalBinary()
	}
	return tx.Message.MarshalBinary()
}

// MessageAccountKeys returns the ordered account keys of the message, which is
// what tells us which signature slot belongs to which signer.
func MessageAccountKeys(tx *outscript.SolanaTx) []outscript.SolanaKey {
	if tx == nil {
		return nil
	}
	if tx.MessageV0 != nil {
		return tx.MessageV0.AccountKeys
	}
	return tx.Message.AccountKeys
}

// NumRequiredSignatures returns the number of signatures expected in the wire form.
func NumRequiredSignatures(tx *outscript.SolanaTx) int {
	if tx == nil {
		return 0
	}
	if tx.MessageV0 != nil {
		return int(tx.MessageV0.Header.NumRequiredSignatures)
	}
	return int(tx.Message.Header.NumRequiredSignatures)
}

// AttachSignature writes a 64-byte Ed25519 signature into the slot whose
// account key matches signer. Used to apply a TSS-produced signature after
// out-of-band signing.
func AttachSignature(tx *outscript.SolanaTx, signer outscript.SolanaKey, sig []byte) error {
	if len(sig) != 64 {
		return fmt.Errorf("solana: signature must be 64 bytes, got %d", len(sig))
	}
	keys := MessageAccountKeys(tx)
	n := NumRequiredSignatures(tx)
	for i := 0; i < n && i < len(keys); i++ {
		if keys[i] == signer {
			if len(tx.Signatures) <= i {
				grown := make([][]byte, n)
				copy(grown, tx.Signatures)
				tx.Signatures = grown
			}
			tx.Signatures[i] = sig
			return nil
		}
	}
	return fmt.Errorf("solana: signer %s is not in the required signer set", signer)
}
