package agent

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// Protocol identifiers understood by the agent.
//
// The legacy GG18 paths (`ecdsatss` / `eddsatss`) are deliberately absent:
// clawdwallet runs only the modern protocols. A peer that sends an init
// payload with `protocol: "legacy"` (or omits the field with a curve that
// would default to GG18) is rejected at parse time.
const (
	ProtocolFrost  = "frost"  // FROST(Ed25519) per RFC 9591 → frosttss
	ProtocolDkls23 = "dkls23" // DKLs23 secp256k1 ECDSA → dklstss
)

// CurveEd25519 / CurveSecp256k1 are the canonical wire spellings used by the
// policy module and wdrone. tss-lib's CurveName(...) uses the same strings.
const (
	CurveEd25519   = "ed25519"
	CurveSecp256k1 = "secp256k1"
)

// resolveCurveProtocol picks the canonical elliptic curve plus the normalised
// (curve, protocol) pair for a given init payload.
//
// Either field may be omitted; missing fields are derived where the choice is
// unambiguous:
//
//   - protocol == "" + curve "" or "ed25519" → frost / ed25519 (the default,
//     consistent with Stage-1 Solana usage).
//   - protocol == "" + curve "secp256k1"     → dkls23 / secp256k1.
//   - protocol == "frost"                    → curve must be "" or ed25519.
//   - protocol == "dkls23"                   → curve must be "" or secp256k1.
//   - any other combination                  → error.
//
// This is the agent-side counterpart of wdrone/walletsign_protocol.go's
// resolveCurveProtocol (which also accepts the GG18 "legacy" path).
func resolveCurveProtocol(curve, protocol string) (elliptic.Curve, string, string, error) {
	switch protocol {
	case ProtocolFrost:
		if curve == "" {
			curve = CurveEd25519
		}
		if curve != CurveEd25519 {
			return nil, "", "", fmt.Errorf("protocol frost requires curve ed25519, got %q", curve)
		}
		return tss.Edwards(), curve, ProtocolFrost, nil

	case ProtocolDkls23:
		if curve == "" {
			curve = CurveSecp256k1
		}
		if curve != CurveSecp256k1 {
			return nil, "", "", fmt.Errorf("protocol dkls23 requires curve secp256k1, got %q", curve)
		}
		return tss.S256(), curve, ProtocolDkls23, nil

	case "":
		// Caller did not say which protocol. Pick one from the curve.
		switch curve {
		case "", CurveEd25519:
			return tss.Edwards(), CurveEd25519, ProtocolFrost, nil
		case CurveSecp256k1:
			return tss.S256(), CurveSecp256k1, ProtocolDkls23, nil
		default:
			return nil, "", "", fmt.Errorf("unknown curve %q (no protocol specified)", curve)
		}

	default:
		return nil, "", "", fmt.Errorf("unsupported protocol %q (legacy GG18 paths are not enabled)", protocol)
	}
}

// decodeDigestBytes accepts a hex (with or without `0x` prefix), base64-url,
// or base64-std digest and returns the raw bytes that frosttss / dklstss
// signing expects. Mirrors wdrone's helper of the same name.
func decodeDigestBytes(in string) ([]byte, error) {
	if in == "" {
		return nil, errors.New("empty digest")
	}
	hexCand := strings.TrimPrefix(in, "0x")
	if b, err := hex.DecodeString(hexCand); err == nil && len(b) > 0 {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(in); err == nil && len(b) > 0 {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(in); err == nil && len(b) > 0 {
		return b, nil
	}
	return nil, fmt.Errorf("digest %q is neither hex nor base64", in)
}

// bigIntToFixed left-pads a big.Int byte representation to the given length.
// Returns the unmodified bytes if they already equal or exceed size. Used by
// the DKLs23 signing path to emit the compact `R||S||V` 65-byte format wdrone
// reports back to the policy module.
func bigIntToFixed(n *big.Int, size int) []byte {
	b := n.Bytes()
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
