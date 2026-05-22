package agent

import (
	"math/big"
	"testing"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

func TestResolveCurveProtocol(t *testing.T) {
	cases := []struct {
		name, curve, protocol string
		wantCurve, wantProto  string
		wantEC                string // "ed" | "s256"
		wantErr               bool
	}{
		// Happy paths.
		{"frost explicit", "ed25519", "frost", "ed25519", "frost", "ed", false},
		{"frost curve-only", "ed25519", "", "ed25519", "frost", "ed", false},
		{"frost protocol-only", "", "frost", "ed25519", "frost", "ed", false},
		{"default frost", "", "", "ed25519", "frost", "ed", false},

		{"dkls23 explicit", "secp256k1", "dkls23", "secp256k1", "dkls23", "s256", false},
		{"dkls23 curve-only", "secp256k1", "", "secp256k1", "dkls23", "s256", false},
		{"dkls23 protocol-only", "", "dkls23", "secp256k1", "dkls23", "s256", false},

		// Rejections.
		{"frost on wrong curve", "secp256k1", "frost", "", "", "", true},
		{"dkls23 on wrong curve", "ed25519", "dkls23", "", "", "", true},
		{"legacy is dead", "ed25519", "legacy", "", "", "", true},
		{"unknown protocol", "ed25519", "bogus", "", "", "", true},
		{"unknown curve", "p256", "", "", "", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ec, c, p, err := resolveCurveProtocol(tc.curve, tc.protocol)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err: want=%v got=%v (%v)", tc.wantErr, err != nil, err)
			}
			if tc.wantErr {
				return
			}
			if c != tc.wantCurve {
				t.Errorf("curve: want %q got %q", tc.wantCurve, c)
			}
			if p != tc.wantProto {
				t.Errorf("protocol: want %q got %q", tc.wantProto, p)
			}
			switch tc.wantEC {
			case "ed":
				if ec != tss.Edwards() {
					t.Errorf("ec: want tss.Edwards(), got something else")
				}
			case "s256":
				if ec != tss.S256() {
					t.Errorf("ec: want tss.S256(), got something else")
				}
			}
		})
	}
}

func TestDecodeDigestBytes(t *testing.T) {
	want := []byte{0xde, 0xad, 0xbe, 0xef}
	for _, in := range []string{"deadbeef", "0xdeadbeef", "3q2-7w", "3q2+7w=="} {
		got, err := decodeDigestBytes(in)
		if err != nil {
			t.Errorf("decodeDigestBytes(%q): %s", in, err)
			continue
		}
		if string(got) != string(want) {
			t.Errorf("decodeDigestBytes(%q): want %x got %x", in, want, got)
		}
	}
	if _, err := decodeDigestBytes(""); err == nil {
		t.Errorf("expected error on empty digest")
	}
}

func TestBigIntToFixed(t *testing.T) {
	// short input gets left-padded
	in := new(big.Int).SetBytes([]byte{0x12, 0x34})
	out := bigIntToFixed(in, 4)
	if got, want := out, []byte{0, 0, 0x12, 0x34}; string(got) != string(want) {
		t.Errorf("padding: want %x got %x", want, got)
	}
	// exact length passthrough
	out2 := bigIntToFixed(new(big.Int).SetBytes([]byte{1, 2, 3, 4}), 4)
	if string(out2) != string([]byte{1, 2, 3, 4}) {
		t.Errorf("exact: got %x", out2)
	}
}
