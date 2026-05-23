package agent

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/TibaneLabs/clawdwallet/config"
	"github.com/TibaneLabs/clawdwallet/policy"
	"github.com/TibaneLabs/clawdwallet/store"
)

func TestBase64URLEncode(t *testing.T) {
	in := []byte{0x01, 0x02, 0x03}
	if got := base64URLEncode(in); got != base64.RawURLEncoding.EncodeToString(in) {
		t.Errorf("base64URLEncode mismatch: %q", got)
	}
}

func TestEncodeParsedEffects(t *testing.T) {
	intent := policy.Intent{Description: "buy data", Reason: "skill needs it"}
	parsed := policy.ParsedEffects{
		TokenDeltas: []policy.TokenDelta{{Mint: "MINT", Delta: -100, Decimals: 6}},
	}
	raw, err := encodeParsedEffects(intent, parsed, nil)
	if err != nil {
		t.Fatalf("encodeParsedEffects: %s", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %s", err)
	}
	// token_deltas is mirrored to the top level for the Stage-1 evaluator.
	if _, ok := m["token_deltas"]; !ok {
		t.Errorf("encodeParsedEffects must surface top-level token_deltas")
	}
	if _, ok := m["intent"]; !ok {
		t.Errorf("encodeParsedEffects must carry intent")
	}
}

func TestResolveSignersFromInitPayload(t *testing.T) {
	a := &Agent{cfg: &config.Config{Moniker: "agent"}}
	resp := &policy.SignResponse{
		InitPayload: &policy.InitPayload{
			Peers: []policy.PeerInit{
				{SpotID: "k.agent", Moniker: "agent", Key: "AAAA"},
				{SpotID: "k.wdrone", Moniker: "wdrone", Key: "BBBB"},
			},
		},
	}
	sh := &store.Share{Threshold: 1}
	got, err := a.resolveSigners(resp, sh)
	if err != nil {
		t.Fatalf("resolveSigners: %s", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 signers, got %d", len(got))
	}
	if got[0].SpotID != "k.agent" || got[1].SpotID != "k.wdrone" {
		t.Errorf("signer ids: %+v", got)
	}
	if got[1].Key != "BBBB" {
		t.Errorf("init-payload key not carried: %+v", got[1])
	}
}

func TestResolveSignersNoPeers(t *testing.T) {
	a := &Agent{cfg: &config.Config{Moniker: "agent"}}
	// No init payload and a share with no peer table → error.
	if _, err := a.resolveSigners(&policy.SignResponse{}, &store.Share{Threshold: 1}); err == nil {
		t.Errorf("resolveSigners should error when no peers are known")
	}
}

func TestShareKeyFor(t *testing.T) {
	a := &Agent{cfg: &config.Config{Moniker: "agent"}}
	sh := &store.Share{
		PeerSpotIDs: []string{"k.agent", "k.wdrone"},
		PeerKeys:    []*big.Int{big.NewInt(0x0102), big.NewInt(0x0304)},
	}
	got := a.shareKeyFor(sh, "k.wdrone")
	want := base64.RawURLEncoding.EncodeToString(big.NewInt(0x0304).Bytes())
	if got != want {
		t.Errorf("shareKeyFor: want %q got %q", want, got)
	}
	// Unknown spot id → empty.
	if a.shareKeyFor(sh, "k.absent") != "" {
		t.Errorf("shareKeyFor should be empty for an unknown spot id")
	}
	// Nil share → empty.
	if a.shareKeyFor(nil, "k.agent") != "" {
		t.Errorf("shareKeyFor(nil) should be empty")
	}
}
