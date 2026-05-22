package agent

import (
	"encoding/hex"
	"encoding/json"
	"testing"
)

// TestMarshalLeaderInit asserts the agent (as sign leader) produces an init
// payload shaped the way wdrone's parseTxsignInit expects (peers as PartyID
// objects with id/moniker/key, plus a per-recipient `name`).
func TestMarshalLeaderInit(t *testing.T) {
	signers := []PeerSpec{
		{SpotID: "k.agent", Moniker: "agent"},
		{SpotID: "k.wdrone", Moniker: "wdrone"},
	}
	digest := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	}
	body, err := marshalLeaderInit("crwsv-test", signers, signers[1], 1, digest)
	if err != nil {
		t.Fatalf("marshalLeaderInit: %s", err)
	}

	// Parse as a generic map and assert the wdrone-relevant fields.
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("json unmarshal: %s", err)
	}
	if got := m["threshold"]; got != float64(1) {
		t.Fatalf("threshold: want 1, got %v", got)
	}
	if got := m["curve"]; got != "ed25519" {
		t.Fatalf("curve: want ed25519, got %v", got)
	}
	if got := m["digest"]; got != hex.EncodeToString(digest) {
		t.Fatalf("digest: want %s, got %v", hex.EncodeToString(digest), got)
	}
	if got := m["sid"]; got != "crwsv-test" {
		t.Fatalf("sid: want crwsv-test, got %v", got)
	}
	if got := m["type"]; got != "txsign" {
		t.Fatalf("type: want txsign, got %v", got)
	}
	// Default leader path advertises the modern FROST protocol so the
	// recipient (wdrone-compat) picks the right runner.
	if got := m["protocol"]; got != "frost" {
		t.Fatalf("protocol: want frost, got %v", got)
	}

	peers, ok := m["peers"].([]any)
	if !ok {
		t.Fatalf("peers: want array, got %T", m["peers"])
	}
	if len(peers) != 2 {
		t.Fatalf("peers: want 2 entries, got %d", len(peers))
	}
	// Each entry must carry id+moniker+key (NOT spot_id) so wdrone's
	// walletSignTxsignInit unmarshal succeeds.
	for i, raw := range peers {
		entry, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("peers[%d]: want object, got %T", i, raw)
		}
		if _, hasID := entry["id"]; !hasID {
			t.Fatalf("peers[%d]: missing `id` (wdrone-compat)", i)
		}
		if _, hasMoniker := entry["moniker"]; !hasMoniker {
			t.Fatalf("peers[%d]: missing `moniker`", i)
		}
		if _, hasKey := entry["key"]; !hasKey {
			t.Fatalf("peers[%d]: missing `key`", i)
		}
	}

	name, ok := m["name"].(map[string]any)
	if !ok {
		t.Fatalf("name: want object, got %T", m["name"])
	}
	if got := name["id"]; got != "k.wdrone" {
		t.Fatalf("name.id: want k.wdrone, got %v", got)
	}
}

// TestSignResponseUnmarshalAcceptsBothInitKeys verifies the policy response
// decoder tolerates `init_payload` AND `init` (legacy phplatform alias).
func TestInitPayloadJSON(t *testing.T) {
	// Verify the local InitPayload type accepts the canonical wire shape with
	// `type` (not `kind`) and `id` in peers (matches tss-lib's protobuf JSON
	// tag — the same field name wdrone reads via tss.SortedPartyIDs).
	body := []byte(`{
		"sid": "crwsv-abc",
		"type": "txsign",
		"curve": "ed25519",
		"threshold": 1,
		"peers": [
			{"id":"k.agent","moniker":"agent","key":"AAAA"},
			{"id":"k.wdrone","moniker":"wdrone","key":"BBBB"}
		],
		"digest": "deadbeef"
	}`)
	var ip InitPayload
	if err := json.Unmarshal(body, &ip); err != nil {
		t.Fatalf("InitPayload unmarshal: %s", err)
	}
	if ip.Kind != SessionSign {
		t.Fatalf("Kind: want %q, got %q", SessionSign, ip.Kind)
	}
	if ip.Curve != "ed25519" {
		t.Fatalf("Curve: want ed25519, got %q", ip.Curve)
	}
	if len(ip.Peers) != 2 {
		t.Fatalf("Peers: want 2, got %d", len(ip.Peers))
	}
	if ip.Peers[0].SpotID != "k.agent" {
		t.Fatalf("peer 0 SpotID: want k.agent, got %q", ip.Peers[0].SpotID)
	}
	if ip.Peers[0].Key != "AAAA" {
		t.Fatalf("peer 0 Key: want AAAA, got %q", ip.Peers[0].Key)
	}

	// Legacy `kind` alias.
	legacy := []byte(`{"kind":"sign","peers":[]}`)
	var ip2 InitPayload
	if err := json.Unmarshal(legacy, &ip2); err != nil {
		t.Fatalf("legacy unmarshal: %s", err)
	}
	if ip2.Kind != SessionSign {
		t.Fatalf("legacy: Kind want txsign, got %q", ip2.Kind)
	}
}
