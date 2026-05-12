package policy

import (
	"encoding/json"
	"testing"
)

// TestSignResponseDecode covers the canonical
// `Crypto/WalletSign:signByPolicy` response shape: session id, remote_key,
// wdrone_spot_id, and the InitPayload that drives the agent→wdrone
// `walletsign/<sid>/init` send.
func TestSignResponseDecode(t *testing.T) {
	body := `{
		"session": "crwsv-1",
		"format": "all-digits",
		"length": 6,
		"remote_key": "crws-1:crwsv-1",
		"wdrone_spot_id": "k.wdrone",
		"init_payload": {
			"type": "txsign",
			"curve": "ed25519",
			"threshold": 1,
			"peers": [
				{"id":"k.agent","moniker":"agent","key":"AAAA"},
				{"id":"k.wdrone","moniker":"wdrone","key":"BBBB"}
			],
			"digest": "3q2+7w=="
		}
	}`
	var r SignResponse
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatalf("unmarshal: %s", err)
	}
	if !r.Approved {
		t.Fatalf("Approved should be true when session is set")
	}
	if r.SessionID() != "crwsv-1" {
		t.Fatalf("SessionID: want crwsv-1, got %q", r.SessionID())
	}
	if r.WdroneSpotID != "k.wdrone" {
		t.Fatalf("WdroneSpotID: want k.wdrone, got %q", r.WdroneSpotID)
	}
	if r.InitPayload == nil {
		t.Fatalf("InitPayload should be populated")
	}
	if len(r.InitPayload.Peers) != 2 {
		t.Fatalf("InitPayload.Peers: want 2, got %d", len(r.InitPayload.Peers))
	}
	if r.InitPayload.Peers[0].SpotID != "k.agent" {
		t.Fatalf("peer[0].SpotID: want k.agent, got %q", r.InitPayload.Peers[0].SpotID)
	}
	if r.InitPayload.Digest != "3q2+7w==" {
		t.Fatalf("InitPayload.Digest: unexpected %q", r.InitPayload.Digest)
	}
}

// TestSignResponseEmptyApprovesFalse asserts that a response without a
// session id is treated as non-approved (defensive — phplatform throws on
// rejection so this branch shouldn't fire in practice).
func TestSignResponseEmptyApprovesFalse(t *testing.T) {
	var r SignResponse
	if err := json.Unmarshal([]byte(`{}`), &r); err != nil {
		t.Fatalf("unmarshal: %s", err)
	}
	if r.Approved {
		t.Fatalf("Approved should be false for empty response")
	}
}
