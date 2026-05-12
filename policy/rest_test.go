package policy

import (
	"encoding/json"
	"testing"
)

// TestSignResponseAcceptsInitPayloadAlias confirms the policy response decoder
// tolerates both `init_payload` and the legacy `init` field name. The
// phplatform integration agent has not finalised the canonical name; the
// clawdwallet agent accepts either.
func TestSignResponseAcceptsInitPayloadAlias(t *testing.T) {
	for name, body := range map[string]string{
		"init_payload": `{
			"remote_key": "crws-1:crwsv-1",
			"approved": true,
			"peers": ["k.agent","k.wdrone"],
			"init_payload": {
				"sid": "crwsv-1",
				"type": "txsign",
				"curve": "ed25519",
				"threshold": 1,
				"peers": [
					{"spot_id":"k.agent","moniker":"agent","key":"AAAA"},
					{"spot_id":"k.wdrone","moniker":"wdrone","key":"BBBB"}
				],
				"digest": "deadbeef"
			}
		}`,
		"init": `{
			"remote_key": "crws-1:crwsv-1",
			"approved": true,
			"init": {
				"sid": "crwsv-1",
				"type": "txsign",
				"peers": [
					{"spot_id":"k.agent","moniker":"agent","key":"AAAA"}
				]
			}
		}`,
	} {
		t.Run(name, func(t *testing.T) {
			var r SignResponse
			if err := json.Unmarshal([]byte(body), &r); err != nil {
				t.Fatalf("unmarshal: %s", err)
			}
			if !r.Approved {
				t.Fatalf("Approved should be true")
			}
			if r.SessionID() != "crwsv-1" {
				t.Fatalf("SessionID: want crwsv-1, got %q", r.SessionID())
			}
			if r.InitPayload == nil {
				t.Fatalf("InitPayload should be populated under field %q", name)
			}
			if len(r.InitPayload.Peers) == 0 {
				t.Fatalf("InitPayload.Peers empty")
			}
			if r.InitPayload.Peers[0].SpotID != "k.agent" {
				t.Fatalf("peer[0].SpotID: want k.agent, got %q", r.InitPayload.Peers[0].SpotID)
			}
		})
	}
}

// TestSignResponseLegacyBarePeers asserts the agent still accepts the bare
// `peers: ["k.agent","k.wdrone"]` shape (no init_payload), which is what the
// Stage-1 scaffold returned before the integration phase.
func TestSignResponseLegacyBarePeers(t *testing.T) {
	body := `{"remote_key":"crws-1:crwsv-1","approved":true,"peers":["k.agent","k.wdrone"]}`
	var r SignResponse
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatalf("unmarshal: %s", err)
	}
	if r.InitPayload != nil {
		t.Fatalf("InitPayload should be nil for legacy shape")
	}
	if len(r.Peers) != 2 {
		t.Fatalf("Peers: want 2, got %d", len(r.Peers))
	}
}
