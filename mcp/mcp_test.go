package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// newTestServer returns a Server with no Agent and a single echo tool, so the
// JSON-RPC routing layer can be exercised without a live agent.
func newTestServer() *Server {
	s := &Server{}
	s.tools = []toolSpec{
		{
			Name:        "echo",
			Description: "echoes its args",
			InputSchema: map[string]any{"type": "object"},
			Run: func(_ context.Context, args json.RawMessage) (any, error) {
				return map[string]any{"echoed": json.RawMessage(args)}, nil
			},
		},
	}
	return s
}

// call runs one request line through handle and returns the parsed response,
// or nil for notifications (which produce no output).
func call(t *testing.T, s *Server, line string) *rpcResponse {
	t.Helper()
	var buf strings.Builder
	s.Out = &buf
	s.handle(context.Background(), []byte(line))
	out := strings.TrimSpace(buf.String())
	if out == "" {
		return nil
	}
	var resp rpcResponse
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("unmarshal response %q: %s", out, err)
	}
	return &resp
}

func TestHandleInitialize(t *testing.T) {
	s := newTestServer()
	resp := call(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	if resp == nil || resp.Error != nil {
		t.Fatalf("initialize failed: %+v", resp)
	}
	m, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("result not an object: %T", resp.Result)
	}
	if m["protocolVersion"] == nil {
		t.Errorf("initialize result missing protocolVersion")
	}
}

func TestHandleToolsList(t *testing.T) {
	s := newTestServer()
	resp := call(t, s, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if resp == nil || resp.Error != nil {
		t.Fatalf("tools/list failed: %+v", resp)
	}
	m := resp.Result.(map[string]any)
	tools, ok := m["tools"].([]any)
	if !ok || len(tools) != 1 {
		t.Fatalf("tools/list should list 1 tool, got %v", m["tools"])
	}
}

func TestHandleToolsCall(t *testing.T) {
	s := newTestServer()
	resp := call(t, s, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"x":1}}}`)
	if resp == nil || resp.Error != nil {
		t.Fatalf("tools/call failed: %+v", resp)
	}
	m := resp.Result.(map[string]any)
	if _, ok := m["content"]; !ok {
		t.Errorf("tools/call result missing content: %+v", m)
	}
}

func TestHandleToolsCallUnknown(t *testing.T) {
	s := newTestServer()
	resp := call(t, s, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"nope","arguments":{}}}`)
	if resp == nil || resp.Error == nil {
		t.Fatalf("unknown tool should produce a JSON-RPC error, got %+v", resp)
	}
	if resp.Error.Code != -32601 {
		t.Errorf("unknown tool: want code -32601 got %d", resp.Error.Code)
	}
}

func TestHandleParseError(t *testing.T) {
	s := newTestServer()
	resp := call(t, s, `{not valid json`)
	if resp == nil || resp.Error == nil {
		t.Fatalf("parse error expected, got %+v", resp)
	}
	if resp.Error.Code != -32700 {
		t.Errorf("parse error: want code -32700 got %d", resp.Error.Code)
	}
}

func TestHandleMethodNotFound(t *testing.T) {
	s := newTestServer()
	resp := call(t, s, `{"jsonrpc":"2.0","id":5,"method":"does/not/exist"}`)
	if resp == nil || resp.Error == nil {
		t.Fatalf("method-not-found expected, got %+v", resp)
	}
	if resp.Error.Code != -32601 {
		t.Errorf("method not found: want code -32601 got %d", resp.Error.Code)
	}
}

func TestHandleNotificationNoResponse(t *testing.T) {
	s := newTestServer()
	// No id → notification → no response written.
	if resp := call(t, s, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); resp != nil {
		t.Errorf("notification should produce no response, got %+v", resp)
	}
}

func TestHandlePing(t *testing.T) {
	s := newTestServer()
	resp := call(t, s, `{"jsonrpc":"2.0","id":6,"method":"ping"}`)
	if resp == nil || resp.Error != nil {
		t.Fatalf("ping failed: %+v", resp)
	}
}
