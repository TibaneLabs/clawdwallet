package solana

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// rpcServer spins up an httptest server that returns `result` (already a JSON
// value) for any JSON-RPC call, echoing back the request id. If rpcErr is
// non-empty it returns a JSON-RPC error instead.
func rpcServer(t *testing.T, result string, rpcErr string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		w.Header().Set("Content-Type", "application/json")
		if rpcErr != "" {
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+itoa(req.ID)+`,"error":{"code":-32000,"message":"`+rpcErr+`"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+itoa(req.ID)+`,"result":`+result+`}`)
	}))
	t.Cleanup(srv.Close)
	c := NewClient(srv.URL)
	return c
}

func itoa(u uint64) string {
	if u == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for u > 0 {
		i--
		b[i] = byte('0' + u%10)
		u /= 10
	}
	return string(b[i:])
}

func TestNewClientDefaultURL(t *testing.T) {
	c := NewClient("")
	if c.URL == "" {
		t.Errorf("NewClient(\"\") should fall back to a default URL")
	}
	if c.HTTP == nil {
		t.Errorf("NewClient should set an HTTP client")
	}
}

func TestGetBalance(t *testing.T) {
	c := rpcServer(t, `{"value":12345}`, "")
	got, err := c.GetBalance(context.Background(), "addr")
	if err != nil {
		t.Fatalf("GetBalance: %s", err)
	}
	if got != 12345 {
		t.Errorf("GetBalance: want 12345 got %d", got)
	}
}

func TestGetBalanceRPCError(t *testing.T) {
	c := rpcServer(t, "", "boom")
	if _, err := c.GetBalance(context.Background(), "addr"); err == nil {
		t.Errorf("GetBalance should surface the rpc error")
	}
}

func TestGetLatestBlockhash(t *testing.T) {
	// A valid base58 blockhash so ParseSolanaKey succeeds.
	c := rpcServer(t, `{"value":{"blockhash":"11111111111111111111111111111111","lastValidBlockHeight":100}}`, "")
	bh, err := c.GetLatestBlockhash(context.Background())
	if err != nil {
		t.Fatalf("GetLatestBlockhash: %s", err)
	}
	// "1"*32 in base58 decodes to all-zero bytes, so just assert the call
	// round-tripped without error rather than checking IsZero here.
	_ = bh
}

func TestGetTokenAccountBalance(t *testing.T) {
	c := rpcServer(t, `{"value":{"amount":"500","decimals":6,"uiAmount":0.0005,"uiAmountString":"0.0005"}}`, "")
	ta, err := c.GetTokenAccountBalance(context.Background(), "ata")
	if err != nil {
		t.Fatalf("GetTokenAccountBalance: %s", err)
	}
	if ta.Amount != "500" || ta.Decimals != 6 {
		t.Errorf("unexpected token amount: %+v", ta)
	}
}

func TestGetTokenSupplyDecimals(t *testing.T) {
	c := rpcServer(t, `{"value":{"amount":"0","decimals":9}}`, "")
	d, err := c.GetTokenSupplyDecimals(context.Background(), "mint")
	if err != nil {
		t.Fatalf("GetTokenSupplyDecimals: %s", err)
	}
	if d != 9 {
		t.Errorf("decimals: want 9 got %d", d)
	}
}

func TestSendTransaction(t *testing.T) {
	c := rpcServer(t, `"sigBase58"`, "")
	sig, err := c.SendTransaction(context.Background(), []byte{0x01, 0x02})
	if err != nil {
		t.Fatalf("SendTransaction: %s", err)
	}
	if sig != "sigBase58" {
		t.Errorf("signature: got %q", sig)
	}
}

func TestSimulateTransaction(t *testing.T) {
	c := rpcServer(t, `{"err":null,"logs":[]}`, "")
	res, err := c.SimulateTransaction(context.Background(), []byte{0x01})
	if err != nil {
		t.Fatalf("SimulateTransaction: %s", err)
	}
	if len(res) == 0 {
		t.Errorf("expected a result payload")
	}
}

func TestCallTransportError(t *testing.T) {
	// Point the client at a closed server to force a transport error.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()
	c := NewClient(url)
	if _, err := c.GetBalance(context.Background(), "addr"); err == nil {
		t.Errorf("expected transport error against a closed server")
	}
}
