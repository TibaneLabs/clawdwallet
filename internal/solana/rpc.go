package solana

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/KarpelesLab/outscript"
)

// Client is a minimal Solana JSON-RPC client. It only implements the subset of
// methods the agent needs: get a recent blockhash, query balances, look up the
// owner of a token account, fetch the mint decimals, and submit transactions.
type Client struct {
	URL  string
	HTTP *http.Client
	id   atomic.Uint64
}

// NewClient returns a client pointed at the given JSON-RPC endpoint.
func NewClient(url string) *Client {
	if url == "" {
		url = "https://api.mainnet-beta.solana.com"
	}
	return &Client{URL: url, HTTP: http.DefaultClient}
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      uint64 `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string {
	return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message)
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error,omitempty"`
}

// call issues a JSON-RPC call and unmarshals the result into out (which may be nil).
func (c *Client) call(ctx context.Context, method string, params []any, out any) error {
	req := rpcRequest{
		JSONRPC: "2.0",
		ID:      c.id.Add(1),
		Method:  method,
		Params:  params,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(hreq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var r rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return fmt.Errorf("decode rpc response: %w", err)
	}
	if r.Error != nil {
		return r.Error
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(r.Result, out)
}

// GetLatestBlockhash returns the most recent blockhash from the cluster.
func (c *Client) GetLatestBlockhash(ctx context.Context) (outscript.SolanaKey, error) {
	var res struct {
		Value struct {
			Blockhash            string `json:"blockhash"`
			LastValidBlockHeight uint64 `json:"lastValidBlockHeight"`
		} `json:"value"`
	}
	if err := c.call(ctx, "getLatestBlockhash", []any{map[string]string{"commitment": "confirmed"}}, &res); err != nil {
		return outscript.SolanaKey{}, err
	}
	return outscript.ParseSolanaKey(res.Value.Blockhash)
}

// GetBalance returns the lamport balance of an account.
func (c *Client) GetBalance(ctx context.Context, addr string) (uint64, error) {
	var res struct {
		Value uint64 `json:"value"`
	}
	if err := c.call(ctx, "getBalance", []any{addr, map[string]string{"commitment": "confirmed"}}, &res); err != nil {
		return 0, err
	}
	return res.Value, nil
}

// TokenAmount is the cluster response shape for SPL balances.
type TokenAmount struct {
	Amount         string  `json:"amount"`
	Decimals       uint8   `json:"decimals"`
	UIAmount       float64 `json:"uiAmount"`
	UIAmountString string  `json:"uiAmountString"`
}

// GetTokenAccountBalance returns the SPL balance of a token account.
func (c *Client) GetTokenAccountBalance(ctx context.Context, ata string) (*TokenAmount, error) {
	var res struct {
		Value TokenAmount `json:"value"`
	}
	if err := c.call(ctx, "getTokenAccountBalance", []any{ata, map[string]string{"commitment": "confirmed"}}, &res); err != nil {
		return nil, err
	}
	return &res.Value, nil
}

// GetTokenSupplyDecimals returns the decimals of a mint.
func (c *Client) GetTokenSupplyDecimals(ctx context.Context, mint string) (uint8, error) {
	var res struct {
		Value TokenAmount `json:"value"`
	}
	if err := c.call(ctx, "getTokenSupply", []any{mint, map[string]string{"commitment": "confirmed"}}, &res); err != nil {
		return 0, err
	}
	return res.Value.Decimals, nil
}

// SendTransaction submits a fully-signed serialized transaction and returns its signature.
func (c *Client) SendTransaction(ctx context.Context, rawTx []byte) (string, error) {
	encoded := base64.StdEncoding.EncodeToString(rawTx)
	opts := map[string]any{
		"encoding":            "base64",
		"skipPreflight":       false,
		"preflightCommitment": "confirmed",
	}
	var sig string
	if err := c.call(ctx, "sendTransaction", []any{encoded, opts}, &sig); err != nil {
		return "", err
	}
	return sig, nil
}

// SimulateTransaction performs a preflight simulation. Useful for the policy
// evaluator's parsed_effects verification.
func (c *Client) SimulateTransaction(ctx context.Context, rawTx []byte) (json.RawMessage, error) {
	encoded := base64.StdEncoding.EncodeToString(rawTx)
	opts := map[string]any{
		"encoding":   "base64",
		"commitment": "confirmed",
		"sigVerify":  false,
	}
	var res json.RawMessage
	if err := c.call(ctx, "simulateTransaction", []any{encoded, opts}, &res); err != nil {
		return nil, err
	}
	return res, nil
}
