// Package x402 implements the HTTP 402 Payment Required protocol used by
// AI-agent gateways. The agent calls a resource URL, parses the
// X-PAYMENT-REQUIRED header on a 402 response, asks the wallet to produce a
// signed Solana USDC TransferChecked transaction, then retries the request
// with the signed transaction in the X-PAYMENT header.
package x402

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

// PaymentRequirement is the schema carried in the X-PAYMENT-REQUIRED header.
type PaymentRequirement struct {
	Scheme            string         `json:"scheme"`
	Network           string         `json:"network"`
	Asset             string         `json:"asset"`
	MaxAmountRequired string         `json:"maxAmountRequired"`
	Receiver          string         `json:"receiver"`
	Extra             map[string]any `json:"extra,omitempty"`
}

// Amount parses MaxAmountRequired into an integer of asset base units.
func (p *PaymentRequirement) Amount() (uint64, error) {
	v, err := strconv.ParseUint(p.MaxAmountRequired, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("x402: invalid maxAmountRequired %q: %w", p.MaxAmountRequired, err)
	}
	return v, nil
}

// Payer is the interface the x402 client uses to produce a signed Solana
// transaction. It is satisfied by the agent's high-level pay-x402 flow.
type Payer interface {
	// Pay constructs a TransferChecked transaction to send `amount` base units
	// of `mint` to `recipient`, gets it co-signed via TSS, and returns the
	// fully serialized transaction bytes.
	Pay(ctx context.Context, mint, recipient string, amount uint64, requirement *PaymentRequirement) ([]byte, error)
}

// Client wraps http.Client with the x402 handshake.
type Client struct {
	HTTP  *http.Client
	Payer Payer
}

// New returns an x402 client using the given payer.
func New(payer Payer) *Client {
	return &Client{HTTP: http.DefaultClient, Payer: payer}
}

// Do performs an HTTP request, handling a single 402 cycle if needed.
// Returns the final response. The caller is responsible for closing Body.
func (c *Client) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if c.Payer == nil {
		return nil, errors.New("x402: nil payer")
	}

	// Capture body so we can replay it after paying.
	var bodyBytes []byte
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		bodyBytes = b
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	resp, err := c.HTTP.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusPaymentRequired {
		return resp, nil
	}
	defer resp.Body.Close()

	header := resp.Header.Get("X-PAYMENT-REQUIRED")
	if header == "" {
		return nil, errors.New("x402: 402 without X-PAYMENT-REQUIRED header")
	}
	var pr PaymentRequirement
	if err := json.Unmarshal([]byte(header), &pr); err != nil {
		return nil, fmt.Errorf("x402: bad X-PAYMENT-REQUIRED header: %w", err)
	}
	amount, err := pr.Amount()
	if err != nil {
		return nil, err
	}

	rawTx, err := c.Payer.Pay(ctx, pr.Asset, pr.Receiver, amount, &pr)
	if err != nil {
		return nil, fmt.Errorf("x402: payment failed: %w", err)
	}
	payment := map[string]any{
		"scheme":  pr.Scheme,
		"network": pr.Network,
		"tx":      base64.StdEncoding.EncodeToString(rawTx),
	}
	encPayment, _ := json.Marshal(payment)

	// Build the retry: same method/URL, body replayed, X-PAYMENT added.
	retry, err := http.NewRequestWithContext(ctx, req.Method, req.URL.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	for k, vv := range req.Header {
		for _, v := range vv {
			retry.Header.Add(k, v)
		}
	}
	retry.Header.Set("X-PAYMENT", string(encPayment))

	return c.HTTP.Do(retry)
}
