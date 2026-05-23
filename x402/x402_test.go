package x402

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAmount(t *testing.T) {
	p := &PaymentRequirement{MaxAmountRequired: "1000000"}
	v, err := p.Amount()
	if err != nil {
		t.Fatalf("Amount: %s", err)
	}
	if v != 1_000_000 {
		t.Errorf("Amount: want 1000000 got %d", v)
	}

	bad := &PaymentRequirement{MaxAmountRequired: "not-a-number"}
	if _, err := bad.Amount(); err == nil {
		t.Errorf("Amount should reject non-numeric input")
	}
}

func TestDoNilPayer(t *testing.T) {
	c := &Client{HTTP: http.DefaultClient}
	req, _ := http.NewRequest(http.MethodGet, "http://example.invalid", nil)
	if _, err := c.Do(context.Background(), req); err == nil {
		t.Errorf("Do should error when Payer is nil")
	}
}

func TestDoNon402Passthrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	c := New(&fakePayer{})
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := c.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: want 200 got %d", resp.StatusCode)
	}
}

func TestDo402MissingHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPaymentRequired)
	}))
	defer srv.Close()

	c := New(&fakePayer{})
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	if _, err := c.Do(context.Background(), req); err == nil {
		t.Errorf("Do should error on a 402 without X-PAYMENT-REQUIRED")
	}
}

func TestDo402PayAndRetry(t *testing.T) {
	var sawPayment string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if pay := r.Header.Get("X-PAYMENT"); pay != "" {
			sawPayment = pay
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "paid")
			return
		}
		pr := PaymentRequirement{
			Scheme:            "exact",
			Network:           "solana",
			Asset:             "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
			MaxAmountRequired: "1000",
			Receiver:          "RcvR1111111111111111111111111111111111111111",
		}
		hdr, _ := json.Marshal(pr)
		w.Header().Set("X-PAYMENT-REQUIRED", string(hdr))
		w.WriteHeader(http.StatusPaymentRequired)
	}))
	defer srv.Close()

	fp := &fakePayer{raw: []byte{0xde, 0xad, 0xbe, 0xef}}
	c := New(fp)
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := c.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("retry status: want 200 got %d", resp.StatusCode)
	}

	// Payer must have been called with the parsed requirement.
	if fp.gotAmount != 1000 {
		t.Errorf("payer amount: want 1000 got %d", fp.gotAmount)
	}
	if fp.gotRecipient != "RcvR1111111111111111111111111111111111111111" {
		t.Errorf("payer recipient: got %q", fp.gotRecipient)
	}

	// The X-PAYMENT header on the retry must carry the base64 tx the payer produced.
	if sawPayment == "" {
		t.Fatalf("retry did not carry X-PAYMENT")
	}
	var pay struct {
		Scheme  string `json:"scheme"`
		Network string `json:"network"`
		Tx      string `json:"tx"`
	}
	if err := json.Unmarshal([]byte(sawPayment), &pay); err != nil {
		t.Fatalf("X-PAYMENT json: %s", err)
	}
	wantTx := base64.StdEncoding.EncodeToString(fp.raw)
	if pay.Tx != wantTx {
		t.Errorf("X-PAYMENT tx: want %q got %q", wantTx, pay.Tx)
	}
	if pay.Scheme != "exact" || pay.Network != "solana" {
		t.Errorf("X-PAYMENT scheme/network: %+v", pay)
	}
}

// fakePayer records what it was asked to pay and returns canned tx bytes.
type fakePayer struct {
	raw          []byte
	gotMint      string
	gotRecipient string
	gotAmount    uint64
}

func (f *fakePayer) Pay(ctx context.Context, mint, recipient string, amount uint64, req *PaymentRequirement) ([]byte, error) {
	f.gotMint = mint
	f.gotRecipient = recipient
	f.gotAmount = amount
	return f.raw, nil
}
