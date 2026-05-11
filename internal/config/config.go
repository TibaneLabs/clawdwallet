package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Config holds persistent agent configuration. It does NOT include secrets;
// secrets live in the encrypted store alongside it.
type Config struct {
	// Moniker is a human-friendly name for this agent.
	Moniker string `json:"moniker"`

	// Relays is an optional list of Spot relay hostnames. Empty = use spotlib defaults.
	Relays []string `json:"relays,omitempty"`

	// PolicyID is the Spot identity of the policy evaluator (k.<base64>).
	PolicyID string `json:"policy_id,omitempty"`

	// OwnerID is the Spot identity of the owner's mobile app (k.<base64>).
	OwnerID string `json:"owner_id,omitempty"`

	// SolanaRPC is the Solana JSON-RPC endpoint.
	SolanaRPC string `json:"solana_rpc,omitempty"`

	// USDCMint is the USDC mint address on the configured network.
	USDCMint string `json:"usdc_mint,omitempty"`

	// WalletID identifies the active wallet (TSS keygen session id derivative).
	// Empty until keygen has completed.
	WalletID string `json:"wallet_id,omitempty"`

	// SolanaAddress is the on-chain address of the wallet, derived from the
	// EdDSA aggregate public key. Set when keygen completes.
	SolanaAddress string `json:"solana_address,omitempty"`
}

// Defaults returns a Config with reasonable mainnet/USDC defaults.
func Defaults() *Config {
	return &Config{
		SolanaRPC: "https://api.mainnet-beta.solana.com",
		USDCMint:  "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
	}
}

// Dir returns the configuration directory, creating it if needed.
func Dir() (string, error) {
	if d := os.Getenv("CLAWDWALLET_HOME"); d != "" {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return "", err
		}
		return d, nil
	}
	home, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	d := filepath.Join(home, "clawdwallet")
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", err
	}
	return d, nil
}

func path() (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "config.json"), nil
}

// Load reads the configuration file. Returns Defaults() if it doesn't exist.
func Load() (*Config, error) {
	p, err := path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return Defaults(), nil
	}
	if err != nil {
		return nil, err
	}
	c := Defaults()
	if err := json.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return c, nil
}

// Save writes the configuration atomically.
func (c *Config) Save() error {
	p, err := path()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
