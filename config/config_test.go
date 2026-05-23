package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaults(t *testing.T) {
	d := Defaults()
	if d.SolanaRPC == "" {
		t.Errorf("Defaults should set SolanaRPC")
	}
	if d.USDCMint == "" {
		t.Errorf("Defaults should set USDCMint")
	}
}

func TestDirUsesEnv(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "cfgdir")
	t.Setenv("CLAWDWALLET_HOME", tmp)
	got, err := Dir()
	if err != nil {
		t.Fatalf("Dir: %s", err)
	}
	if got != tmp {
		t.Errorf("Dir: want %q got %q", tmp, got)
	}
	// Dir must have created the directory.
	if fi, err := os.Stat(tmp); err != nil || !fi.IsDir() {
		t.Errorf("Dir should create the directory: %v", err)
	}
}

func TestLoadMissingReturnsDefaults(t *testing.T) {
	t.Setenv("CLAWDWALLET_HOME", t.TempDir())
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %s", err)
	}
	if c.SolanaRPC != Defaults().SolanaRPC {
		t.Errorf("Load on empty dir should return defaults, got SolanaRPC=%q", c.SolanaRPC)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	t.Setenv("CLAWDWALLET_HOME", t.TempDir())

	orig := Defaults()
	orig.Moniker = "test-agent"
	orig.WalletID = "crws-abc"
	orig.SolanaAddress = "SoLAddr1111111111111111111111111111111111111"
	orig.Relays = []string{"relay.example"}
	if err := orig.Save(); err != nil {
		t.Fatalf("Save: %s", err)
	}

	got, err := Load()
	if err != nil {
		t.Fatalf("Load: %s", err)
	}
	if got.Moniker != "test-agent" {
		t.Errorf("Moniker: got %q", got.Moniker)
	}
	if got.WalletID != "crws-abc" {
		t.Errorf("WalletID: got %q", got.WalletID)
	}
	if got.SolanaAddress != orig.SolanaAddress {
		t.Errorf("SolanaAddress: got %q", got.SolanaAddress)
	}
	if len(got.Relays) != 1 || got.Relays[0] != "relay.example" {
		t.Errorf("Relays: got %v", got.Relays)
	}
	// Defaults preserved for unspecified fields.
	if got.USDCMint != Defaults().USDCMint {
		t.Errorf("USDCMint default not preserved: %q", got.USDCMint)
	}
}

func TestLoadRejectsBadJSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CLAWDWALLET_HOME", dir)
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Errorf("Load should error on malformed JSON")
	}
}
