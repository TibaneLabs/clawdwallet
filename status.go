package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/TibaneLabs/clawdwallet/agent"
	"github.com/TibaneLabs/clawdwallet/config"
)

func init() {
	register(&command{
		name:  "status",
		short: "Show the agent's identity, address, lock state, and balance",
		run:   runStatus,
	})
}

func runStatus(args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	a, err := agent.New(agent.Options{Config: cfg})
	if err != nil {
		return err
	}
	if err := a.Start(); err != nil {
		return err
	}
	defer a.Stop()

	out := map[string]any{
		"moniker":        cfg.Moniker,
		"spot_id":        a.SpotID(),
		"policy_id":      cfg.PolicyID,
		"owner_id":       cfg.OwnerID,
		"solana_rpc":     cfg.SolanaRPC,
		"solana_address": a.SolanaAddress(),
		"has_share":      a.Share() != nil,
		"locked":         a.Locked(),
		"wallet_id":      cfg.WalletID,
	}
	addr := a.SolanaAddress()
	if addr != "" {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if lamports, err := a.RPC().GetBalance(ctx, addr); err == nil {
			out["balance_lamports"] = lamports
			out["balance_sol"] = float64(lamports) / 1e9
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return err
	}
	_ = fmt.Println
	return nil
}
