package cli

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/TibaneLabs/clawdwallet/internal/agent"
	"github.com/TibaneLabs/clawdwallet/internal/config"
)

func init() {
	register(&command{
		name:  "balance",
		short: "Print the SOL balance (and optionally an SPL balance) for the wallet",
		run:   runBalance,
	})
}

func runBalance(args []string) error {
	fs := flag.NewFlagSet("balance", flag.ContinueOnError)
	mint := fs.String("mint", "", "SPL mint address; if given, return that ATA balance")
	if err := fs.Parse(args); err != nil {
		return err
	}
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
	addr := a.SolanaAddress()
	if addr == "" {
		return fmt.Errorf("no wallet address (run keygen first)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	lamports, err := a.RPC().GetBalance(ctx, addr)
	if err != nil {
		return err
	}
	fmt.Printf("SOL: %.9f (%d lamports)\n", float64(lamports)/1e9, lamports)
	if *mint != "" {
		// Derive the agent's ATA for the mint and query its balance.
		fmt.Println("(SPL balance lookup not yet wired through the ATA helper here; use the RPC client directly)")
	}
	return nil
}
