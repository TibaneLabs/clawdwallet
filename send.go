package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/TibaneLabs/clawdwallet/agent"
	"github.com/TibaneLabs/clawdwallet/config"
	"github.com/TibaneLabs/clawdwallet/policy"
)

func init() {
	register(&command{
		name:  "send",
		short: "Build a transfer, request policy approval, sign via TSS, submit",
		run:   runSend,
	})
}

func runSend(args []string) error {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	to := fs.String("to", "", "destination Solana address (base58)")
	amount := fs.Uint64("amount", 0, "amount in base units (lamports / token base units)")
	mint := fs.String("mint", "", "SPL token mint (empty = native SOL)")
	decimals := fs.Uint("decimals", 0, "decimals for SPL (defaults to RPC lookup)")
	reason := fs.String("reason", "", "human-readable reason for the policy evaluator")
	skill := fs.String("skill", "", "skill name invoked by this transfer")
	desc := fs.String("desc", "", "description of the transfer")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *to == "" || *amount == 0 {
		return errors.New("send: --to and --amount are required")
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

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	d := uint8(*decimals)
	if *mint != "" && d == 0 {
		v, err := a.RPC().GetTokenSupplyDecimals(ctx, *mint)
		if err != nil {
			return fmt.Errorf("lookup decimals: %w", err)
		}
		d = v
	}

	sig, err := a.BuildAndPay(ctx, agent.TransferOptions{
		To:       *to,
		Mint:     *mint,
		Amount:   *amount,
		Decimals: d,
		Intent: policy.Intent{
			Description: *desc,
			Skill:       *skill,
			Reason:      *reason,
		},
	})
	if err != nil {
		return err
	}
	fmt.Println("submitted:", sig)
	return nil
}
