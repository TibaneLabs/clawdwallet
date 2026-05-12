package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/TibaneLabs/clawdwallet/agent"
	"github.com/TibaneLabs/clawdwallet/config"
)

func init() {
	register(&command{
		name:  "keygen",
		short: "Wait for a server-issued walletsign keygen init and run the ceremony",
		run:   runKeygen,
	})
}

// runKeygen is now JOIN-only per Stage 1 Decision 1. Mobile drives the
// `Crypto/ClawdWallet:create` flow; phplatform tells this agent (via Spot
// inbound `walletsign/<sid>/init`) to join. This command just blocks until a
// share lands on disk.
func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	timeout := fs.Duration("timeout", 5*time.Minute, "how long to wait for the keygen init message")
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

	fmt.Println("waiting for keygen init message on /walletsign/<sid>/init")
	fmt.Println("  this agent:", a.SpotID())
	if cfg.PolicyID != "" {
		fmt.Println("  policy id: ", cfg.PolicyID)
	}
	deadline := time.Now().Add(*timeout)
	for time.Now().Before(deadline) {
		if sh := a.Share(); sh != nil {
			fmt.Println("share received")
			fmt.Println("  wallet id:", sh.WalletID)
			fmt.Println("  address:  ", a.SolanaAddress())
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for keygen init")
}
