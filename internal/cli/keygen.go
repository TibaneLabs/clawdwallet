package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/TibaneLabs/clawdwallet/internal/agent"
	"github.com/TibaneLabs/clawdwallet/internal/config"
)

func init() {
	register(&command{
		name:  "keygen",
		short: "Initiate (or join) a 3-party EdDSA TSS keygen ceremony",
		run:   runKeygen,
	})
}

func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	policy := fs.String("policy", "", "Spot id of the policy evaluator (overrides config)")
	owner := fs.String("owner", "", "Spot id of the owner mobile app (overrides config)")
	threshold := fs.Int("threshold", 1, "t in t-of-n (default 1 = 2-of-3)")
	join := fs.Bool("join", false, "wait for an inbound init message instead of initiating")
	timeout := fs.Duration("timeout", 5*time.Minute, "maximum time to wait for the ceremony")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if *policy != "" {
		cfg.PolicyID = *policy
	}
	if *owner != "" {
		cfg.OwnerID = *owner
	}
	if cfg.PolicyID == "" || cfg.OwnerID == "" {
		return errors.New("keygen requires --policy and --owner (or values in config)")
	}
	_ = cfg.Save()

	a, err := agent.New(agent.Options{Config: cfg})
	if err != nil {
		return err
	}
	if err := a.Start(); err != nil {
		return err
	}
	defer a.Stop()

	peers := []agent.PeerSpec{
		{SpotID: a.SpotID(), Moniker: cfg.Moniker},
		{SpotID: cfg.PolicyID, Moniker: "policy"},
		{SpotID: cfg.OwnerID, Moniker: "owner"},
	}

	if *join {
		fmt.Println("waiting for keygen init message; press Ctrl-C to abort")
		fmt.Println("  this agent:", a.SpotID())
		fmt.Println("  expected peers:", strings.Join([]string{cfg.PolicyID, cfg.OwnerID}, ", "))
		// Block until the share lands on disk, or timeout.
		deadline := time.Now().Add(*timeout)
		for time.Now().Before(deadline) {
			if sh := a.Share(); sh != nil {
				fmt.Println("share received, wallet:", a.SolanaAddress())
				return nil
			}
			time.Sleep(500 * time.Millisecond)
		}
		return fmt.Errorf("timed out waiting for keygen init")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	share, err := a.Keygen(ctx, peers, *threshold)
	if err != nil {
		return err
	}
	fmt.Println("keygen complete")
	fmt.Println("  wallet id: ", share.WalletID)
	fmt.Println("  address:   ", a.SolanaAddress())
	return nil
}
