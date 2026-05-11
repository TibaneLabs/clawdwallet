package cli

import (
	"flag"
	"fmt"

	"github.com/TibaneLabs/clawdwallet/internal/agent"
	"github.com/TibaneLabs/clawdwallet/internal/config"
)

func init() {
	register(&command{
		name:  "init",
		short: "Initialise the agent identity and write a default config",
		run:   runInit,
	})
}

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	moniker := fs.String("moniker", "agent", "human-friendly name for this agent")
	policyID := fs.String("policy", "", "Spot identity of the policy evaluator")
	ownerID := fs.String("owner", "", "Spot identity of the owner mobile app")
	solanaRPC := fs.String("rpc", "", "Solana JSON-RPC endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if *moniker != "" {
		cfg.Moniker = *moniker
	}
	if *policyID != "" {
		cfg.PolicyID = *policyID
	}
	if *ownerID != "" {
		cfg.OwnerID = *ownerID
	}
	if *solanaRPC != "" {
		cfg.SolanaRPC = *solanaRPC
	}
	if err := cfg.Save(); err != nil {
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

	dir, _ := config.Dir()
	fmt.Println("clawdwallet initialised")
	fmt.Println("  config dir:", dir)
	fmt.Println("  moniker:   ", cfg.Moniker)
	fmt.Println("  spot id:   ", a.SpotID())
	if cfg.PolicyID != "" {
		fmt.Println("  policy id: ", cfg.PolicyID)
	}
	if cfg.OwnerID != "" {
		fmt.Println("  owner id:  ", cfg.OwnerID)
	}
	fmt.Println("  solana rpc:", cfg.SolanaRPC)
	return nil
}
