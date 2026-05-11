package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/TibaneLabs/clawdwallet/agent"
	"github.com/TibaneLabs/clawdwallet/config"
)

func init() {
	register(&command{
		name:  "daemon",
		short: "Run the agent in the foreground, accepting Spot messages",
		run:   runDaemon,
	})
}

func runDaemon(args []string) error {
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

	fmt.Println("clawdwallet daemon online")
	fmt.Println("  spot id:", a.SpotID())
	if addr := a.SolanaAddress(); addr != "" {
		fmt.Println("  address:", addr)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	fmt.Println("shutting down")
	return errors.Join((error)(nil))
}
