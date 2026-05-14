package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mdp/qrterminal/v3"

	"github.com/TibaneLabs/clawdwallet/agent"
	"github.com/TibaneLabs/clawdwallet/config"
)

func init() {
	register(&command{
		name:  "pair",
		short: "Print a one-shot tibane:// URL to pair this agent with the mobile app",
		run:   runPair,
	})
}

// runPair mints a single-use pairing token and prints the deep-link URL the
// mobile app expects. The agent stays online to serve the inbound pair
// request; the command exits on first successful pair, after the 5-minute
// token TTL, or when interrupted.
func runPair(args []string) error {
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

	token, done, err := a.Pairing().Issue()
	if err != nil {
		return err
	}
	url := agent.PairingURL(a.SpotID(), token)

	fmt.Println("Scan this QR or open the URL on your phone to pair the mobile app with this agent:")
	fmt.Println()
	qrterminal.GenerateHalfBlock(url, qrterminal.L, os.Stdout)
	fmt.Println()
	fmt.Println("  " + url)
	fmt.Println()
	fmt.Println("The token is single-use and expires in 5 minutes.")
	fmt.Println("Waiting for pair request — Ctrl-C to cancel.")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	timer := time.NewTimer(5 * time.Minute)
	defer timer.Stop()

	select {
	case c := <-done:
		fmt.Println()
		fmt.Println("paired:")
		fmt.Println("  mobile spot id:", c.MobileSpotID)
		fmt.Println("  at:            ", c.At.UTC().Format(time.RFC3339))
		return nil
	case <-timer.C:
		fmt.Println()
		return fmt.Errorf("pairing token expired; run `clawdwallet pair` again")
	case <-sigCh:
		fmt.Println()
		fmt.Println("cancelled")
		return nil
	}
}
