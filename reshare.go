package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/TibaneLabs/clawdwallet/agent"
	"github.com/TibaneLabs/clawdwallet/config"
)

func init() {
	register(&command{
		name:  "reshare",
		short: "Run a reshare ceremony to rotate share holders (preserves the address)",
		run:   runReshare,
	})
}

func runReshare(args []string) error {
	fs := flag.NewFlagSet("reshare", flag.ContinueOnError)
	newPeers := fs.String("new-peers", "", "comma-separated Spot IDs of the new committee")
	newThreshold := fs.Int("new-threshold", 1, "t in t-of-n for the new committee")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *newPeers == "" {
		return errors.New("reshare: --new-peers is required")
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

	sh := a.Share()
	if sh == nil {
		return errors.New("no share on disk; nothing to reshare")
	}
	oldPeers := make([]agent.PeerSpec, len(sh.PeerSpotIDs))
	for i, id := range sh.PeerSpotIDs {
		moniker := "peer"
		if id == a.SpotID() {
			moniker = cfg.Moniker
		}
		oldPeers[i] = agent.PeerSpec{SpotID: id, Moniker: moniker}
	}

	var nps []agent.PeerSpec
	for _, id := range strings.Split(*newPeers, ",") {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		nps = append(nps, agent.PeerSpec{SpotID: id})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := a.Reshare(ctx, oldPeers, nps, sh.Threshold, *newThreshold); err != nil {
		return err
	}
	fmt.Println("reshare complete; address unchanged:", a.SolanaAddress())
	return nil
}
