package main

import (
	"errors"
	"os"
)

func init() {
	if os.Getenv("CLAWDWALLET_ENABLE_RESHARE") == "" {
		// Stage 2 functionality. Disabled by default in the Stage 1 build so
		// the demo CLI path is deterministic.
		return
	}
	register(&command{
		name:  "reshare",
		short: "(Stage 2) Run a reshare ceremony to rotate share holders",
		run:   runReshare,
	})
}

func runReshare(args []string) error {
	return errors.New("reshare is Stage 2 — not enabled in this build")
}
