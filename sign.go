package main

import (
	"errors"
	"os"
)

func init() {
	if os.Getenv("CLAWDWALLET_ENABLE_RAW_SIGN") == "" {
		// Stage 1: the canonical sign flow is `clawdwallet send`, which goes
		// through the policy module's :signRequest REST and gets a server-
		// issued sid. Standalone digest signing is a developer convenience
		// only and is hidden behind an env flag for Stage 1 demos.
		return
	}
	register(&command{
		name:  "sign",
		short: "(dev) Run a TSS signing round over an arbitrary digest with an explicit sid",
		run:   runSignDev,
	})
}

func runSignDev(args []string) error {
	return errors.New("raw sign is dev-only and currently unwired; use `clawdwallet send`")
}
