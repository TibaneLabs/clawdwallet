package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/TibaneLabs/clawdwallet/agent"
	"github.com/TibaneLabs/clawdwallet/config"
	"github.com/TibaneLabs/clawdwallet/mcp"
)

func init() {
	if os.Getenv("CLAWDWALLET_ENABLE_MCP") == "" {
		// Stage 2: MCP server is deferred so the Stage 1 demo CLI surface
		// stays minimal and predictable.
		return
	}
	register(&command{
		name:  "mcp",
		short: "(Stage 2) Run an MCP server on stdio (JSON-RPC 2.0)",
		run:   runMCP,
	})
}

func runMCP(args []string) error {
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

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	srv := mcp.New(a)
	return srv.Serve(ctx)
}
