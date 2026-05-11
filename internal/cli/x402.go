package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/TibaneLabs/clawdwallet/internal/agent"
	"github.com/TibaneLabs/clawdwallet/internal/config"
	"github.com/TibaneLabs/clawdwallet/internal/x402"
)

func init() {
	register(&command{
		name:  "x402",
		short: "Perform an HTTP request that may require x402 payment",
		run:   runX402,
	})
}

func runX402(args []string) error {
	fs := flag.NewFlagSet("x402", flag.ContinueOnError)
	method := fs.String("method", "GET", "HTTP method")
	bodyFile := fs.String("body", "", "request body file (- for stdin)")
	header := fs.String("header", "", "additional headers as 'K: V; K: V'")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("x402: URL required")
	}
	url := fs.Arg(0)

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

	var bodyReader io.Reader
	if *bodyFile == "-" {
		bodyReader = os.Stdin
	} else if *bodyFile != "" {
		f, err := os.Open(*bodyFile)
		if err != nil {
			return err
		}
		defer f.Close()
		bodyReader = f
	}

	req, err := http.NewRequest(*method, url, bodyReader)
	if err != nil {
		return err
	}
	if *header != "" {
		for _, h := range strings.Split(*header, ";") {
			h = strings.TrimSpace(h)
			if k, v, ok := strings.Cut(h, ":"); ok {
				req.Header.Set(strings.TrimSpace(k), strings.TrimSpace(v))
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	client := x402.New(&agent.X402Payer{A: a})
	resp, err := client.Do(ctx, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	fmt.Fprintf(os.Stderr, "%s %s -> %d\n", *method, url, resp.StatusCode)
	_, err = io.Copy(os.Stdout, resp.Body)
	return err
}
