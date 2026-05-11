package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
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
		name:  "sign",
		short: "Run a TSS signing round over an arbitrary digest (32 bytes hex or base64)",
		run:   runSign,
	})
}

func runSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	enc := fs.String("enc", "hex", "encoding of digest: hex | base64")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("sign: digest argument required")
	}
	in := fs.Arg(0)
	var digest []byte
	var err error
	switch strings.ToLower(*enc) {
	case "hex":
		digest, err = hex.DecodeString(in)
	case "base64":
		digest, err = base64.StdEncoding.DecodeString(in)
	default:
		return fmt.Errorf("unknown encoding %q", *enc)
	}
	if err != nil {
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

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	sig, err := a.SignDigest(ctx, digest, nil)
	if err != nil {
		return err
	}
	fmt.Println("hex:    ", hex.EncodeToString(sig))
	fmt.Println("base64: ", base64.StdEncoding.EncodeToString(sig))
	return nil
}
