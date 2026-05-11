package main

import (
	"fmt"
	"os"

	"github.com/TibaneLabs/clawdwallet/internal/cli"
)

func main() {
	if err := cli.Run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "clawdwallet:", err)
		os.Exit(1)
	}
}
