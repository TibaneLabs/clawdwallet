package main

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

type command struct {
	name  string
	short string
	run   func(args []string) error
}

var commands = map[string]*command{}

func register(c *command) {
	commands[c.name] = c
}

func Run(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		printUsage()
		if len(args) == 0 {
			return errors.New("no command given")
		}
		return nil
	}

	name := args[0]
	cmd, ok := commands[name]
	if !ok {
		printUsage()
		return fmt.Errorf("unknown command %q", name)
	}
	return cmd.run(args[1:])
}

func printUsage() {
	fmt.Println("clawdwallet — TSS agent wallet for Solana")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  clawdwallet <command> [args]")
	fmt.Println()
	fmt.Println("Commands:")
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Printf("  %-12s %s\n", n, commands[n].short)
	}
}

func splitArg(s string) (k, v string, ok bool) {
	if i := strings.IndexByte(s, '='); i > 0 {
		return s[:i], s[i+1:], true
	}
	return s, "", false
}
