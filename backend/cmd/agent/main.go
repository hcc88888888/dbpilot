package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

const version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("dbpilot-agent", flag.ContinueOnError)
	flags.SetOutput(stderr)
	showVersion := flags.Bool("version", false, "print version and exit")
	config := flags.String("config", "", "path to the Agent configuration file")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}
	if strings.TrimSpace(*config) == "" {
		fmt.Fprintln(stderr, "--config is required")
		return 2
	}

	return 0
}
