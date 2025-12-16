package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/austinkregel/compute-agent/internal/app"
	"github.com/austinkregel/compute-agent/pkg/config"
	"github.com/austinkregel/compute-agent/pkg/logging"
	"github.com/austinkregel/compute-agent/pkg/version"
)

type agentRunner interface {
	Run(ctx context.Context) error
}

// newAgent is an indirection to make cmd/agent testable.
var newAgent = func(cfg *config.Config, log *logging.Logger) (agentRunner, error) {
	return app.New(cfg, log)
}

// printVersion prints the version information and exits.
// Extracted for testability.
func printVersion() {
	fmt.Printf("backup-agent %s (%s) built=%s\n", version.Version, version.Commit, version.BuildDate)
}

// handleVersionFlag processes the version flag and returns true if the program should exit.
// Extracted for testability to ensure the return statement is covered.
func handleVersionFlag(showVersion bool) bool {
	if showVersion {
		printVersion()
		return true
	}
	return false
}

func main() {
	var cfgPath string
	var showVersion bool
	flag.StringVar(&cfgPath, "config", config.DefaultPath(), "Path to agent-config.json")
	flag.BoolVar(&showVersion, "version", false, "Print version and exit")
	flag.Parse()

	if handleVersionFlag(showVersion) {
		return
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	log, err := logging.New(logging.Options{
		File:  cfg.Logging.FilePath,
		Level: cfg.Logging.Level,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to init logger: %v\n", err)
		os.Exit(1)
	}
	defer log.Sync() // best effort

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	agent, err := newAgent(cfg, log)
	if err != nil {
		log.Error("startup failed", "error", err)
		os.Exit(1)
	}

	if err := agent.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("agent terminated with error", "error", err)
		os.Exit(1)
	}
}
