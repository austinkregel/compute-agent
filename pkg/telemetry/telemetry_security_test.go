package telemetry

import (
	"context"
	"testing"

	"github.com/austinkregel/compute-agent/pkg/config"
	"github.com/austinkregel/compute-agent/pkg/logging"
)

type noopEmitter struct{}

func (noopEmitter) Emit(string, any) error { return nil }

func TestPublisher_Run_DefaultIntervalDoesNotPanic(t *testing.T) {
	// Regression test: StatsIntervalSec=0 previously caused time.NewTicker panic.
	cfg := &config.Config{StatsIntervalSec: 0}
	log, _ := logging.New(logging.Options{Level: "error"})
	pub := NewPublisher(cfg, log, noopEmitter{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = pub.Run(ctx) // should return context error, not panic
}
