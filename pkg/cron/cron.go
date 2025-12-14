package cron

import (
	"context"

	"github.com/austinkregel/compute-agent/pkg/config"
	"github.com/austinkregel/compute-agent/pkg/logging"
)

// Bridge proxies cron get/set requests through admin_run.
type Bridge struct {
	cfg *config.Config
	log *logging.Logger
}

// NewBridge constructs a placeholder cron bridge.
func NewBridge(cfg *config.Config, log *logging.Logger) *Bridge {
	return &Bridge{cfg: cfg, log: log}
}

// Fetch forwards a crontab read (stub).
func (b *Bridge) Fetch(ctx context.Context) (string, error) {
	b.log.Info("cron fetch requested (stub)")
	return "", nil
}

// Apply sets the remote crontab (stub).
func (b *Bridge) Apply(ctx context.Context, cronText string) error {
	b.log.Info("cron apply requested (stub)")
	return nil
}
