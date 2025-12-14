package cron

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"

	"github.com/austinkregel/compute-agent/pkg/config"
	"github.com/austinkregel/compute-agent/pkg/logging"
)

// Bridge proxies cron get/set requests through admin_run.
type Bridge struct {
	cfg *config.Config
	log *logging.Logger
}

// NewBridge constructs a cron bridge.
func NewBridge(cfg *config.Config, log *logging.Logger) *Bridge {
	return &Bridge{cfg: cfg, log: log}
}

// Fetch returns the current user's crontab text (equivalent to `crontab -l`).
func (b *Bridge) Fetch(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "crontab", "-l")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Preserve command output for callers (parity with shelling out).
		return "", fmt.Errorf("crontab -l failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// Apply installs the given crontab text (equivalent to `crontab -` with stdin).
func (b *Bridge) Apply(ctx context.Context, cronText string) error {
	cmd := exec.CommandContext(ctx, "crontab", "-")
	cmd.Stdin = bytes.NewBufferString(cronText)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("crontab - failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ApplyBase64 decodes a base64-encoded crontab and installs it.
func (b *Bridge) ApplyBase64(ctx context.Context, b64 string) error {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return fmt.Errorf("decode base64 cron: %w", err)
	}
	return b.Apply(ctx, string(decoded))
}

