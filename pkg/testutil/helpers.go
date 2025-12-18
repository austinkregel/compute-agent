package testutil

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/austinkregel/compute-agent/pkg/config"
)

// TempConfig creates a temporary config file with the given config data.
// Returns the file path and a cleanup function.
func TempConfig(t interface{ Cleanup(func()) }, cfg *config.Config) (string, func()) {
	tmpdir := t.(interface{ TempDir() string }).TempDir()
	path := filepath.Join(tmpdir, "agent-config.json")

	data, err := json.Marshal(cfg)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		panic(err)
	}

	return path, func() {
		_ = os.Remove(path)
	}
}

// BuildConfig creates a config with sensible defaults for testing.
func BuildConfig() *config.Config {
	return &config.Config{
		ClientID:             "test-client",
		ServerURL:            "https://test.example.com",
		AuthToken:            "test-token",
		StatsIntervalSec:     60,
		HeartbeatIntervalSec: 20,
		Admin: config.AdminConfig{
			EnableShell:       true,
			Allowed:           []string{"echo", "uptime"},
			MaxConcurrent:     2,
			DefaultTimeoutSec: 30,
		},
		Transport: config.TransportConfig{
			SkipTLSVerify: false,
			Path:          "/socket.io",
		},
		Logging: config.LoggingConfig{
			FilePath: "",
			Level:    "info",
		},
		Shell: config.ShellConfig{
			Command: "/bin/bash",
			Args:    []string{"-l"},
		},
	}
}
