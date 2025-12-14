package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Config captures all runtime knobs for the Go agent.
type Config struct {
	ClientID             string             `json:"clientId"`
	ServerURL            string             `json:"serverUrl"`
	AuthToken            string             `json:"authToken"`
	StatsIntervalSec     int                `json:"statsIntervalSec"`
	HeartbeatIntervalSec int                `json:"heartbeatIntervalSec"`
	Connectivity         ConnectivityConfig `json:"connectivity"`
	Admin                AdminConfig        `json:"admin"`
	Backup               BackupConfig       `json:"backup"`
	Transport            TransportConfig    `json:"transport"`
	Logging              LoggingConfig      `json:"logging"`
	Shell                ShellConfig        `json:"shell"`
}

// ConnectivityConfig governs liveness probes (DNS + TCP).
type ConnectivityConfig struct {
	DNSTestHost string `json:"dnsTestHost"`
	TCPTestHost string `json:"tcpTestHost"`
	TCPTestPort int    `json:"tcpTestPort"`
}

// AdminConfig validates remote command guardrails.
type AdminConfig struct {
	EnableShell bool     `json:"enableShell"`
	Allowed     []string `json:"allowedCommands"`

	// AllowedCwds restricts server-provided working directories for admin_run.
	// If empty, any request specifying a Cwd will be rejected.
	AllowedCwds []string `json:"allowedCwds"`

	MaxConcurrent      int    `json:"maxConcurrent"`
	DefaultTimeoutSec  int    `json:"defaultTimeoutSec"`
	RequireToken       bool   `json:"requireToken"`
	CommandToken       string `json:"commandToken"`
	RateLimitMax       int    `json:"rateLimitMax"`
	RateLimitWindowSec int    `json:"rateLimitWindowSec"`
}

// BackupConfig constrains server-provided backup requests.
type BackupConfig struct {
	// AllowedSourceRoots restricts source directories that may be walked.
	// If empty, backups may read from any local path.
	AllowedSourceRoots []string `json:"allowedSourceRoots"`

	// AllowedDestRoots restricts destination roots that files may be written under.
	// If empty, backups may write under any local path.
	AllowedDestRoots []string `json:"allowedDestRoots"`
}

// TransportConfig controls TLS and socket path options.
type TransportConfig struct {
	SkipTLSVerify bool   `json:"skipTlsVerify"`
	Path          string `json:"path"`
}

// LoggingConfig describes log destination and verbosity.
type LoggingConfig struct {
	FilePath string `json:"file"`
	Level    string `json:"level"`
}

// ShellConfig customizes the interactive shell command.
type ShellConfig struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

// DefaultPath returns the config path honoring CLIENT_CONFIG_PATH.
func DefaultPath() string {
	if override := os.Getenv("CLIENT_CONFIG_PATH"); override != "" {
		return override
	}
	return filepath.Join(".", "agent-config.json")
}

// Load reads the config file, applies env overrides, defaults, and validation.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyEnvOverrides()
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate ensures the minimum viable fields are set.
func (c *Config) Validate() error {
	switch {
	case strings.TrimSpace(c.ClientID) == "":
		return errors.New("clientId is required")
	case strings.TrimSpace(c.ServerURL) == "":
		return errors.New("serverUrl is required")
	case strings.TrimSpace(c.AuthToken) == "":
		return errors.New("authToken is required")
	}
	return nil
}

func (c *Config) applyDefaults() {
	if c.StatsIntervalSec <= 0 {
		c.StatsIntervalSec = 60
	}
	if c.HeartbeatIntervalSec <= 0 {
		c.HeartbeatIntervalSec = 20
	}
	if c.Connectivity.TCPTestPort == 0 {
		c.Connectivity.TCPTestPort = 53
	}
	if c.Admin.MaxConcurrent <= 0 {
		c.Admin.MaxConcurrent = 1
	}
	if c.Admin.DefaultTimeoutSec <= 0 {
		c.Admin.DefaultTimeoutSec = 30
	}
	if c.Admin.RateLimitMax > 0 && c.Admin.RateLimitWindowSec <= 0 {
		c.Admin.RateLimitWindowSec = 60
	}
	if c.Transport.Path == "" {
		c.Transport.Path = "/socket.io"
	}
	if c.Shell.Command == "" {
		if runtime.GOOS == "windows" {
			c.Shell.Command = "cmd.exe"
			c.Shell.Args = []string{"/Q"}
		} else {
			c.Shell.Command = "/bin/bash"
			if len(c.Shell.Args) == 0 {
				c.Shell.Args = []string{"-l"}
			}
		}
	}
	if c.Logging.FilePath == "" {
		if env := os.Getenv("LOG_FILE"); env != "" {
			c.Logging.FilePath = env
		} else {
			c.Logging.FilePath = filepath.Join(".", "agent.log")
		}
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
}

func (c *Config) applyEnvOverrides() {
	if v := os.Getenv("CLIENT_ID"); v != "" {
		c.ClientID = v
	}
	if v := os.Getenv("SERVER_URL"); v != "" {
		c.ServerURL = v
	}
	if v := os.Getenv("AUTH_TOKEN"); v != "" {
		c.AuthToken = v
	}
	if v := os.Getenv("STATS_INTERVAL_SEC"); v != "" {
		if parsed, err := parseInt(v); err == nil {
			c.StatsIntervalSec = parsed
		}
	}
	if v := os.Getenv("HEARTBEAT_INTERVAL_SEC"); v != "" {
		if parsed, err := parseInt(v); err == nil {
			c.HeartbeatIntervalSec = parsed
		}
	}
	if v := os.Getenv("ADMIN_ALLOWED_COMMANDS"); v != "" {
		c.Admin.Allowed = strings.Split(v, ",")
	}
	if v := os.Getenv("AGENT_SKIP_TLS_VERIFY"); v != "" {
		if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			c.Transport.SkipTLSVerify = b
		}
	}
}

func parseInt(val string) (int, error) {
	return strconv.Atoi(strings.TrimSpace(val))
}
