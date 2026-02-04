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
	ClientID                 string `json:"clientId"`
	ServerURL                string `json:"serverUrl"`
	AuthToken                string `json:"authToken"`
	StatsIntervalSec         int    `json:"statsIntervalSec"`
	HeartbeatIntervalSec     int    `json:"heartbeatIntervalSec"`
	UpdateCheckEnabled       *bool  `json:"updateCheckEnabled"`
	UpdateCheckIntervalHours int    `json:"updateCheckIntervalHours"`
	OpenHardwareMonitorPort  int    `json:"openHardwareMonitorPort"`
	// PongTimeoutSec controls when the agent should send proactive pings if idle.
	// See requirements.md: pongTimeoutSec is 90s by default.
	PongTimeoutSec int                `json:"pongTimeoutSec"`
	Connectivity   ConnectivityConfig `json:"connectivity"`
	Admin          AdminConfig        `json:"admin"`
	Backup         BackupConfig       `json:"backup"`
	Transport      TransportConfig    `json:"transport"`
	Logging        LoggingConfig      `json:"logging"`
	Shell          ShellConfig        `json:"shell"`
	DirBrowse      DirBrowseConfig    `json:"dirBrowse"`
	Kiosk          KioskConfig        `json:"kiosk"`
	Alerts         AlertsConfig       `json:"alerts"`
}

// KioskConfig controls the optional kiosk mode (fullscreen WebView display).
type KioskConfig struct {
	// Enabled starts the kiosk subsystem. Requires a build with -tags kiosk.
	Enabled bool `json:"enabled"`
	// ListenAddr is the address for the local kiosk HTTP/WS server (default "127.0.0.1:0" for ephemeral port).
	ListenAddr string `json:"listenAddr"`
	// Fullscreen opens the WebView in fullscreen mode (default true).
	Fullscreen bool `json:"fullscreen"`
}

// AlertsConfig controls OS-level alert monitoring (kernel panics, segfaults, OOM, etc.).
type AlertsConfig struct {
	// Enabled enables OS alert collection. Default: true on Linux.
	Enabled bool `json:"enabled"`
	// ScanIntervalSec is how often to scan for new alerts. Default: 300 (5 minutes).
	ScanIntervalSec int `json:"scanIntervalSec"`
	// MaxAlerts is the maximum number of alerts to retain. Default: 50.
	MaxAlerts int `json:"maxAlerts"`
	// LookbackHours is how far back to scan on startup. Default: 24.
	LookbackHours int `json:"lookbackHours"`
	// Categories filters to specific alert categories. Empty means all.
	// Supported: kernel_panic, oom, memory, hardware, segfault, disk_io, driver, thermal, watchdog, network
	Categories []string `json:"categories"`
}

// DirBrowseConfig controls directory browsing behavior (RFC-0002).
type DirBrowseConfig struct {
	// AllowedRoots restricts which local paths may be listed.
	// If empty, directory browsing is unrestricted (subject to validation).
	AllowedRoots []string `json:"allowedRoots"`

	// SSHHostKeyPolicy controls how SSH host keys are verified for remote browsing.
	// Supported values:
	// - "known_hosts" (default): verify against ~/.ssh/known_hosts
	// - "insecure_accept_any": accept any host key (unsafe; explicit opt-in)
	SSHHostKeyPolicy string `json:"sshHostKeyPolicy"`

	// SMBProfiles stores credentials for SMB browsing. Requests reference a profile by name.
	SMBProfiles map[string]SMBProfile `json:"smbProfiles"`
}

type SMBProfile struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Domain   string `json:"domain"`
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

	// MaxClockSkewSec is the maximum allowed clock difference (in seconds)
	// between server and agent for signed command verification.
	// Default: 300 (5 minutes).
	// Note: Command signing is mandatory and cannot be disabled.
	MaxClockSkewSec int `json:"maxClockSkewSec"`
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

	// IdleTimeoutSec closes interactive shell sessions after this many seconds without
	// any activity (input/output/resize). Defaults to 60.
	IdleTimeoutSec int `json:"idleTimeoutSec"`
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
	// Updates: enabled by default, run every 12 hours.
	if c.UpdateCheckIntervalHours <= 0 {
		c.UpdateCheckIntervalHours = 12
	}
	if c.UpdateCheckEnabled == nil {
		v := true
		c.UpdateCheckEnabled = &v
	}
	if c.OpenHardwareMonitorPort <= 0 {
		c.OpenHardwareMonitorPort = 8085
	}
	if c.PongTimeoutSec <= 0 {
		c.PongTimeoutSec = 90
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
	if c.Transport.MaxClockSkewSec <= 0 {
		c.Transport.MaxClockSkewSec = 300 // 5 minutes
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
	if c.Shell.IdleTimeoutSec <= 0 {
		c.Shell.IdleTimeoutSec = 60
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

	if strings.TrimSpace(c.DirBrowse.SSHHostKeyPolicy) == "" {
		c.DirBrowse.SSHHostKeyPolicy = "known_hosts"
	}
	if c.DirBrowse.SMBProfiles == nil {
		c.DirBrowse.SMBProfiles = map[string]SMBProfile{}
	}

	// Kiosk defaults
	if c.Kiosk.ListenAddr == "" {
		c.Kiosk.ListenAddr = "127.0.0.1:0"
	}
	// Fullscreen defaults to true when kiosk is enabled
	// (Go zero-value is false, so we only set it if config explicitly doesn't specify)

	// Alerts defaults: enabled by default on Linux
	if runtime.GOOS == "linux" && !c.Alerts.Enabled {
		// Check if this is a zero-value (not explicitly set to false)
		// We enable by default on Linux; users can set enabled: false to disable
		c.Alerts.Enabled = true
	}
	if c.Alerts.ScanIntervalSec <= 0 {
		c.Alerts.ScanIntervalSec = 300 // 5 minutes
	}
	if c.Alerts.MaxAlerts <= 0 {
		c.Alerts.MaxAlerts = 50
	}
	if c.Alerts.LookbackHours <= 0 {
		c.Alerts.LookbackHours = 24
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
	if v := os.Getenv("UPDATE_CHECK_INTERVAL_HOURS"); v != "" {
		if parsed, err := parseInt(v); err == nil {
			c.UpdateCheckIntervalHours = parsed
		}
	}
	if v := os.Getenv("UPDATE_CHECK_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			c.UpdateCheckEnabled = &b
		}
	}
	if v := os.Getenv("PONG_TIMEOUT_SEC"); v != "" {
		if parsed, err := parseInt(v); err == nil {
			c.PongTimeoutSec = parsed
		}
	}
	if v := os.Getenv("OHM_PORT"); v != "" {
		if parsed, err := parseInt(v); err == nil {
			c.OpenHardwareMonitorPort = parsed
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

func (c *Config) UpdateChecksEnabled() bool {
	if c == nil || c.UpdateCheckEnabled == nil {
		return true
	}
	return *c.UpdateCheckEnabled
}

func parseInt(val string) (int, error) {
	return strconv.Atoi(strings.TrimSpace(val))
}
