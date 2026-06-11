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
	Variant        VariantConfig      `json:"variant"`
	Docker         DockerConfig       `json:"docker"`
	DirectMode     DirectModeConfig   `json:"directMode"`
}

// DirectModeConfig configures the optional inbound listener that lets a trusted
// IDE client (the rebase desktop app) connect to the agent directly over a
// private network, bypassing the control plane. See docs/DIRECT_MODE.md.
//
// SAFETY: this is the agent's only inbound, network-facing surface. It is
// disabled by default and refuses to start unless TLS, OIDC, allowed roots, and
// an explicit bind address are all configured. It exposes ONLY file and shell
// operations (a strict subset of the control-plane command set) and confines
// every path to AllowedRoots.
type DirectModeConfig struct {
	// Enabled starts the inbound WSS listener. Default false.
	Enabled bool `json:"enabled"`
	// ListenAddr is the bind address, e.g. "100.64.0.5:7420". Bind to the VPN
	// interface; there is intentionally no default (refuses to start if empty).
	ListenAddr string `json:"listenAddr"`
	// TLSCertFile / TLSKeyFile are required — the listener never serves plaintext.
	TLSCertFile string `json:"tlsCertFile"`
	TLSKeyFile  string `json:"tlsKeyFile"`
	// AllowedRoots confines file/dir operations. If empty, falls back to
	// DirBrowse.AllowedRoots; if both are empty the listener refuses to start.
	AllowedRoots []string `json:"allowedRoots"`
	// MaxConns caps concurrent authenticated connections (default 4).
	MaxConns int `json:"maxConns"`
	// MaxUploadBytes caps a single file upload (default 100 MiB).
	MaxUploadBytes int64 `json:"maxUploadBytes"`
	// OIDC configures token verification against the issuer.
	OIDC DirectOIDCConfig `json:"oidc"`
}

// DirectOIDCConfig configures Machine Token verification for direct mode.
type DirectOIDCConfig struct {
	// Issuer is the OIDC issuer base URL (e.g. "https://aut.hair").
	Issuer string `json:"issuer"`
	// Audience is the rebase-ide machine client_id; incoming tokens must carry
	// exactly this aud. Required.
	Audience string `json:"audience"`
	// RequiredScope must be present in the token (default "openid").
	RequiredScope string `json:"requiredScope"`
	// MachineInfoProbe enables the /api/machine-info revocation probe (default true).
	MachineInfoProbe bool `json:"machineInfoProbe"`
	// ProbeIntervalSec re-checks revocation while connected (default 60).
	ProbeIntervalSec int `json:"probeIntervalSec"`
}

// DockerConfig controls Docker integration and Swarm management.
type DockerConfig struct {
	Enabled    bool   `json:"enabled"`
	SocketPath string `json:"socketPath,omitempty"`
}

// KioskConfig controls the optional kiosk mode (fullscreen WebView display).
type KioskConfig struct {
	// Enabled starts the kiosk subsystem. Requires the kiosk variant binary.
	Enabled bool `json:"enabled"`
	// ListenAddr is the address for the local kiosk HTTP/WS server (default "127.0.0.1:0" for ephemeral port).
	ListenAddr string `json:"listenAddr"`
	// Fullscreen opens the WebView in fullscreen mode (default true).
	Fullscreen bool `json:"fullscreen"`
}

// AgentVariant specifies which binary variant is running or desired.
type AgentVariant string

const (
	// VariantHeadless is the default variant without kiosk/GUI support.
	VariantHeadless AgentVariant = "headless"
	// VariantKiosk is the variant with kiosk/GUI support (requires CGO and GUI libraries).
	VariantKiosk AgentVariant = "kiosk"
)

// VariantConfig tracks the current and desired agent binary variant.
type VariantConfig struct {
	// Current is the variant of the currently running binary (detected at startup).
	// This is informational and not persisted.
	Current AgentVariant `json:"-"`
	// Desired is the preferred variant. If different from Current, the agent will
	// attempt to switch on the next update or when explicitly requested.
	Desired AgentVariant `json:"desired"`
	// LastSwitchError records the error from the most recent failed variant switch.
	LastSwitchError string `json:"lastSwitchError,omitempty"`
	// LastSwitchAttempt is the RFC3339 timestamp of the last switch attempt.
	LastSwitchAttempt string `json:"lastSwitchAttempt,omitempty"`
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

// Load reads the config file, deep-merges it over the built-in defaults,
// applies env overrides, and validates the result.
//
// Because we unmarshal the user's JSON into a pre-populated struct, any
// fields absent from the file keep their default values. This prevents
// configuration drift when new fields are added across releases.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := defaultConfig()
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyEnvOverrides()
	cfg.applyPostMerge()
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

// defaultConfig returns a Config pre-populated with all built-in defaults.
// Load() unmarshals the user's JSON file into this struct, so any fields
// not present in the file keep their default values automatically.
func defaultConfig() Config {
	enabled := true
	shellCmd := "/bin/bash"
	shellArgs := []string{"-l"}
	if runtime.GOOS == "windows" {
		shellCmd = "cmd.exe"
		shellArgs = []string{"/Q"}
	}

	return Config{
		StatsIntervalSec:         60,
		HeartbeatIntervalSec:     20,
		UpdateCheckEnabled:       &enabled,
		UpdateCheckIntervalHours: 12,
		OpenHardwareMonitorPort:  8085,
		PongTimeoutSec:           90,
		Connectivity: ConnectivityConfig{
			TCPTestPort: 53,
		},
		Admin: AdminConfig{
			MaxConcurrent:     1,
			DefaultTimeoutSec: 30,
		},
		Transport: TransportConfig{
			Path:            "/ws/agent",
			MaxClockSkewSec: 300,
		},
		Shell: ShellConfig{
			Command:        shellCmd,
			Args:           shellArgs,
			IdleTimeoutSec: 60,
		},
		Logging: LoggingConfig{
			FilePath: filepath.Join(".", "agent.log"),
			Level:    "info",
		},
		DirBrowse: DirBrowseConfig{
			SSHHostKeyPolicy: "known_hosts",
			SMBProfiles:      map[string]SMBProfile{},
		},
		Kiosk: KioskConfig{
			ListenAddr: "127.0.0.1:0",
		},
		DirectMode: DirectModeConfig{
			MaxConns:       4,
			MaxUploadBytes: 100 << 20, // 100 MiB
			OIDC: DirectOIDCConfig{
				RequiredScope:    "openid",
				MachineInfoProbe: true,
				ProbeIntervalSec: 60,
			},
		},
		Alerts: AlertsConfig{
			Enabled:         runtime.GOOS == "linux",
			ScanIntervalSec: 300,
			MaxAlerts:       50,
			LookbackHours:   24,
		},
		Variant: VariantConfig{
			Desired: VariantHeadless,
		},
		Docker: DockerConfig{
			Enabled: true,
		},
	}
}

// applyPostMerge handles cross-field dependencies that can't be expressed as
// simple static defaults (e.g., one field's default depends on another's value).
func (c *Config) applyPostMerge() {
	// LOG_FILE env var overrides when no explicit file path was provided
	if env := os.Getenv("LOG_FILE"); env != "" {
		c.Logging.FilePath = env
	}

	// Rate-limit window defaults to 60s only when a rate limit is configured
	if c.Admin.RateLimitMax > 0 && c.Admin.RateLimitWindowSec <= 0 {
		c.Admin.RateLimitWindowSec = 60
	}

	// Ensure SMBProfiles map is never nil (slice/map zero-values from JSON "null")
	if c.DirBrowse.SMBProfiles == nil {
		c.DirBrowse.SMBProfiles = map[string]SMBProfile{}
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
	if v := os.Getenv("AGENT_DOCKER_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			c.Docker.Enabled = b
		}
	}
	if v := os.Getenv("AGENT_DOCKER_SOCKET"); v != "" {
		c.Docker.SocketPath = strings.TrimSpace(v)
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
