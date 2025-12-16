package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDefaultPath(t *testing.T) {
	// Test default path
	originalEnv := os.Getenv("CLIENT_CONFIG_PATH")
	defer os.Setenv("CLIENT_CONFIG_PATH", originalEnv)
	os.Unsetenv("CLIENT_CONFIG_PATH")

	path := DefaultPath()
	// filepath.Join normalizes the path, so "./" becomes ""
	expected := "agent-config.json"
	if path != expected {
		t.Errorf("expected default path %q, got %q", expected, path)
	}

	// Test environment override
	os.Setenv("CLIENT_CONFIG_PATH", "/custom/path.json")
	path = DefaultPath()
	if path != "/custom/path.json" {
		t.Errorf("expected env override '/custom/path.json', got %q", path)
	}
}

func TestLoad_ValidFile(t *testing.T) {
	tmpdir := t.TempDir()
	cfgPath := filepath.Join(tmpdir, "config.json")

	cfg := &Config{
		ClientID:  "test-id",
		ServerURL: "https://example.com",
		AuthToken: "secret-token",
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	loaded, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if loaded.ClientID != "test-id" {
		t.Errorf("expected ClientID 'test-id', got %q", loaded.ClientID)
	}
	if loaded.ServerURL != "https://example.com" {
		t.Errorf("expected ServerURL 'https://example.com', got %q", loaded.ServerURL)
	}
	if loaded.AuthToken != "secret-token" {
		t.Errorf("expected AuthToken 'secret-token', got %q", loaded.AuthToken)
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	tmpdir := t.TempDir()
	cfgPath := filepath.Join(tmpdir, "config.json")

	if err := os.WriteFile(cfgPath, []byte("not json"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path/config.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_EnvOverrides(t *testing.T) {
	tmpdir := t.TempDir()
	cfgPath := filepath.Join(tmpdir, "config.json")

	cfg := &Config{
		ClientID:  "file-id",
		ServerURL: "https://file.example.com",
		AuthToken: "file-token",
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Set environment variables
	originalVars := map[string]string{
		"CLIENT_ID":              os.Getenv("CLIENT_ID"),
		"SERVER_URL":             os.Getenv("SERVER_URL"),
		"AUTH_TOKEN":             os.Getenv("AUTH_TOKEN"),
		"STATS_INTERVAL_SEC":     os.Getenv("STATS_INTERVAL_SEC"),
		"HEARTBEAT_INTERVAL_SEC": os.Getenv("HEARTBEAT_INTERVAL_SEC"),
		"PONG_TIMEOUT_SEC":       os.Getenv("PONG_TIMEOUT_SEC"),
		"ADMIN_ALLOWED_COMMANDS": os.Getenv("ADMIN_ALLOWED_COMMANDS"),
		"AGENT_SKIP_TLS_VERIFY":  os.Getenv("AGENT_SKIP_TLS_VERIFY"),
		"OHM_PORT":               os.Getenv("OHM_PORT"),
	}
	defer func() {
		for k, v := range originalVars {
			if v == "" {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, v)
			}
		}
	}()

	os.Setenv("CLIENT_ID", "env-id")
	os.Setenv("SERVER_URL", "https://env.example.com")
	os.Setenv("AUTH_TOKEN", "env-token")
	os.Setenv("STATS_INTERVAL_SEC", "120")
	os.Setenv("HEARTBEAT_INTERVAL_SEC", "25")
	os.Setenv("PONG_TIMEOUT_SEC", "100")
	os.Setenv("ADMIN_ALLOWED_COMMANDS", "echo,uptime,ls")
	os.Setenv("AGENT_SKIP_TLS_VERIFY", "true")
	os.Setenv("OHM_PORT", "12345")

	loaded, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if loaded.ClientID != "env-id" {
		t.Errorf("expected env override ClientID 'env-id', got %q", loaded.ClientID)
	}
	if loaded.ServerURL != "https://env.example.com" {
		t.Errorf("expected env override ServerURL 'https://env.example.com', got %q", loaded.ServerURL)
	}
	if loaded.AuthToken != "env-token" {
		t.Errorf("expected env override AuthToken 'env-token', got %q", loaded.AuthToken)
	}
	if loaded.StatsIntervalSec != 120 {
		t.Errorf("expected env override StatsIntervalSec 120, got %d", loaded.StatsIntervalSec)
	}
	if loaded.HeartbeatIntervalSec != 25 {
		t.Errorf("expected env override HeartbeatIntervalSec 25, got %d", loaded.HeartbeatIntervalSec)
	}
	if loaded.PongTimeoutSec != 100 {
		t.Errorf("expected env override PongTimeoutSec 100, got %d", loaded.PongTimeoutSec)
	}
	if len(loaded.Admin.Allowed) != 3 {
		t.Errorf("expected 3 allowed commands, got %d", len(loaded.Admin.Allowed))
	}
	if !loaded.Transport.SkipTLSVerify {
		t.Error("expected SkipTLSVerify to be true from env")
	}
	if loaded.OpenHardwareMonitorPort != 12345 {
		t.Errorf("expected OpenHardwareMonitorPort 12345 from env, got %d", loaded.OpenHardwareMonitorPort)
	}
}

func TestValidate_RequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: &Config{
				ClientID:  "test",
				ServerURL: "https://example.com",
				AuthToken: "token",
			},
			wantErr: false,
		},
		{
			name: "missing clientId",
			cfg: &Config{
				ServerURL: "https://example.com",
				AuthToken: "token",
			},
			wantErr: true,
		},
		{
			name: "missing serverUrl",
			cfg: &Config{
				ClientID:  "test",
				AuthToken: "token",
			},
			wantErr: true,
		},
		{
			name: "missing authToken",
			cfg: &Config{
				ClientID:  "test",
				ServerURL: "https://example.com",
			},
			wantErr: true,
		},
		{
			name: "whitespace clientId",
			cfg: &Config{
				ClientID:  "   ",
				ServerURL: "https://example.com",
				AuthToken: "token",
			},
			wantErr: true,
		},
		{
			name: "whitespace serverUrl",
			cfg: &Config{
				ClientID:  "test",
				ServerURL: "   ",
				AuthToken: "token",
			},
			wantErr: true,
		},
		{
			name: "whitespace authToken",
			cfg: &Config{
				ClientID:  "test",
				ServerURL: "https://example.com",
				AuthToken: "   ",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestApplyDefaults(t *testing.T) {
	cfg := &Config{
		ClientID:  "test",
		ServerURL: "https://example.com",
		AuthToken: "token",
	}

	cfg.applyDefaults()

	if cfg.StatsIntervalSec != 60 {
		t.Errorf("expected default StatsIntervalSec 60, got %d", cfg.StatsIntervalSec)
	}
	if cfg.HeartbeatIntervalSec != 20 {
		t.Errorf("expected default HeartbeatIntervalSec 20, got %d", cfg.HeartbeatIntervalSec)
	}
	if cfg.PongTimeoutSec != 90 {
		t.Errorf("expected default PongTimeoutSec 90, got %d", cfg.PongTimeoutSec)
	}
	if cfg.OpenHardwareMonitorPort != 8085 {
		t.Errorf("expected default OpenHardwareMonitorPort 8085, got %d", cfg.OpenHardwareMonitorPort)
	}
	if cfg.Connectivity.TCPTestPort != 53 {
		t.Errorf("expected default TCPTestPort 53, got %d", cfg.Connectivity.TCPTestPort)
	}
	if cfg.Admin.MaxConcurrent != 1 {
		t.Errorf("expected default MaxConcurrent 1, got %d", cfg.Admin.MaxConcurrent)
	}
	if cfg.Admin.DefaultTimeoutSec != 30 {
		t.Errorf("expected default DefaultTimeoutSec 30, got %d", cfg.Admin.DefaultTimeoutSec)
	}
	if cfg.Transport.Path != "/socket.io" {
		t.Errorf("expected default Transport.Path '/socket.io', got %q", cfg.Transport.Path)
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("expected default Logging.Level 'info', got %q", cfg.Logging.Level)
	}

	// Test platform-specific shell defaults
	if runtime.GOOS == "windows" {
		if cfg.Shell.Command != "cmd.exe" {
			t.Errorf("expected Windows shell 'cmd.exe', got %q", cfg.Shell.Command)
		}
		if len(cfg.Shell.Args) == 0 || cfg.Shell.Args[0] != "/Q" {
			t.Errorf("expected Windows shell args ['/Q'], got %v", cfg.Shell.Args)
		}
	} else {
		if cfg.Shell.Command != "/bin/bash" {
			t.Errorf("expected Unix shell '/bin/bash', got %q", cfg.Shell.Command)
		}
		if len(cfg.Shell.Args) == 0 || cfg.Shell.Args[0] != "-l" {
			t.Errorf("expected Unix shell args ['-l'], got %v", cfg.Shell.Args)
		}
	}

	// Test logging file path default
	// filepath.Join normalizes the path, so "./" becomes ""
	expectedLogPath := "agent.log"
	if cfg.Logging.FilePath != expectedLogPath {
		t.Errorf("expected default Logging.FilePath %q, got %q", expectedLogPath, cfg.Logging.FilePath)
	}
}

func TestApplyDefaults_RespectsExistingValues(t *testing.T) {
	cfg := &Config{
		ClientID:                "test",
		ServerURL:               "https://example.com",
		AuthToken:               "token",
		StatsIntervalSec:        120,
		HeartbeatIntervalSec:    40,
		PongTimeoutSec:          120,
		OpenHardwareMonitorPort: 9001,
		Admin: AdminConfig{
			MaxConcurrent:     5,
			DefaultTimeoutSec: 60,
		},
		Transport: TransportConfig{
			Path: "/custom",
		},
		Shell: ShellConfig{
			Command: "/bin/zsh",
			Args:    []string{"-c"},
		},
	}

	cfg.applyDefaults()

	if cfg.StatsIntervalSec != 120 {
		t.Errorf("expected StatsIntervalSec to remain 120, got %d", cfg.StatsIntervalSec)
	}
	if cfg.HeartbeatIntervalSec != 40 {
		t.Errorf("expected HeartbeatIntervalSec to remain 40, got %d", cfg.HeartbeatIntervalSec)
	}
	if cfg.PongTimeoutSec != 120 {
		t.Errorf("expected PongTimeoutSec to remain 120, got %d", cfg.PongTimeoutSec)
	}
	if cfg.OpenHardwareMonitorPort != 9001 {
		t.Errorf("expected OpenHardwareMonitorPort to remain 9001, got %d", cfg.OpenHardwareMonitorPort)
	}
	if cfg.Admin.MaxConcurrent != 5 {
		t.Errorf("expected MaxConcurrent to remain 5, got %d", cfg.Admin.MaxConcurrent)
	}
	if cfg.Admin.DefaultTimeoutSec != 60 {
		t.Errorf("expected DefaultTimeoutSec to remain 60, got %d", cfg.Admin.DefaultTimeoutSec)
	}
	if cfg.Transport.Path != "/custom" {
		t.Errorf("expected Transport.Path to remain '/custom', got %q", cfg.Transport.Path)
	}
	if cfg.Shell.Command != "/bin/zsh" {
		t.Errorf("expected Shell.Command to remain '/bin/zsh', got %q", cfg.Shell.Command)
	}
}

func TestLoad_WithEnvLogFile(t *testing.T) {
	originalEnv := os.Getenv("LOG_FILE")
	defer os.Setenv("LOG_FILE", originalEnv)

	os.Setenv("LOG_FILE", "/custom/log/path.log")

	tmpdir := t.TempDir()
	cfgPath := filepath.Join(tmpdir, "config.json")

	cfg := &Config{
		ClientID:  "test",
		ServerURL: "https://example.com",
		AuthToken: "token",
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	loaded, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if loaded.Logging.FilePath != "/custom/log/path.log" {
		t.Errorf("expected Logging.FilePath '/custom/log/path.log', got %q", loaded.Logging.FilePath)
	}
}

func TestUpdateChecksEnabled(t *testing.T) {
	// Nil config defaults to enabled.
	var nilCfg *Config
	if !nilCfg.UpdateChecksEnabled() {
		t.Fatalf("expected nil config to default to enabled")
	}

	// Nil pointer field defaults to enabled.
	c := &Config{UpdateCheckEnabled: nil}
	if !c.UpdateChecksEnabled() {
		t.Fatalf("expected nil UpdateCheckEnabled to default to enabled")
	}

	f := false
	c.UpdateCheckEnabled = &f
	if c.UpdateChecksEnabled() {
		t.Fatalf("expected UpdateChecksEnabled=false when UpdateCheckEnabled is false")
	}

	tr := true
	c.UpdateCheckEnabled = &tr
	if !c.UpdateChecksEnabled() {
		t.Fatalf("expected UpdateChecksEnabled=true when UpdateCheckEnabled is true")
	}
}
