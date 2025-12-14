package app

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/austinkregel/compute-agent/pkg/config"
	"github.com/austinkregel/compute-agent/pkg/logging"
	"github.com/austinkregel/compute-agent/pkg/transport"
)

// We can't easily mock the transport.Client directly since it's a concrete type
// Instead, we'll test the handlers with a real transport or skip integration tests

func TestNew_ValidConfig(t *testing.T) {
	cfg := &config.Config{
		ClientID:  "test-client",
		ServerURL: "https://example.com",
		AuthToken: "test-token",
		Transport: config.TransportConfig{
			Path: "/socket.io",
		},
		Admin: config.AdminConfig{
			EnableShell: true,
			Allowed:     []string{"echo"},
		},
		Shell: config.ShellConfig{
			Command: "/bin/bash",
			Args:    []string{"-l"},
		},
	}
	log, _ := logging.New(logging.Options{Level: "error"})

	agent, err := New(cfg, log)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if agent == nil {
		t.Fatal("New() returned nil")
	}
	if agent.cfg != cfg {
		t.Error("config not set correctly")
	}
	if agent.log != log {
		t.Error("logger not set correctly")
	}
}

func TestHandleHello(t *testing.T) {
	cfg := &config.Config{
		ClientID:  "test-client",
		ServerURL: "https://example.com",
		AuthToken: "test-token",
		Transport: config.TransportConfig{Path: "/socket.io"},
		Admin:     config.AdminConfig{EnableShell: true},
		Shell:     config.ShellConfig{Command: "/bin/bash", Args: []string{"-l"}},
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	agent, _ := New(cfg, log)

	// Should not panic
	agent.handleHello()
}

func TestHandleAdminRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell command test not portable to windows")
	}
	cfg := &config.Config{
		ClientID:  "test-client",
		ServerURL: "https://example.com",
		AuthToken: "test-token",
		Transport: config.TransportConfig{Path: "/socket.io"},
		Admin: config.AdminConfig{
			EnableShell: true,
			Allowed:     []string{"echo"},
		},
		Shell: config.ShellConfig{Command: "/bin/bash", Args: []string{"-l"}},
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	agent, _ := New(cfg, log)

	msg := transport.AdminCommand{
		Token: "token-123",
		Cmd: transport.CommandSpec{
			Command:    "echo test",
			TimeoutSec: 5,
		},
	}

	// Handler should not panic
	agent.handleAdminRun(msg)
}

func TestAdminRun_UnauthenticatedRequest_Blocked(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell command test not portable to windows")
	}
	tmpdir := t.TempDir()
	target := filepath.Join(tmpdir, "pwned")

	cfg := &config.Config{
		ClientID:  "test-client",
		ServerURL: "https://example.com",
		AuthToken: "test-token",
		Transport: config.TransportConfig{Path: "/socket.io"},
		Admin: config.AdminConfig{
			EnableShell:   false,
			Allowed:       []string{"touch"},
			MaxConcurrent: 1,
			// New security settings (implemented in this hardening pass).
			RequireToken: true,
			CommandToken: "secret",
		},
		Shell: config.ShellConfig{Command: "/bin/bash", Args: []string{"-l"}},
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	agent, _ := New(cfg, log)

	agent.handleAdminRun(transport.AdminCommand{
		Token: "invalid",
		Cmd: transport.CommandSpec{
			Command:    "touch " + target,
			TimeoutSec: 5,
		},
	})

	if _, err := os.Stat(target); err == nil {
		t.Fatalf("expected unauthenticated admin_run to be blocked (file created: %s)", target)
	}
}

func TestAdminRun_AuthenticatedRequest_Allows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell command test not portable to windows")
	}
	tmpdir := t.TempDir()
	target := filepath.Join(tmpdir, "ok")

	cfg := &config.Config{
		ClientID:  "test-client",
		ServerURL: "https://example.com",
		AuthToken: "test-token",
		Transport: config.TransportConfig{Path: "/socket.io"},
		Admin: config.AdminConfig{
			EnableShell:   false,
			Allowed:       []string{"touch"},
			MaxConcurrent: 1,
			RequireToken:  true,
			CommandToken:  "secret",
		},
		Shell: config.ShellConfig{Command: "/bin/bash", Args: []string{"-l"}},
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	agent, _ := New(cfg, log)

	agent.handleAdminRun(transport.AdminCommand{
		Token: "secret",
		Cmd: transport.CommandSpec{
			Command:    "touch " + target,
			TimeoutSec: 5,
		},
	})

	if _, err := os.Stat(target); err != nil {
		t.Fatalf("expected authenticated admin_run to be allowed, stat error: %v", err)
	}
}

func TestHandleShellStart(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shell test in short mode")
	}
	if runtime.GOOS == "windows" {
		t.Skip("shell test not portable to windows")
	}
	cfg := &config.Config{
		ClientID:  "test-client",
		ServerURL: "https://example.com",
		AuthToken: "test-token",
		Transport: config.TransportConfig{Path: "/socket.io"},
		Admin: config.AdminConfig{
			EnableShell:   true,
			MaxConcurrent: 1,
		},
		Shell: config.ShellConfig{Command: "/bin/bash", Args: []string{"-l"}},
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	agent, _ := New(cfg, log)

	msg := transport.ShellStart{
		Session: "session-1",
	}

	// Handler should not panic
	agent.handleShellStart(msg)

	// Clean up
	agent.handleShellClose(transport.ShellClose{Session: "session-1"})
}

func TestHandleShellInput(t *testing.T) {
	cfg := &config.Config{
		ClientID:  "test-client",
		ServerURL: "https://example.com",
		AuthToken: "test-token",
		Transport: config.TransportConfig{Path: "/socket.io"},
		Admin: config.AdminConfig{
			EnableShell:   true,
			MaxConcurrent: 1,
		},
		Shell: config.ShellConfig{Command: "/bin/bash", Args: []string{"-l"}},
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	agent, _ := New(cfg, log)

	msg := transport.ShellInput{
		Session: "unknown-session",
		Data:    "test input",
	}

	// Should not panic even with unknown session
	agent.handleShellInput(msg)
}

func TestHandleShellResize(t *testing.T) {
	cfg := &config.Config{
		ClientID:  "test-client",
		ServerURL: "https://example.com",
		AuthToken: "test-token",
		Transport: config.TransportConfig{Path: "/socket.io"},
		Admin: config.AdminConfig{
			EnableShell:   true,
			MaxConcurrent: 1,
		},
		Shell: config.ShellConfig{Command: "/bin/bash", Args: []string{"-l"}},
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	agent, _ := New(cfg, log)

	msg := transport.ShellResize{
		Session: "unknown-session",
		Cols:    80,
		Rows:    24,
	}

	// Should not panic even with unknown session
	agent.handleShellResize(msg)
}

func TestHandleShellClose(t *testing.T) {
	cfg := &config.Config{
		ClientID:  "test-client",
		ServerURL: "https://example.com",
		AuthToken: "test-token",
		Transport: config.TransportConfig{Path: "/socket.io"},
		Admin: config.AdminConfig{
			EnableShell:   true,
			MaxConcurrent: 1,
		},
		Shell: config.ShellConfig{Command: "/bin/bash", Args: []string{"-l"}},
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	agent, _ := New(cfg, log)

	msg := transport.ShellClose{
		Session: "unknown-session",
	}

	// Should not panic even with unknown session
	agent.handleShellClose(msg)
}

func TestHandleBackupPlan(t *testing.T) {
	tmpdir := t.TempDir()
	src := filepath.Join(tmpdir, "src")
	dest := filepath.Join(tmpdir, "dest")
	os.Mkdir(src, 0o755)
	os.WriteFile(filepath.Join(src, "file.txt"), []byte("data"), 0o644)

	cfg := &config.Config{
		ClientID:  "test-client",
		ServerURL: "https://example.com",
		AuthToken: "test-token",
		Transport: config.TransportConfig{Path: "/socket.io"},
		Admin:     config.AdminConfig{EnableShell: true},
		Shell:     config.ShellConfig{Command: "/bin/bash", Args: []string{"-l"}},
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	agent, _ := New(cfg, log)

	msg := transport.BackupRequest{
		PlanID:     "plan-1",
		SourceDirs: []string{src},
		DestRoot:   dest,
	}

	// Handler should not panic
	agent.handleBackupPlan(msg)
}

func TestHandleBackupStart(t *testing.T) {
	tmpdir := t.TempDir()
	src := filepath.Join(tmpdir, "src")
	dest := filepath.Join(tmpdir, "dest")
	os.Mkdir(src, 0o755)
	os.WriteFile(filepath.Join(src, "file.txt"), []byte("data"), 0o644)

	cfg := &config.Config{
		ClientID:  "test-client",
		ServerURL: "https://example.com",
		AuthToken: "test-token",
		Transport: config.TransportConfig{Path: "/socket.io"},
		Admin:     config.AdminConfig{EnableShell: true},
		Shell:     config.ShellConfig{Command: "/bin/bash", Args: []string{"-l"}},
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	agent, _ := New(cfg, log)

	msg := transport.BackupRequest{
		PlanID:     "plan-1",
		SourceDirs: []string{src},
		DestRoot:   dest,
	}

	// Generate plan first
	agent.handleBackupPlan(msg)

	// Then start backup - should not panic
	agent.handleBackupStart(msg)
}

func TestHandleSyncKeys_ValidUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	cfg := &config.Config{
		ClientID:  "test-client",
		ServerURL: "https://example.com",
		AuthToken: "test-token",
		Transport: config.TransportConfig{Path: "/socket.io"},
		Admin:     config.AdminConfig{EnableShell: true},
		Shell:     config.ShellConfig{Command: "/bin/bash", Args: []string{"-l"}},
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	agent, _ := New(cfg, log)

	// We can't easily test the actual GitHub API call, but we can test the handler
	msg := transport.SyncKeysRequest{
		User: "testuser",
	}

	// Handler should not panic (may fail due to network, but that's expected)
	agent.handleSyncKeys(msg)
}

func TestSyncAuthorizedKeys_InvalidUser(t *testing.T) {
	cfg := &config.Config{
		ClientID:  "test-client",
		ServerURL: "https://example.com",
		AuthToken: "test-token",
		Transport: config.TransportConfig{Path: "/socket.io"},
		Admin:     config.AdminConfig{EnableShell: true},
		Shell:     config.ShellConfig{Command: "/bin/bash", Args: []string{"-l"}},
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	agent, _ := New(cfg, log)

	// Invalid username (contains invalid characters)
	_, err := agent.syncAuthorizedKeys("invalid user!")
	if err == nil {
		t.Error("expected error for invalid username")
	}
}

func TestSyncAuthorizedKeys_EmptyUser(t *testing.T) {
	cfg := &config.Config{
		ClientID:  "test-client",
		ServerURL: "https://example.com",
		AuthToken: "test-token",
		Transport: config.TransportConfig{Path: "/socket.io"},
		Admin:     config.AdminConfig{EnableShell: true},
		Shell:     config.ShellConfig{Command: "/bin/bash", Args: []string{"-l"}},
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	agent, _ := New(cfg, log)

	_, err := agent.syncAuthorizedKeys("")
	if err == nil {
		t.Error("expected error for empty username")
	}
}

func TestSyncKeys_InvalidSSHKey_Blocked(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want bool
	}{
		{
			name: "valid_ed25519",
			key:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEV2YWxpZEtleUJhc2U2NEJsb2I= test@example",
			want: true,
		},
		{
			name: "invalid_prefix",
			key:  "not-a-key AAAAB3NzaC1yc2EAAAADAQABAAABAQC= test@example",
			want: false,
		},
		{
			name: "newline_injection",
			key:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEV2YWxpZEtleQ== test@example\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEJhZA== bad@example",
			want: false,
		},
		{
			name: "too_long",
			key:  "ssh-ed25519 " + strings.Repeat("A", 20000) + " test@example",
			want: false,
		},
		{
			name: "invalid_base64",
			key:  "ssh-ed25519 !!! test@example",
			want: false,
		},
		{
			name: "missing_fields",
			key:  "ssh-ed25519",
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isValidAuthorizedKeyLine(tc.key); got != tc.want {
				t.Fatalf("isValidAuthorizedKeyLine()=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestEmitShellOutput(t *testing.T) {
	cfg := &config.Config{
		ClientID:  "test-client",
		ServerURL: "https://example.com",
		AuthToken: "test-token",
		Transport: config.TransportConfig{Path: "/socket.io"},
		Admin:     config.AdminConfig{EnableShell: true},
		Shell:     config.ShellConfig{Command: "/bin/bash", Args: []string{"-l"}},
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	agent, _ := New(cfg, log)

	// Should not panic even if transport is not connected
	agent.emitShellOutput("session-1", []byte("test output"))
}

func TestEmitShellClosed(t *testing.T) {
	cfg := &config.Config{
		ClientID:  "test-client",
		ServerURL: "https://example.com",
		AuthToken: "test-token",
		Transport: config.TransportConfig{Path: "/socket.io"},
		Admin:     config.AdminConfig{EnableShell: true},
		Shell:     config.ShellConfig{Command: "/bin/bash", Args: []string{"-l"}},
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	agent, _ := New(cfg, log)

	// Should not panic even if transport is not connected
	agent.emitShellClosed("session-1", 0, "exit")
}

func TestCtxOrBackground(t *testing.T) {
	cfg := &config.Config{
		ClientID:  "test-client",
		ServerURL: "https://example.com",
		AuthToken: "test-token",
		Transport: config.TransportConfig{Path: "/socket.io"},
		Admin:     config.AdminConfig{EnableShell: true},
		Shell:     config.ShellConfig{Command: "/bin/bash", Args: []string{"-l"}},
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	agent, _ := New(cfg, log)

	// Before Run(), ctx should be nil, so should return background
	ctx := agent.ctxOrBackground()
	if ctx == nil {
		t.Error("expected non-nil context")
	}

	// After Run(), should return the agent's context
	runCtx, cancel := context.WithCancel(context.Background())
	agent.ctx = runCtx
	defer cancel()

	ctx = agent.ctxOrBackground()
	if ctx != runCtx {
		t.Error("expected agent context to be returned")
	}
}

func TestRun_ContextCancellation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	cfg := &config.Config{
		ClientID:  "test-client",
		ServerURL: "https://example.com",
		AuthToken: "test-token",
		Transport: config.TransportConfig{Path: "/socket.io"},
		Admin:     config.AdminConfig{EnableShell: true},
		Shell:     config.ShellConfig{Command: "/bin/bash", Args: []string{"-l"}},
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	agent, _ := New(cfg, log)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Run should respect context cancellation
	err := agent.Run(ctx)
	if err == nil {
		t.Error("expected error from cancelled context")
	}
}
