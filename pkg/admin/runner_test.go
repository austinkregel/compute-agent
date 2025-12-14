package admin

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/austinkregel/compute-agent/pkg/config"
	"github.com/austinkregel/compute-agent/pkg/logging"
)

func TestRunCommandAllowlist(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell command test not portable to windows")
	}
	log, err := logging.New(logging.Options{Level: "error"})
	if err != nil {
		t.Fatalf("log init: %v", err)
	}
	cfg := &config.Config{
		Admin: config.AdminConfig{
			Allowed:       []string{"echo"},
			MaxConcurrent: 1,
		},
	}
	r := NewRunner(cfg, log, ShellCallbacks{})

	res := r.RunCommand(context.Background(), CommandRequest{
		Command: "echo hello",
		Timeout: time.Second,
	})
	if res.Summary.Code != 0 {
		t.Fatalf("expected success, got code=%d error=%s", res.Summary.Code, res.Error)
	}
	if res.Stdout == "" {
		t.Fatalf("expected stdout to contain data")
	}

	denied := r.RunCommand(context.Background(), CommandRequest{
		Command: "uptime",
		Timeout: time.Second,
	})
	if denied.Summary.Code != 126 {
		t.Fatalf("expected allowlist to block command, got %d", denied.Summary.Code)
	}
}

func TestRunCommand_CommandInjection_Blocked(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell command test not portable to windows")
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	cfg := &config.Config{
		Admin: config.AdminConfig{
			Allowed:       []string{"echo"},
			MaxConcurrent: 1,
		},
	}
	r := NewRunner(cfg, log, ShellCallbacks{})

	// This used to be exploitable because allow-list prefix matching + `/bin/sh -c`
	// would happily execute both commands.
	res := r.RunCommand(context.Background(), CommandRequest{
		Command: "echo ok; echo pwned",
		Timeout: time.Second,
	})
	if res.Summary.Code != 126 {
		t.Fatalf("expected injection attempt to be blocked, got code=%d stdout=%q stderr=%q err=%q",
			res.Summary.Code, res.Stdout, res.Stderr, res.Error)
	}
	if contains(res.Stdout, "pwned") {
		t.Fatalf("expected blocked command to not execute injected payload, stdout=%q", res.Stdout)
	}
}

func TestRunCommand_ShellInjection_Blocked(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell command test not portable to windows")
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	cfg := &config.Config{
		Admin: config.AdminConfig{
			Allowed:       []string{"echo"},
			MaxConcurrent: 1,
		},
	}
	r := NewRunner(cfg, log, ShellCallbacks{})

	tests := []string{
		`echo $(id)`,
		"echo `id`",
		`echo $HOME`,
	}
	for _, tc := range tests {
		t.Run(tc, func(t *testing.T) {
			res := r.RunCommand(context.Background(), CommandRequest{
				Command: tc,
				Timeout: time.Second,
			})
			if res.Summary.Code != 126 {
				t.Fatalf("expected shell injection attempt to be blocked, got code=%d stdout=%q stderr=%q err=%q",
					res.Summary.Code, res.Stdout, res.Stderr, res.Error)
			}
		})
	}
}

func TestRunCommand_PathTraversal_Cwd_Blocked(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell command test not portable to windows")
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	cfg := &config.Config{
		Admin: config.AdminConfig{
			Allowed:       []string{"pwd"},
			MaxConcurrent: 1,
		},
	}
	r := NewRunner(cfg, log, ShellCallbacks{})

	tests := []string{
		"/etc",
		"../../../etc",
	}
	for _, cwd := range tests {
		t.Run(cwd, func(t *testing.T) {
			res := r.RunCommand(context.Background(), CommandRequest{
				Command: "pwd",
				Cwd:     cwd,
				Timeout: time.Second,
			})
			if res.Summary.Code != 126 {
				t.Fatalf("expected disallowed cwd to be blocked, got code=%d stdout=%q stderr=%q err=%q",
					res.Summary.Code, res.Stdout, res.Stderr, res.Error)
			}
		})
	}
}

func TestRunCommand_EnvironmentSanitization(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell command test not portable to windows")
	}
	t.Setenv("SECRET", "shh")
	t.Setenv("API_KEY", "k")

	log, _ := logging.New(logging.Options{Level: "error"})
	cfg := &config.Config{
		Admin: config.AdminConfig{
			Allowed:       []string{"env"},
			MaxConcurrent: 1,
		},
	}
	r := NewRunner(cfg, log, ShellCallbacks{})

	res := r.RunCommand(context.Background(), CommandRequest{
		Command: "env",
		Timeout: time.Second,
	})
	if res.Summary.Code != 0 {
		t.Fatalf("expected env to run, got code=%d err=%q stderr=%q", res.Summary.Code, res.Error, res.Stderr)
	}
	if contains(res.Stdout, "SECRET=") || contains(res.Stdout, "API_KEY=") {
		t.Fatalf("expected sensitive env vars to be stripped, got stdout=%q", res.Stdout)
	}
}

func TestAdminRun_RateLimit_Enforced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell command test not portable to windows")
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	cfg := &config.Config{
		Admin: config.AdminConfig{
			Allowed:            []string{"echo"},
			MaxConcurrent:      1,
			RateLimitMax:       2,
			RateLimitWindowSec: 60,
		},
	}
	r := NewRunner(cfg, log, ShellCallbacks{})

	for i := 0; i < 2; i++ {
		res := r.RunCommand(context.Background(), CommandRequest{
			Command: "echo ok",
			Timeout: time.Second,
		})
		if res.Summary.Code != 0 {
			t.Fatalf("expected request %d to be allowed, got code=%d err=%q", i+1, res.Summary.Code, res.Error)
		}
	}

	limited := r.RunCommand(context.Background(), CommandRequest{
		Command: "echo blocked",
		Timeout: time.Second,
	})
	if limited.Summary.Code != 429 {
		t.Fatalf("expected rate limit to be enforced (code 429), got code=%d stdout=%q stderr=%q err=%q",
			limited.Summary.Code, limited.Stdout, limited.Stderr, limited.Error)
	}
}

func TestRunCommand_Success(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell command test not portable to windows")
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	cfg := &config.Config{
		Admin: config.AdminConfig{
			Allowed:       []string{"echo"},
			MaxConcurrent: 1,
		},
	}
	r := NewRunner(cfg, log, ShellCallbacks{})

	res := r.RunCommand(context.Background(), CommandRequest{
		Command: "echo test-output",
		Timeout: time.Second,
	})

	if res.Summary.Code != 0 {
		t.Errorf("expected exit code 0, got %d", res.Summary.Code)
	}
	if !contains(res.Stdout, "test-output") {
		t.Errorf("expected stdout to contain 'test-output', got %q", res.Stdout)
	}
	// Duration might be 0 for very fast commands, but should be set (>= 0)
	if res.Summary.DurationMs < 0 {
		t.Error("expected duration to be non-negative")
	}
}

func TestRunCommand_Timeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timeout test in short mode")
	}
	if runtime.GOOS == "windows" {
		t.Skip("shell command test not portable to windows")
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	cfg := &config.Config{
		Admin: config.AdminConfig{
			Allowed:       []string{"sleep"},
			MaxConcurrent: 1,
		},
	}
	r := NewRunner(cfg, log, ShellCallbacks{})

	res := r.RunCommand(context.Background(), CommandRequest{
		Command: "sleep 5",
		Timeout: 100 * time.Millisecond,
	})

	if res.Summary.Code != 124 {
		t.Errorf("expected timeout exit code 124, got %d", res.Summary.Code)
	}
}

func TestRunCommand_ExitCode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell command test not portable to windows")
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	cfg := &config.Config{
		Admin: config.AdminConfig{
			Allowed:       []string{"sh"},
			MaxConcurrent: 1,
		},
	}
	r := NewRunner(cfg, log, ShellCallbacks{})

	res := r.RunCommand(context.Background(), CommandRequest{
		Command: "sh -c 'exit 42'",
		Timeout: time.Second,
	})

	if res.Summary.Code != 42 {
		t.Errorf("expected exit code 42, got %d", res.Summary.Code)
	}
}

func TestRunCommand_Stderr(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell command test not portable to windows")
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	cfg := &config.Config{
		Admin: config.AdminConfig{
			Allowed:       []string{"sh"},
			MaxConcurrent: 1,
		},
	}
	r := NewRunner(cfg, log, ShellCallbacks{})

	res := r.RunCommand(context.Background(), CommandRequest{
		Command: "sh -c 'echo error >&2'",
		Timeout: time.Second,
	})

	if !contains(res.Stderr, "error") {
		t.Errorf("expected stderr to contain 'error', got %q", res.Stderr)
	}
}

func TestRunCommand_WorkingDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell command test not portable to windows")
	}
	tmpdir := t.TempDir()
	log, _ := logging.New(logging.Options{Level: "error"})
	cfg := &config.Config{
		Admin: config.AdminConfig{
			Allowed:       []string{"pwd"},
			AllowedCwds:   []string{tmpdir},
			MaxConcurrent: 1,
		},
	}
	r := NewRunner(cfg, log, ShellCallbacks{})

	res := r.RunCommand(context.Background(), CommandRequest{
		Command: "pwd",
		Cwd:     tmpdir,
		Timeout: time.Second,
	})

	if !contains(res.Stdout, tmpdir) {
		t.Errorf("expected pwd to show %q, got %q", tmpdir, res.Stdout)
	}
}

func TestRunCommand_EmptyCommand(t *testing.T) {
	log, _ := logging.New(logging.Options{Level: "error"})
	cfg := &config.Config{
		Admin: config.AdminConfig{
			Allowed:       []string{},
			MaxConcurrent: 1,
		},
	}
	r := NewRunner(cfg, log, ShellCallbacks{})

	res := r.RunCommand(context.Background(), CommandRequest{
		Command: "",
		Timeout: time.Second,
	})

	if res.Summary.Code != 1 {
		t.Errorf("expected exit code 1 for empty command, got %d", res.Summary.Code)
	}
	if res.Error == "" {
		t.Error("expected error message for empty command")
	}
}

func TestRunCommand_Allowlist_Empty(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell command test not portable to windows")
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	cfg := &config.Config{
		Admin: config.AdminConfig{
			Allowed:       []string{},
			MaxConcurrent: 1,
		},
	}
	r := NewRunner(cfg, log, ShellCallbacks{})

	// Empty allowlist should allow all
	res := r.RunCommand(context.Background(), CommandRequest{
		Command: "echo test",
		Timeout: time.Second,
	})

	if res.Summary.Code != 0 {
		t.Errorf("expected empty allowlist to allow command, got code %d", res.Summary.Code)
	}
}

func TestRunCommand_Allowlist_CaseInsensitive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell command test not portable to windows")
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	cfg := &config.Config{
		Admin: config.AdminConfig{
			Allowed:       []string{"ECHO"},
			MaxConcurrent: 1,
		},
	}
	r := NewRunner(cfg, log, ShellCallbacks{})

	res := r.RunCommand(context.Background(), CommandRequest{
		Command: "echo test",
		Timeout: time.Second,
	})

	if res.Summary.Code != 0 {
		t.Errorf("expected case-insensitive match, got code %d", res.Summary.Code)
	}
}

func TestRunCommand_Allowlist_PrefixMatch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell command test not portable to windows")
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	cfg := &config.Config{
		Admin: config.AdminConfig{
			Allowed:       []string{"echo"},
			MaxConcurrent: 1,
		},
	}
	r := NewRunner(cfg, log, ShellCallbacks{})

	res := r.RunCommand(context.Background(), CommandRequest{
		Command: "echo hello world",
		Timeout: time.Second,
	})

	if res.Summary.Code != 0 {
		t.Errorf("expected prefix match to work, got code %d", res.Summary.Code)
	}
}

func TestRunCommand_MaxConcurrent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell command test not portable to windows")
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	cfg := &config.Config{
		Admin: config.AdminConfig{
			Allowed:       []string{"sleep"},
			MaxConcurrent: 2,
		},
	}
	r := NewRunner(cfg, log, ShellCallbacks{})

	// Start two commands that should both run
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done1 := make(chan CommandResult, 1)
	done2 := make(chan CommandResult, 1)
	done3 := make(chan CommandResult, 1)

	go func() {
		done1 <- r.RunCommand(ctx, CommandRequest{
			Command: "sleep 0.5",
			Timeout: time.Second,
		})
	}()
	go func() {
		done2 <- r.RunCommand(ctx, CommandRequest{
			Command: "sleep 0.5",
			Timeout: time.Second,
		})
	}()
	go func() {
		done3 <- r.RunCommand(ctx, CommandRequest{
			Command: "sleep 0.5",
			Timeout: time.Second,
		})
	}()

	// All three should complete (third waits for slot)
	<-done1
	<-done2
	<-done3
}

func TestStartShell_Disabled(t *testing.T) {
	log, _ := logging.New(logging.Options{Level: "error"})
	cfg := &config.Config{
		Admin: config.AdminConfig{
			EnableShell:   false,
			MaxConcurrent: 1,
		},
	}
	r := NewRunner(cfg, log, ShellCallbacks{})

	err := r.StartShell(context.Background(), "session-1")
	if err != ErrShellDisabled {
		t.Errorf("expected ErrShellDisabled, got %v", err)
	}
}

func TestStartShell_EmptySessionID(t *testing.T) {
	log, _ := logging.New(logging.Options{Level: "error"})
	cfg := &config.Config{
		Admin: config.AdminConfig{
			EnableShell:   true,
			MaxConcurrent: 1,
		},
		Shell: config.ShellConfig{
			Command: "/bin/bash",
			Args:    []string{"-l"},
		},
	}
	r := NewRunner(cfg, log, ShellCallbacks{})

	err := r.StartShell(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty session ID")
	}
}

func TestShell_SendInput_UnknownSession(t *testing.T) {
	log, _ := logging.New(logging.Options{Level: "error"})
	cfg := &config.Config{
		Admin: config.AdminConfig{
			EnableShell:   true,
			MaxConcurrent: 1,
		},
	}
	r := NewRunner(cfg, log, ShellCallbacks{})

	err := r.SendInput("unknown-session", "test")
	if err == nil {
		t.Error("expected error for unknown session")
	}
}

func TestShell_Resize_UnknownSession(t *testing.T) {
	log, _ := logging.New(logging.Options{Level: "error"})
	cfg := &config.Config{
		Admin: config.AdminConfig{
			EnableShell:   true,
			MaxConcurrent: 1,
		},
	}
	r := NewRunner(cfg, log, ShellCallbacks{})

	err := r.Resize("unknown-session", 80, 24)
	if err == nil {
		t.Error("expected error for unknown session")
	}
}

func TestShell_Resize_InvalidDimensions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PTY test not portable to windows")
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	cfg := &config.Config{
		Admin: config.AdminConfig{
			EnableShell:   true,
			MaxConcurrent: 1,
		},
		Shell: config.ShellConfig{
			Command: "/bin/bash",
			Args:    []string{"-l"},
		},
	}
	r := NewRunner(cfg, log, ShellCallbacks{})

	err := r.StartShell(context.Background(), "session-1")
	if err != nil {
		t.Fatalf("StartShell: %v", err)
	}
	defer r.CloseShell("session-1")

	// Invalid dimensions should be ignored (not error)
	err = r.Resize("session-1", 0, 24)
	if err != nil {
		t.Errorf("expected invalid dimensions to be ignored, got error: %v", err)
	}

	err = r.Resize("session-1", 80, 0)
	if err != nil {
		t.Errorf("expected invalid dimensions to be ignored, got error: %v", err)
	}
}

func TestShell_Close_UnknownSession(t *testing.T) {
	log, _ := logging.New(logging.Options{Level: "error"})
	cfg := &config.Config{
		Admin: config.AdminConfig{
			EnableShell:   true,
			MaxConcurrent: 1,
		},
	}
	r := NewRunner(cfg, log, ShellCallbacks{})

	// Closing unknown session should not error
	err := r.CloseShell("unknown-session")
	if err != nil {
		t.Errorf("expected no error for unknown session, got %v", err)
	}
}

func TestShell_OutputCallback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PTY test not portable to windows")
	}
	outputs := make([][]byte, 0)
	log, _ := logging.New(logging.Options{Level: "error"})
	cfg := &config.Config{
		Admin: config.AdminConfig{
			EnableShell:   true,
			MaxConcurrent: 1,
		},
		Shell: config.ShellConfig{
			Command: "/bin/bash",
			Args:    []string{"-l"},
		},
	}
	callbacks := ShellCallbacks{
		OnOutput: func(session string, data []byte) {
			outputs = append(outputs, data)
		},
	}
	r := NewRunner(cfg, log, callbacks)

	err := r.StartShell(context.Background(), "session-1")
	if err != nil {
		t.Fatalf("StartShell: %v", err)
	}
	defer r.CloseShell("session-1")

	// Send input that should produce output
	time.Sleep(100 * time.Millisecond) // Give shell time to start
	err = r.SendInput("session-1", "echo test-output\n")
	if err != nil {
		t.Fatalf("SendInput: %v", err)
	}

	// Wait a bit for output
	time.Sleep(200 * time.Millisecond)

	// Check if we got any output
	if len(outputs) == 0 {
		t.Error("expected output callback to be called")
	}
}

func TestShell_ClosedCallback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PTY test not portable to windows")
	}
	var closedSession string
	var closedCode int
	var closedReason string

	log, _ := logging.New(logging.Options{Level: "error"})
	cfg := &config.Config{
		Admin: config.AdminConfig{
			EnableShell:   true,
			MaxConcurrent: 1,
		},
		Shell: config.ShellConfig{
			Command: "/bin/bash",
			Args:    []string{"-l", "-c", "exit 42"},
		},
	}
	callbacks := ShellCallbacks{
		OnClosed: func(session string, code int, reason string) {
			closedSession = session
			closedCode = code
			closedReason = reason
		},
	}
	r := NewRunner(cfg, log, callbacks)

	err := r.StartShell(context.Background(), "session-1")
	if err != nil {
		t.Fatalf("StartShell: %v", err)
	}

	// Wait for shell to exit
	time.Sleep(500 * time.Millisecond)

	if closedSession != "session-1" {
		t.Errorf("expected closed callback with session 'session-1', got %q", closedSession)
	}
	if closedCode != 42 {
		t.Errorf("expected closed callback with code 42, got %d", closedCode)
	}
	if closedReason == "" {
		t.Error("expected closed callback with reason")
	}
}

func TestRunCommand_DefaultTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timeout test in short mode")
	}
	if runtime.GOOS == "windows" {
		t.Skip("shell command test not portable to windows")
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	cfg := &config.Config{
		Admin: config.AdminConfig{
			Allowed:           []string{"sleep"},
			MaxConcurrent:     1,
			DefaultTimeoutSec: 1,
		},
	}
	r := NewRunner(cfg, log, ShellCallbacks{})

	// Command with no timeout should use default
	res := r.RunCommand(context.Background(), CommandRequest{
		Command: "sleep 2",
		Timeout: 0, // Use default
	})

	if res.Summary.Code != 124 {
		t.Errorf("expected timeout exit code 124, got %d", res.Summary.Code)
	}
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
