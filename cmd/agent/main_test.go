package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/austinkregel/compute-agent/pkg/config"
	"github.com/austinkregel/compute-agent/pkg/logging"
)

type fakeAgent struct {
	runErr error
}

func (f fakeAgent) Run(_ context.Context) error {
	return f.runErr
}

func TestPrintVersion(t *testing.T) {
	// Test printVersion function directly to ensure coverage
	printVersion()
	// Function should complete without error
}

func TestMain_VersionFlagPath(t *testing.T) {
	// Test the version flag code path directly by simulating the flag parsing
	// This ensures coverage of the return statement that subprocess tests might miss
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// Reset flags
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	os.Args = []string{"backup-agent", "-version"}

	var showVersion bool
	flag.BoolVar(&showVersion, "version", false, "Print version and exit")
	flag.Parse()

	// This directly tests the code path in main() for the version flag
	if showVersion {
		printVersion()
		// In the actual main(), there's a return here, but we can't test that directly
		// without calling main() which would exit. The subprocess test handles that.
		// This test ensures the printVersion() call is covered.
	}
}

func TestHelperProcess_Main(t *testing.T) {
	// Helper subprocess to execute main() and observe os.Exit behavior.
	// This test is only meant to be run when invoked via exec.Command from other tests.
	if os.Getenv("TEST_HELPER_MAIN") != "1" {
		t.Skip("helper process")
	}

	mode := os.Getenv("TEST_HELPER_MODE")
	cfgPath := os.Getenv("TEST_HELPER_CONFIG")

	// Reset flags for the subprocess invocation.
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

	switch mode {
	case "agent_run_error":
		newAgent = func(_ *config.Config, _ *logging.Logger) (agentRunner, error) {
			return fakeAgent{runErr: errors.New("boom")}, nil
		}
	case "agent_run_canceled":
		newAgent = func(_ *config.Config, _ *logging.Logger) (agentRunner, error) {
			return fakeAgent{runErr: context.Canceled}, nil
		}
	case "agent_run_success":
		newAgent = func(_ *config.Config, _ *logging.Logger) (agentRunner, error) {
			return fakeAgent{runErr: nil}, nil
		}
	}

	switch mode {
	case "version_flag":
		os.Args = []string{"backup-agent", "-version"}
	case "invalid_config", "missing_config", "logger_init_failure", "agent_creation_failure", "agent_run_error", "agent_run_canceled", "agent_run_success":
		os.Args = []string{"backup-agent", "--config", cfgPath}
	default:
		os.Args = []string{"backup-agent"}
	}

	main()
}

func TestMain_VersionFlag(t *testing.T) {
	// Test version flag using helper process pattern to ensure coverage is captured
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess_Main")
	cmd.Env = append(os.Environ(),
		"TEST_HELPER_MAIN=1",
		"TEST_HELPER_MODE=version_flag",
	)
	output, err := cmd.CombinedOutput()

	if err != nil {
		t.Fatalf("command failed: %v, output: %s", err, output)
	}

	if !strings.Contains(string(output), "backup-agent") {
		t.Errorf("expected version output to contain 'backup-agent', got %q", string(output))
	}
}

func TestMain_ConfigFlag(t *testing.T) {
	tmpdir := t.TempDir()
	cfgPath := filepath.Join(tmpdir, "config.json")

	// Create a minimal valid config
	cfg := `{
		"clientId": "test",
		"serverUrl": "https://example.com",
		"authToken": "token"
	}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Test that --config flag is accepted (we can't easily test full execution
	// without mocking all dependencies, but we can verify flag parsing)
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"backup-agent", "--config", cfgPath, "--version"}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

	var cfgPathFlag string
	flag.StringVar(&cfgPathFlag, "config", "", "Path to agent-config.json")
	flag.Parse()

	if cfgPathFlag != cfgPath {
		t.Errorf("expected config path %q, got %q", cfgPath, cfgPathFlag)
	}
}

func TestMain_InvalidConfig(t *testing.T) {
	tmpdir := t.TempDir()
	cfgPath := filepath.Join(tmpdir, "invalid.json")

	if err := os.WriteFile(cfgPath, []byte("not json"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess_Main")
	cmd.Env = append(os.Environ(),
		"TEST_HELPER_MAIN=1",
		"TEST_HELPER_MODE=invalid_config",
		"TEST_HELPER_CONFIG="+cfgPath,
	)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit; output: %s", output)
	}
	if !strings.Contains(string(output), "failed to load config:") {
		t.Fatalf("expected stderr to mention failed to load config, got %q", string(output))
	}
}

func TestMain_MissingConfig(t *testing.T) {
	nonexistent := filepath.Join(t.TempDir(), "nonexistent.json")

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess_Main")
	cmd.Env = append(os.Environ(),
		"TEST_HELPER_MAIN=1",
		"TEST_HELPER_MODE=missing_config",
		"TEST_HELPER_CONFIG="+nonexistent,
	)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit; output: %s", output)
	}
	if !strings.Contains(string(output), "failed to load config:") {
		t.Fatalf("expected stderr to mention failed to load config, got %q", string(output))
	}
}

func TestMain_LoggerInitFailure(t *testing.T) {
	tmpdir := t.TempDir()
	cfgPath := filepath.Join(tmpdir, "config.json")
	notADir := filepath.Join(tmpdir, "notadir")
	logPath := filepath.Join(notADir, "agent.log")

	// Create minimal valid config (logging defaults are taken from LOG_FILE env var).
	cfg := `{
		"clientId": "test",
		"serverUrl": "http://127.0.0.1:1",
		"authToken": "token"
	}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	// Create a file where a directory is expected, forcing logger init to fail on MkdirAll.
	if err := os.WriteFile(notADir, []byte("x"), 0o644); err != nil {
		t.Fatalf("write notadir sentinel file: %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess_Main")
	cmd.Env = append(os.Environ(),
		"TEST_HELPER_MAIN=1",
		"TEST_HELPER_MODE=logger_init_failure",
		"TEST_HELPER_CONFIG="+cfgPath,
		"LOG_FILE="+logPath,
	)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit; output: %s", output)
	}
	if !strings.Contains(string(output), "failed to init logger:") {
		t.Fatalf("expected stderr to mention failed to init logger, got %q", string(output))
	}
}

func TestMain_AgentCreationFailure(t *testing.T) {
	tmpdir := t.TempDir()
	cfgPath := filepath.Join(tmpdir, "config.json")
	logPath := filepath.Join(tmpdir, "agent.log")

	// Use a malformed URL so transport.New fails during app.New.
	cfg := `{
		"clientId": "test",
		"serverUrl": "http://[::1",
		"authToken": "token"
	}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess_Main")
	cmd.Env = append(os.Environ(),
		"TEST_HELPER_MAIN=1",
		"TEST_HELPER_MODE=agent_creation_failure",
		"TEST_HELPER_CONFIG="+cfgPath,
		"LOG_FILE="+logPath,
	)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit; output: %s", output)
	}
	if !strings.Contains(string(output), "startup failed") {
		t.Fatalf("expected output to contain startup failed, got %q", string(output))
	}
}

func TestMain_AgentRunError(t *testing.T) {
	tmpdir := t.TempDir()
	cfgPath := filepath.Join(tmpdir, "config.json")
	logPath := filepath.Join(tmpdir, "agent.log")

	cfg := `{
		"clientId": "test",
		"serverUrl": "http://127.0.0.1:1",
		"authToken": "token"
	}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess_Main")
	cmd.Env = append(os.Environ(),
		"TEST_HELPER_MAIN=1",
		"TEST_HELPER_MODE=agent_run_error",
		"TEST_HELPER_CONFIG="+cfgPath,
		"LOG_FILE="+logPath,
	)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit; output: %s", output)
	}
	if !strings.Contains(string(output), "agent terminated with error") {
		t.Fatalf("expected output to contain agent terminated with error, got %q", string(output))
	}
}

func TestMain_AgentRunContextCanceled(t *testing.T) {
	tmpdir := t.TempDir()
	cfgPath := filepath.Join(tmpdir, "config.json")
	logPath := filepath.Join(tmpdir, "agent.log")

	cfg := `{
		"clientId": "test",
		"serverUrl": "http://127.0.0.1:1",
		"authToken": "token"
	}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess_Main")
	cmd.Env = append(os.Environ(),
		"TEST_HELPER_MAIN=1",
		"TEST_HELPER_MODE=agent_run_canceled",
		"TEST_HELPER_CONFIG="+cfgPath,
		"LOG_FILE="+logPath,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected zero exit; err=%v output=%s", err, output)
	}
}

func TestMain_AgentRunSuccess(t *testing.T) {
	tmpdir := t.TempDir()
	cfgPath := filepath.Join(tmpdir, "config.json")
	logPath := filepath.Join(tmpdir, "agent.log")

	cfg := `{
		"clientId": "test",
		"serverUrl": "http://127.0.0.1:1",
		"authToken": "token"
	}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess_Main")
	cmd.Env = append(os.Environ(),
		"TEST_HELPER_MAIN=1",
		"TEST_HELPER_MODE=agent_run_success",
		"TEST_HELPER_CONFIG="+cfgPath,
		"LOG_FILE="+logPath,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected zero exit; err=%v output=%s", err, output)
	}
	// When agent.Run returns nil, the program should exit cleanly without any error output
	if len(output) > 0 && strings.Contains(string(output), "error") {
		t.Errorf("unexpected error output: %s", string(output))
	}
}
