package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNew_StdoutOnly(t *testing.T) {
	log, err := New(Options{
		File:  "",
		Level: "info",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if log == nil {
		t.Fatal("New() returned nil")
	}

	// Should not panic
	log.Info("test message")
	log.Error("test error")
	log.Debug("test debug")
}

func TestNew_WithFile(t *testing.T) {
	tmpdir := t.TempDir()
	logPath := filepath.Join(tmpdir, "test.log")

	log, err := New(Options{
		File:  logPath,
		Level: "info",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	log.Info("test message")
	log.Sync()

	// Verify file was created
	if _, err := os.Stat(logPath); err != nil {
		t.Errorf("log file not created: %v", err)
	}

	// Verify file permissions (should be 0600)
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat log file: %v", err)
	}
	mode := info.Mode().Perm()
	if mode != 0o600 {
		t.Errorf("expected file permissions 0600, got %o", mode)
	}

	// Verify content
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(data), "test message") {
		t.Errorf("log file doesn't contain message: %q", string(data))
	}
}

func TestNew_InvalidFile(t *testing.T) {
	// Try to create log in non-existent directory
	_, err := New(Options{
		File:  "/nonexistent/dir/log.log",
		Level: "info",
	})
	if err == nil {
		t.Error("expected error for invalid file path")
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"debug", "debug", "debug"},
		{"DEBUG", "DEBUG", "debug"},
		{"Debug", "Debug", "debug"},
		{"info", "info", "info"},
		{"INFO", "INFO", "info"},
		{"warn", "warn", "warn"},
		{"warning", "warning", "warn"},
		{"WARNING", "WARNING", "warn"},
		{"error", "error", "error"},
		{"ERROR", "ERROR", "error"},
		{"invalid", "invalid", "info"},
		{"empty", "", "info"},
		{"whitespace", "   ", "info"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, _ := New(Options{
				File:  "",
				Level: tt.input,
			})
			if log == nil {
				t.Fatal("New() returned nil")
			}
			// We can't directly check the level, but we can verify it doesn't panic
			log.Info("test")
		})
	}
}

func TestLogger_Methods(t *testing.T) {
	log, _ := New(Options{
		File:  "",
		Level: "debug",
	})

	// All methods should work without panicking
	log.Info("info message", "key", "value")
	log.Error("error message", "key", "value")
	log.Debug("debug message", "key", "value")
}

func TestLogger_With(t *testing.T) {
	log, _ := New(Options{
		File:  "",
		Level: "info",
	})

	child := log.With("component", "test", "id", "123")
	if child == nil {
		t.Fatal("With() returned nil")
	}
	if child == log {
		t.Error("With() should return a new logger")
	}

	// Should not panic
	child.Info("test message")
}

func TestLogger_Sync(t *testing.T) {
	tmpdir := t.TempDir()
	logPath := filepath.Join(tmpdir, "test.log")

	log, err := New(Options{
		File:  logPath,
		Level: "info",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	log.Info("test message")

	// Sync should close the file
	log.Sync()

	// Multiple syncs should be safe
	log.Sync()
	log.Sync()

	// Verify file was written
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(data), "test message") {
		t.Errorf("log file doesn't contain message: %q", string(data))
	}
}

func TestLogger_JSONFormat(t *testing.T) {
	tmpdir := t.TempDir()
	logPath := filepath.Join(tmpdir, "test.log")

	log, err := New(Options{
		File:  logPath,
		Level: "info",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	log.Info("test message", "key1", "value1", "key2", 42)
	log.Sync()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}

	// Verify it's JSON (should contain quotes and braces)
	if !strings.Contains(string(data), `"msg"`) && !strings.Contains(string(data), `"message"`) {
		t.Error("log output doesn't appear to be JSON format")
	}
}

func TestLogger_MultiWriter(t *testing.T) {
	tmpdir := t.TempDir()
	logPath := filepath.Join(tmpdir, "test.log")

	log, err := New(Options{
		File:  logPath,
		Level: "info",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Should write to both stdout and file
	log.Info("multi-writer test")
	log.Sync()

	// Verify file contains the message
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(data), "multi-writer test") {
		t.Errorf("log file doesn't contain message: %q", string(data))
	}
}




