package logging

import (
	"bytes"
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
	log.Warn("warn message", "key", "value")
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

func TestRotatingFile_Rotates(t *testing.T) {
	tmpdir := t.TempDir()
	logPath := filepath.Join(tmpdir, "rotate.log")

	rot, err := newRotatingFile(logPath, 50)
	if err != nil {
		t.Fatalf("newRotatingFile: %v", err)
	}
	t.Cleanup(func() { _ = rot.Close() })

	first := bytes.Repeat([]byte("a"), 40)
	second := bytes.Repeat([]byte("b"), 20) // triggers rotation before write

	if _, err := rot.Write(first); err != nil {
		t.Fatalf("write first: %v", err)
	}
	if _, err := rot.Write(second); err != nil {
		t.Fatalf("write second: %v", err)
	}
	_ = rot.Close()

	rotatedPath := logPath + ".1"
	rotated, err := os.ReadFile(rotatedPath)
	if err != nil {
		t.Fatalf("read rotated file: %v", err)
	}
	current, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read current file: %v", err)
	}
	if !bytes.Equal(rotated, first) {
		t.Fatalf("rotated content mismatch: got %q want %q", string(rotated), string(first))
	}
	if !bytes.Equal(current, second) {
		t.Fatalf("current content mismatch: got %q want %q", string(current), string(second))
	}
}

func TestRotatingFile_ExistingFileTriggersRotationOnNextWrite(t *testing.T) {
	tmpdir := t.TempDir()
	logPath := filepath.Join(tmpdir, "rotate.log")

	// Pre-create a file larger than the max so the first write forces rotation.
	orig := bytes.Repeat([]byte("x"), 100)
	if err := os.WriteFile(logPath, orig, 0o600); err != nil {
		t.Fatalf("seed log file: %v", err)
	}

	rot, err := newRotatingFile(logPath, 50)
	if err != nil {
		t.Fatalf("newRotatingFile: %v", err)
	}
	t.Cleanup(func() { _ = rot.Close() })

	payload := []byte("hello")
	if _, err := rot.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = rot.Close()

	rotated, err := os.ReadFile(logPath + ".1")
	if err != nil {
		t.Fatalf("read rotated file: %v", err)
	}
	current, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read current file: %v", err)
	}
	if !bytes.Equal(rotated, orig) {
		t.Fatalf("rotated content mismatch: got %d bytes want %d bytes", len(rotated), len(orig))
	}
	if string(current) != string(payload) {
		t.Fatalf("current content mismatch: got %q want %q", string(current), string(payload))
	}
}

func TestNewRotatingFile_DefaultMaxSizeWhenNonPositive(t *testing.T) {
	tmpdir := t.TempDir()
	logPath := filepath.Join(tmpdir, "rotate.log")

	rot, err := newRotatingFile(logPath, 0)
	if err != nil {
		t.Fatalf("newRotatingFile: %v", err)
	}
	t.Cleanup(func() { _ = rot.Close() })

	if rot.maxSize != defaultRotateMaxBytes {
		t.Fatalf("expected default maxSize %d, got %d", defaultRotateMaxBytes, rot.maxSize)
	}
}

func TestNewRotatingFile_MkdirAllErrorWhenParentIsFile(t *testing.T) {
	tmpdir := t.TempDir()
	parentAsFile := filepath.Join(tmpdir, "not-a-dir")
	if err := os.WriteFile(parentAsFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed parent file: %v", err)
	}
	// filepath.Dir(child) == parentAsFile, but it's a file, so MkdirAll should fail.
	child := filepath.Join(parentAsFile, "rotate.log")
	if _, err := newRotatingFile(child, 10); err == nil {
		t.Fatalf("expected error when parent is a file")
	}
}

func TestRotatingFile_ReopensOnWriteAfterClose(t *testing.T) {
	tmpdir := t.TempDir()
	logPath := filepath.Join(tmpdir, "rotate.log")

	rot, err := newRotatingFile(logPath, 100)
	if err != nil {
		t.Fatalf("newRotatingFile: %v", err)
	}

	if _, err := rot.Write([]byte("first")); err != nil {
		t.Fatalf("write first: %v", err)
	}
	if err := rot.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Second write should reopen the file (covers r.file == nil branch).
	if _, err := rot.Write([]byte("second")); err != nil {
		t.Fatalf("write second: %v", err)
	}
	_ = rot.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "firstsecond" {
		t.Fatalf("unexpected content: %q", string(data))
	}
}

func TestRotatingFile_RotateLockedOpenOrCreateFailurePropagates(t *testing.T) {
	tmpdir := t.TempDir()
	logPath := filepath.Join(tmpdir, "rotate.log")

	rot, err := newRotatingFile(logPath, 10)
	if err != nil {
		t.Fatalf("newRotatingFile: %v", err)
	}
	t.Cleanup(func() { _ = rot.Close() })

	if _, err := rot.Write([]byte("123456789")); err != nil {
		t.Fatalf("write initial: %v", err)
	}

	// Force rotation, but sabotage openOrCreate by setting path to a directory.
	// Also force the rename step to fail deterministically by ensuring "<dir>.1"
	// exists and is a non-empty directory (os.Remove will fail; rename will fail).
	dirPath := filepath.Join(tmpdir, "dir-as-path")
	if err := os.MkdirAll(dirPath, 0o755); err != nil {
		t.Fatalf("mkdir dirPath: %v", err)
	}
	rotatedDir := dirPath + ".1"
	if err := os.MkdirAll(rotatedDir, 0o755); err != nil {
		t.Fatalf("mkdir rotatedDir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rotatedDir, "keep"), []byte("x"), 0o644); err != nil {
		t.Fatalf("seed rotatedDir: %v", err)
	}

	rot.path = dirPath

	// Need enough bytes to cross the threshold (size 9 + 2 == 11 > 10).
	if _, err := rot.Write([]byte("XX")); err == nil {
		t.Fatalf("expected rotation/openOrCreate error")
	}
}
