//go:build windows
// +build windows

package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSwapExecutableWindowsRenamePattern(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "agent.exe")
	staged := filepath.Join(dir, "agent.exe.new")

	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatalf("write exe: %v", err)
	}
	if err := os.WriteFile(staged, []byte("new"), 0o755); err != nil {
		t.Fatalf("write staged: %v", err)
	}

	if err := swapExecutable(exe, staged); err != nil {
		t.Fatalf("swapExecutable error: %v", err)
	}

	gotNew, err := os.ReadFile(exe)
	if err != nil {
		t.Fatalf("read exe: %v", err)
	}
	if string(gotNew) != "new" {
		t.Fatalf("exe contents = %q, want %q", string(gotNew), "new")
	}

	gotOld, err := os.ReadFile(exe + ".old")
	if err != nil {
		t.Fatalf("read old exe: %v", err)
	}
	if string(gotOld) != "old" {
		t.Fatalf("old exe contents = %q, want %q", string(gotOld), "old")
	}
}

func TestCleanupOldExecutablesWindows(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "agent.exe")
	oldPath := exe + ".old"

	if err := os.WriteFile(oldPath, []byte("old"), 0o644); err != nil {
		t.Fatalf("write old: %v", err)
	}

	cleanupOldExecutables(exe)

	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatalf("expected %s to be removed; err=%v", oldPath, err)
	}
}
