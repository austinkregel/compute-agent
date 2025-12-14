package backup

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/austinkregel/compute-agent/pkg/config"
	"github.com/austinkregel/compute-agent/pkg/logging"
	"github.com/austinkregel/compute-agent/pkg/transport"
)

func TestSafeJoin_BlocksTraversalAndAbs(t *testing.T) {
	tmp := t.TempDir()
	root, err := filepath.Abs(filepath.Join(tmp, "dest"))
	if err != nil {
		t.Fatal(err)
	}

	ok, err := safeJoin(root, "sub/file.txt")
	if err != nil {
		t.Fatalf("expected ok join, got err: %v", err)
	}
	if !isWithin(root, ok) {
		t.Fatalf("expected joined path within root, got root=%q path=%q", root, ok)
	}

	if _, err := safeJoin(root, "../../outside.txt"); err == nil {
		t.Fatal("expected traversal to be blocked")
	}
	if _, err := safeJoin(root, "/etc/passwd"); err == nil {
		t.Fatal("expected absolute path to be blocked")
	}
}

func TestGeneratePlan_DestRootAllowlist(t *testing.T) {
	tmp := t.TempDir()
	allowedRoot := filepath.Join(tmp, "allowed")
	dest := filepath.Join(allowedRoot, "dest")
	src := filepath.Join(tmp, "src")

	if err := os.MkdirAll(allowedRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(src, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "file.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	log, _ := logging.New(logging.Options{Level: "error"})
	coord := NewCoordinator(&config.Config{
		Backup: config.BackupConfig{
			AllowedDestRoots: []string{allowedRoot},
		},
	}, log, noopEmitter{})

	if _, err := coord.generatePlan(context.Background(), transport.BackupRequest{
		PlanID:     "p1",
		SourceDirs: []string{src},
		DestRoot:   dest,
	}); err != nil {
		t.Fatalf("expected allowed dest root, got err: %v", err)
	}

	// Outside allowlist should be rejected.
	if _, err := coord.generatePlan(context.Background(), transport.BackupRequest{
		PlanID:     "p2",
		SourceDirs: []string{src},
		DestRoot:   filepath.Join(tmp, "not-allowed"),
	}); err == nil {
		t.Fatal("expected dest root outside allowlist to be rejected")
	}
}

func TestGeneratePlan_SourceRootAllowlist(t *testing.T) {
	tmp := t.TempDir()
	allowed := filepath.Join(tmp, "allowed-src")
	forbidden := filepath.Join(tmp, "forbidden-src")
	dest := filepath.Join(tmp, "dest")

	if err := os.MkdirAll(allowed, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(forbidden, 0o700); err != nil {
		t.Fatal(err)
	}

	log, _ := logging.New(logging.Options{Level: "error"})
	coord := NewCoordinator(&config.Config{
		Backup: config.BackupConfig{
			AllowedSourceRoots: []string{allowed},
		},
	}, log, noopEmitter{})

	if _, err := coord.generatePlan(context.Background(), transport.BackupRequest{
		PlanID:     "p1",
		SourceDirs: []string{forbidden},
		DestRoot:   dest,
	}); err == nil {
		t.Fatal("expected source outside allowlist to be rejected")
	}
}
