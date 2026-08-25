package backup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/austinkregel/compute-agent/pkg/config"
	"github.com/austinkregel/compute-agent/pkg/logging"
	"github.com/austinkregel/compute-agent/pkg/transport"
)

// These tests pin the symlink contract deliberately (the old suite only tripped
// it by accident on macOS): with an allowlist, a source or in-tree symlink is
// honoured only when it resolves INSIDE the allowed roots; one that escapes is
// refused/skipped and never followed. That closes the exfiltration vector where
// `<src>/x -> /etc/shadow` would otherwise be copied out.

func allowlistedCoord(t *testing.T, roots ...string) *Coordinator {
	t.Helper()
	log, _ := logging.New(logging.Options{Level: "error"})
	return NewCoordinator(&config.Config{
		Backup: config.BackupConfig{AllowedSourceRoots: roots},
	}, log, noopEmitter{})
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported on this platform: %v", err)
	}
}

func relatives(rec *jobRecord) []string {
	out := make([]string, 0, len(rec.Files))
	for _, f := range rec.Files {
		out = append(out, f.Relative)
	}
	return out
}

func containsSuffix(list []string, suffix string) bool {
	for _, s := range list {
		if strings.HasSuffix(s, suffix) {
			return true
		}
	}
	return false
}

func TestValidateSourceDir_SymlinkIntoAllowedRoot_Accepted(t *testing.T) {
	tmp := realTempDir(t)
	allowed := filepath.Join(tmp, "allowed")
	sub := filepath.Join(allowed, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tmp, "link")
	mustSymlink(t, sub, link) // resolves INSIDE the allowed root

	got, err := allowlistedCoord(t, allowed).validateSourceDir(link)
	if err != nil {
		t.Fatalf("a symlink resolving inside an allowed root should be accepted: %v", err)
	}
	want, _ := filepath.EvalSymlinks(sub)
	if got != want {
		t.Errorf("expected the RESOLVED path %q (check == use), got %q", want, got)
	}
}

func TestValidateSourceDir_SymlinkEscapingAllowedRoot_Refused(t *testing.T) {
	tmp := realTempDir(t)
	allowed := filepath.Join(tmp, "allowed")
	outside := filepath.Join(tmp, "outside")
	os.MkdirAll(allowed, 0o755)
	os.MkdirAll(outside, 0o755)
	link := filepath.Join(tmp, "link")
	mustSymlink(t, outside, link) // escapes the allowed root

	if _, err := allowlistedCoord(t, allowed).validateSourceDir(link); err == nil {
		t.Error("a symlink resolving outside the allowed roots must be refused")
	}
}

func TestGeneratePlan_SkipsInTreeSymlinkEscapingAllowedRoots(t *testing.T) {
	tmp := realTempDir(t)
	src := filepath.Join(tmp, "src")
	outside := filepath.Join(tmp, "outside")
	os.MkdirAll(src, 0o755)
	os.MkdirAll(outside, 0o755)
	os.WriteFile(filepath.Join(src, "normal.txt"), []byte("ok"), 0o644)
	os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("SECRET"), 0o644)
	// The exfiltration attempt: an in-tree symlink pointing at an out-of-scope file.
	mustSymlink(t, filepath.Join(outside, "secret.txt"), filepath.Join(src, "leak.txt"))

	rec, err := allowlistedCoord(t, src).generatePlan(context.Background(), transport.BackupRequest{
		PlanID:     "plan-1",
		SourceDirs: []string{src},
		DestRoot:   filepath.Join(tmp, "dest"),
	})
	if err != nil {
		t.Fatalf("plan failed: %v", err)
	}
	rels := relatives(rec)
	if containsSuffix(rels, "leak.txt") {
		t.Errorf("SECURITY: an escaping symlink was included and would be exfiltrated: %v", rels)
	}
	if !containsSuffix(rels, "normal.txt") {
		t.Errorf("the real file should still be backed up: %v", rels)
	}
	if rec.SkippedSymlinks != 1 {
		t.Errorf("expected 1 skipped symlink (visible, not silent), got %d", rec.SkippedSymlinks)
	}
}

func TestGeneratePlan_FollowsInTreeSymlinkInsideAllowedRoots(t *testing.T) {
	tmp := realTempDir(t)
	src := filepath.Join(tmp, "src")
	os.MkdirAll(src, 0o755)
	os.WriteFile(filepath.Join(src, "real.txt"), []byte("data"), 0o644)
	mustSymlink(t, filepath.Join(src, "real.txt"), filepath.Join(src, "link.txt")) // stays in-scope

	rec, err := allowlistedCoord(t, src).generatePlan(context.Background(), transport.BackupRequest{
		PlanID:     "plan-1",
		SourceDirs: []string{src},
		DestRoot:   filepath.Join(tmp, "dest"),
	})
	if err != nil {
		t.Fatalf("plan failed: %v", err)
	}
	if rec.SkippedSymlinks != 0 {
		t.Errorf("an in-scope symlink should not be skipped, got %d skipped", rec.SkippedSymlinks)
	}
	if rec.TotalFiles != 2 {
		t.Errorf("expected real.txt + the in-scope link.txt = 2 files, got %d", rec.TotalFiles)
	}
}

func TestGeneratePlan_NoAllowlist_SkipsInTreeSymlinks(t *testing.T) {
	tmp := realTempDir(t)
	src := filepath.Join(tmp, "src")
	outside := filepath.Join(tmp, "outside")
	os.MkdirAll(src, 0o755)
	os.MkdirAll(outside, 0o755)
	os.WriteFile(filepath.Join(src, "normal.txt"), []byte("ok"), 0o644)
	os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("SECRET"), 0o644)
	mustSymlink(t, filepath.Join(outside, "secret.txt"), filepath.Join(src, "leak.txt"))

	// No allowlist configured: the canonical src root is accepted, but symlinks
	// can't be vouched for, so they are skipped rather than followed.
	log, _ := logging.New(logging.Options{Level: "error"})
	coord := NewCoordinator(&config.Config{}, log, noopEmitter{})
	rec, err := coord.generatePlan(context.Background(), transport.BackupRequest{
		PlanID:     "plan-1",
		SourceDirs: []string{src},
		DestRoot:   filepath.Join(tmp, "dest"),
	})
	if err != nil {
		t.Fatalf("plan failed: %v", err)
	}
	rels := relatives(rec)
	if containsSuffix(rels, "leak.txt") {
		t.Errorf("SECURITY: a symlink was followed with no allowlist to vouch for it: %v", rels)
	}
	if !containsSuffix(rels, "normal.txt") {
		t.Errorf("the real file should still be backed up: %v", rels)
	}
	if rec.SkippedSymlinks != 1 {
		t.Errorf("expected 1 skipped symlink, got %d", rec.SkippedSymlinks)
	}
}
