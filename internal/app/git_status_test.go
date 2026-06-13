package app

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestCountNonEmptyLines(t *testing.T) {
	cases := map[string]int{
		"":                  0,
		"\n\n":              0,
		" M a.txt\n":        1,
		"?? x\n M y\n\n A z": 3,
	}
	for in, want := range cases {
		if got := countNonEmptyLines(in); got != want {
			t.Errorf("countNonEmptyLines(%q) = %d, want %d", in, got, want)
		}
	}
}

// initRepo creates a git repo in dir with one committed file, returning the
// branch name. Skips the test if git isn't on PATH.
func initRepo(t *testing.T, dir string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-b", "main")
	if err := os.WriteFile(filepath.Join(dir, "committed.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-m", "init")
}

func TestRunGit_BranchAndDirtyCount(t *testing.T) {
	dir := t.TempDir()
	initRepo(t, dir)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	branch, err := runGit(ctx, dir, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		t.Fatalf("rev-parse: %v", err)
	}
	if got := trimSpace(branch); got != "main" {
		t.Errorf("branch = %q, want main", got)
	}

	// Clean tree: porcelain is empty.
	status, err := runGit(ctx, dir, "status", "--porcelain")
	if err != nil {
		t.Fatal(err)
	}
	if n := countNonEmptyLines(status); n != 0 {
		t.Errorf("clean dirty count = %d, want 0", n)
	}

	// Add an untracked + a modified file → 2 dirty entries.
	if err := os.WriteFile(filepath.Join(dir, "committed.txt"), []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "new.txt"), []byte("n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	status, err = runGit(ctx, dir, "status", "--porcelain")
	if err != nil {
		t.Fatal(err)
	}
	if n := countNonEmptyLines(status); n != 2 {
		t.Errorf("dirty count = %d, want 2 (porcelain: %q)", n, status)
	}
}

func TestRunGit_NonRepoErrors(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := runGit(ctx, dir, "rev-parse", "--abbrev-ref", "HEAD"); err == nil {
		t.Error("expected error running git in a non-repo dir")
	}
}

func trimSpace(s string) string {
	// local tiny helper to avoid importing strings just for the test
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	for len(s) > 0 && (s[0] == '\n' || s[0] == ' ' || s[0] == '\t' || s[0] == '\r') {
		s = s[1:]
	}
	return s
}
