package dirbrowse

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestValidateAbsoluteDirPath(t *testing.T) {
	if _, err := ValidateAbsoluteDirPath(""); err == nil {
		t.Fatalf("expected error for empty path")
	}
	if _, err := ValidateAbsoluteDirPath("relative/path"); err == nil {
		t.Fatalf("expected error for relative path")
	}
	if _, err := ValidateAbsoluteDirPath("/tmp/../etc"); err == nil {
		t.Fatalf("expected error for traversal path")
	}
	if _, err := ValidateAbsoluteDirPath("/tmp/\x00x"); err == nil {
		t.Fatalf("expected error for NUL byte")
	}

	if runtime.GOOS != "windows" {
		got, err := ValidateAbsoluteDirPath("/tmp//x/./y")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "/tmp/x/y" {
			t.Fatalf("expected cleaned path, got %q", got)
		}
	}
}

func TestEnforceAllowedRoots(t *testing.T) {
	if err := EnforceAllowedRoots("/tmp/x", nil); err != nil {
		t.Fatalf("expected unrestricted to allow, got %v", err)
	}
	if err := EnforceAllowedRoots("/tmp/x", []string{"/tmp"}); err != nil {
		t.Fatalf("expected allowed, got %v", err)
	}
	if err := EnforceAllowedRoots("/etc/passwd", []string{"/tmp"}); err == nil {
		t.Fatalf("expected disallowed path to error")
	}
}

func TestListLocal_SortingAndTypes(t *testing.T) {
	tmp := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmp, "bdir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(tmp, "adir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "cfile.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "afile.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res, err := ListLocal(ctx, tmp, 0, 0)
	if err != nil {
		t.Fatalf("ListLocal error: %v", err)
	}
	if len(res.Entries) < 4 {
		t.Fatalf("expected at least 4 entries, got %d", len(res.Entries))
	}
	// dirs first, then files, both sorted by name
	if res.Entries[0].Type != "dir" || res.Entries[0].Name != "adir" {
		t.Fatalf("expected first entry adir dir, got %+v", res.Entries[0])
	}
	if res.Entries[1].Type != "dir" || res.Entries[1].Name != "bdir" {
		t.Fatalf("expected second entry bdir dir, got %+v", res.Entries[1])
	}
	if res.Entries[2].Type != "file" || res.Entries[2].Name != "afile.txt" {
		t.Fatalf("expected third entry afile.txt file, got %+v", res.Entries[2])
	}
	if res.Entries[3].Type != "file" || res.Entries[3].Name != "cfile.txt" {
		t.Fatalf("expected fourth entry cfile.txt file, got %+v", res.Entries[3])
	}
}

func TestListLocal_EntryLimitTruncates(t *testing.T) {
	tmp := t.TempDir()
	for i := 0; i < 10; i++ {
		if err := os.WriteFile(filepath.Join(tmp, "f"+string(rune('a'+i))+".txt"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res, err := ListLocal(ctx, tmp, 3, 0)
	if err != nil {
		t.Fatalf("ListLocal error: %v", err)
	}
	if len(res.Entries) != 3 {
		t.Fatalf("expected 3 entries due to maxEntries, got %d", len(res.Entries))
	}
	if !res.Truncated {
		t.Fatalf("expected Truncated=true")
	}
}
