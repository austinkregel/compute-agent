package dirbrowse

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

func TestValidateRemoteSlashPath(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "", true},
		{"/", "/", false},
		{"/tmp//x/./y", "/tmp/x/y", false},
		{"relative/path", "", true},
		{"/tmp/../etc", "", true},
		{"/tmp/\x00x", "", true},
		{`\\server\\share`, "/server/share", false},
		{`\\tmp\\x\\y`, "/tmp/x/y", false},
	}

	for _, tt := range tests {
		got, err := validateRemoteSlashPath(tt.in)
		if (err != nil) != tt.wantErr {
			t.Fatalf("validateRemoteSlashPath(%q) err=%v wantErr=%v", tt.in, err, tt.wantErr)
		}
		if err != nil {
			continue
		}
		if got != tt.want {
			t.Fatalf("validateRemoteSlashPath(%q)=%q want %q", tt.in, got, tt.want)
		}
	}
}

func TestHostKeyCallback_PolicyHandling(t *testing.T) {
	if cb, err := hostKeyCallback("insecure_accept_any"); err != nil || cb == nil {
		t.Fatalf("expected insecure_accept_any to succeed, cb=%v err=%v", cb, err)
	}
	if _, err := hostKeyCallback("definitely-not-a-policy"); err == nil {
		t.Fatalf("expected unsupported policy to error")
	}
}

func TestListSMB_EarlyValidationErrors(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := ListSMB(ctx, SMBRequest{Host: "", Share: "sh", Path: "/"}, SMBCredentials{}, SMBOptions{})
	if err == nil {
		t.Fatalf("expected error for missing host")
	}
	_, err = ListSMB(ctx, SMBRequest{Host: "127.0.0.1", Share: "", Path: "/"}, SMBCredentials{}, SMBOptions{})
	if err == nil {
		t.Fatalf("expected error for missing share")
	}
	_, err = ListSMB(ctx, SMBRequest{Host: "127.0.0.1", Share: "sh", Path: "relative"}, SMBCredentials{}, SMBOptions{})
	if err == nil {
		t.Fatalf("expected error for invalid path")
	}
}

func TestListSSH_EarlyValidationErrors(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := ListSSH(ctx, SSHRequest{Host: "", Path: "/"}, SSHOptions{})
	if err == nil {
		t.Fatalf("expected error for missing host")
	}
	_, err = ListSSH(ctx, SSHRequest{Host: "127.0.0.1", Path: "relative"}, SSHOptions{})
	if err == nil {
		t.Fatalf("expected error for relative path")
	}
	_, err = ListSSH(ctx, SSHRequest{Host: "127.0.0.1", Path: "/tmp/../etc"}, SSHOptions{})
	if err == nil {
		t.Fatalf("expected error for traversal path")
	}
}

func TestListLocal_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := ListLocal(ctx, "/tmp", 0, 0)
	if err == nil {
		t.Fatalf("expected error from cancelled context")
	}
}

func TestListLocal_NonExistentPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := ListLocal(ctx, "/nonexistent/path/that/does/not/exist", 0, 0)
	if err == nil {
		t.Fatalf("expected error for non-existent path")
	}
}

func TestListLocal_ResponseByteLimitTruncates(t *testing.T) {
	tmp := t.TempDir()
	// Create files with long names to hit byte limit quickly
	for i := 0; i < 20; i++ {
		name := "file_with_a_somewhat_long_name_" + string(rune('a'+i)) + ".txt"
		if err := os.WriteFile(filepath.Join(tmp, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Set very low max response bytes
	res, err := ListLocal(ctx, tmp, 100, 200)
	if err != nil {
		t.Fatalf("ListLocal error: %v", err)
	}
	if !res.Truncated {
		t.Fatalf("expected Truncated=true due to byte limit")
	}
}

func TestListLocal_SymlinkToFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test not portable to Windows")
	}

	tmp := t.TempDir()
	targetFile := filepath.Join(tmp, "target.txt")
	if err := os.WriteFile(targetFile, []byte("target content"), 0o644); err != nil {
		t.Fatal(err)
	}

	symlink := filepath.Join(tmp, "link_to_file")
	if err := os.Symlink(targetFile, symlink); err != nil {
		t.Skipf("symlink creation failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	res, err := ListLocal(ctx, tmp, 0, 0)
	if err != nil {
		t.Fatalf("ListLocal error: %v", err)
	}

	// Find the symlink entry
	var foundLink *Entry
	for i := range res.Entries {
		if res.Entries[i].Name == "link_to_file" {
			foundLink = &res.Entries[i]
			break
		}
	}
	if foundLink == nil {
		t.Fatalf("expected to find symlink entry")
	}
	if !foundLink.IsSymlink {
		t.Errorf("expected IsSymlink=true for symlink")
	}
	if foundLink.Type != "file" {
		t.Errorf("expected Type=file for symlink to file, got %q", foundLink.Type)
	}
}

func TestListLocal_SymlinkToDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test not portable to Windows")
	}

	tmp := t.TempDir()
	targetDir := filepath.Join(tmp, "target_dir")
	if err := os.Mkdir(targetDir, 0o755); err != nil {
		t.Fatal(err)
	}

	symlink := filepath.Join(tmp, "link_to_dir")
	if err := os.Symlink(targetDir, symlink); err != nil {
		t.Skipf("symlink creation failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	res, err := ListLocal(ctx, tmp, 0, 0)
	if err != nil {
		t.Fatalf("ListLocal error: %v", err)
	}

	// Find the symlink entry
	var foundLink *Entry
	for i := range res.Entries {
		if res.Entries[i].Name == "link_to_dir" {
			foundLink = &res.Entries[i]
			break
		}
	}
	if foundLink == nil {
		t.Fatalf("expected to find symlink entry")
	}
	if !foundLink.IsSymlink {
		t.Errorf("expected IsSymlink=true for symlink")
	}
	if foundLink.Type != "dir" {
		t.Errorf("expected Type=dir for symlink to directory, got %q", foundLink.Type)
	}
}

func TestListLocal_BrokenSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test not portable to Windows")
	}

	tmp := t.TempDir()
	brokenLink := filepath.Join(tmp, "broken_link")
	if err := os.Symlink("/nonexistent/target", brokenLink); err != nil {
		t.Skipf("symlink creation failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	res, err := ListLocal(ctx, tmp, 0, 0)
	if err != nil {
		t.Fatalf("ListLocal error: %v", err)
	}

	// Find the broken symlink entry
	var foundLink *Entry
	for i := range res.Entries {
		if res.Entries[i].Name == "broken_link" {
			foundLink = &res.Entries[i]
			break
		}
	}
	if foundLink == nil {
		t.Fatalf("expected to find broken symlink entry")
	}
	if !foundLink.IsSymlink {
		t.Errorf("expected IsSymlink=true for broken symlink")
	}
}

func TestListLocal_EmptyDirectory(t *testing.T) {
	tmp := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	res, err := ListLocal(ctx, tmp, 0, 0)
	if err != nil {
		t.Fatalf("ListLocal error: %v", err)
	}
	if len(res.Entries) != 0 {
		t.Errorf("expected 0 entries for empty directory, got %d", len(res.Entries))
	}
	if res.Truncated {
		t.Errorf("expected Truncated=false for empty directory")
	}
}

func TestListLocal_ModeAndModTime(t *testing.T) {
	tmp := t.TempDir()
	testFile := filepath.Join(tmp, "test.txt")
	if err := os.WriteFile(testFile, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	res, err := ListLocal(ctx, tmp, 0, 0)
	if err != nil {
		t.Fatalf("ListLocal error: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(res.Entries))
	}

	entry := res.Entries[0]
	if entry.Mode == "" {
		t.Error("expected Mode to be set")
	}
	if entry.ModTime == "" {
		t.Error("expected ModTime to be set")
	}
	// ModTime should be in RFC3339 format
	if !strings.Contains(entry.ModTime, "T") || !strings.Contains(entry.ModTime, ":") {
		t.Errorf("ModTime doesn't appear to be RFC3339 format: %q", entry.ModTime)
	}
}

func TestValidateAbsoluteDirPath_MoreCases(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"whitespace only", "   ", true},
		{"just dots", ".", true},
		{"nul in middle", "/path/with\x00nul/here", true},
		{"backslash traversal", "/tmp\\..\\etc", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateAbsoluteDirPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAbsoluteDirPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestEnforceAllowedRoots_MoreCases(t *testing.T) {
	tests := []struct {
		name    string
		absPath string
		roots   []string
		wantErr bool
	}{
		{"empty roots allows all", "/any/path", nil, false},
		{"empty roots slice allows all", "/any/path", []string{}, false},
		{"exact match allowed", "/tmp", []string{"/tmp"}, false},
		{"child path allowed", "/tmp/subdir/file", []string{"/tmp"}, false},
		{"sibling path denied", "/var/log", []string{"/tmp"}, true},
		{"whitespace root ignored", "/var/log", []string{"   ", "/var"}, false},
		{"relative root ignored", "/tmp/test", []string{"relative/path", "/tmp"}, false},
		{"multiple roots - first match", "/var/log/syslog", []string{"/tmp", "/var"}, false},
		{"parent path denied", "/tmp", []string{"/tmp/subdir"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := EnforceAllowedRoots(tt.absPath, tt.roots)
			if (err != nil) != tt.wantErr {
				t.Errorf("EnforceAllowedRoots(%q, %v) error = %v, wantErr %v", tt.absPath, tt.roots, err, tt.wantErr)
			}
		})
	}
}

func TestContainsDotDotSegment(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/tmp/safe/path", false},
		{"/tmp/../etc", true},
		{"../relative", true},
		{"/path/to/..", true},
		{"/path/..hidden/file", false}, // ..hidden is NOT a traversal
		{"/path/test../file", false},   // test.. is NOT a traversal
		{"", false},
		{"/", false},
		{"..", true},
		{"...", false}, // ... is not ..
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := containsDotDotSegment(tt.path)
			if got != tt.expected {
				t.Errorf("containsDotDotSegment(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestSortEntries(t *testing.T) {
	entries := []Entry{
		{Name: "file_b.txt", Type: "file"},
		{Name: "dir_a", Type: "dir"},
		{Name: "file_a.txt", Type: "file"},
		{Name: "dir_b", Type: "dir"},
	}

	sortEntries(entries)

	// Directories first, then files, both alphabetically sorted
	expected := []struct {
		name string
		typ  string
	}{
		{"dir_a", "dir"},
		{"dir_b", "dir"},
		{"file_a.txt", "file"},
		{"file_b.txt", "file"},
	}

	for i, e := range expected {
		if entries[i].Name != e.name || entries[i].Type != e.typ {
			t.Errorf("entries[%d] = {%q, %q}, want {%q, %q}",
				i, entries[i].Name, entries[i].Type, e.name, e.typ)
		}
	}
}

func TestDefaultSSHUser(t *testing.T) {
	// This test just verifies the function doesn't panic and returns something
	user := defaultSSHUser()
	if user == "" {
		t.Error("defaultSSHUser() returned empty string")
	}
}

func TestDefaultKnownHostsPath(t *testing.T) {
	// This test verifies the function doesn't panic
	// It may return empty string if no home dir is available
	path := defaultKnownHostsPath()
	// Path should either be empty or contain .ssh/known_hosts
	if path != "" && !strings.Contains(path, "known_hosts") {
		t.Errorf("defaultKnownHostsPath() = %q, expected empty or containing 'known_hosts'", path)
	}
}
