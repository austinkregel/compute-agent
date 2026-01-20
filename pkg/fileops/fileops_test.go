package fileops

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestValidatePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr error
	}{
		{"empty path", "", ErrEmptyPath},
		{"whitespace only", "   ", ErrEmptyPath},
		{"relative path", "relative/path", ErrNotAbsolute},
		{"dot relative", "./relative", ErrNotAbsolute},
		{"contains NUL", "/path/with\x00nul", ErrContainsNUL},
		{"path traversal at start", "../etc/passwd", ErrPathTraversal},
		{"path traversal in middle", "/home/../etc/passwd", ErrPathTraversal},
		{"path traversal at end", "/home/user/..", ErrPathTraversal},
		{"valid absolute unix", "/home/user/file.txt", nil},
		{"valid root", "/", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidatePath(tt.path)
			if tt.wantErr == nil && err != nil {
				t.Errorf("ValidatePath(%q) unexpected error: %v", tt.path, err)
			}
			if tt.wantErr != nil && err != tt.wantErr {
				t.Errorf("ValidatePath(%q) = %v, want %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestCheckPathPolicy_HardDeny(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping Unix hard deny tests on Windows")
	}

	// These paths should ALWAYS be denied, regardless of force flag
	hardDenyPaths := []string{
		"/dev",
		"/dev/null",
		"/dev/sda1",
		"/proc",
		"/proc/1/cmdline",
		"/sys",
		"/sys/class/net",
		"/run",
		"/run/lock",
	}

	for _, path := range hardDenyPaths {
		t.Run(path, func(t *testing.T) {
			// Without force
			err := CheckPathPolicy(path, false)
			if err != ErrHardDeny {
				t.Errorf("CheckPathPolicy(%q, false) = %v, want %v", path, err, ErrHardDeny)
			}

			// With force - still denied
			err = CheckPathPolicy(path, true)
			if err != ErrHardDeny {
				t.Errorf("CheckPathPolicy(%q, true) = %v, want %v", path, err, ErrHardDeny)
			}
		})
	}
}

func TestCheckPathPolicy_DangerousRequiresForce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping Unix dangerous path tests on Windows")
	}

	// These paths require force=true
	dangerousPaths := []string{
		"/bin",
		"/bin/bash",
		"/sbin",
		"/sbin/init",
		"/usr",
		"/usr/bin/ls",
		"/usr/local/bin",
		"/lib",
		"/lib/x86_64-linux-gnu",
		"/boot",
		"/boot/grub",
	}

	for _, path := range dangerousPaths {
		t.Run(path, func(t *testing.T) {
			// Without force - should fail
			err := CheckPathPolicy(path, false)
			if err != ErrDangerousPath {
				t.Errorf("CheckPathPolicy(%q, false) = %v, want %v", path, err, ErrDangerousPath)
			}

			// With force - should pass
			err = CheckPathPolicy(path, true)
			if err != nil {
				t.Errorf("CheckPathPolicy(%q, true) = %v, want nil", path, err)
			}
		})
	}
}

func TestCheckPathPolicy_SafePaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping Unix safe path tests on Windows")
	}

	// These paths should be allowed without force
	safePaths := []string{
		"/home",
		"/home/user",
		"/home/user/.config",
		"/tmp",
		"/tmp/test.txt",
		"/etc",
		"/etc/hosts",
		"/var/log",
		"/opt",
		"/opt/myapp",
	}

	for _, path := range safePaths {
		t.Run(path, func(t *testing.T) {
			err := CheckPathPolicy(path, false)
			if err != nil {
				t.Errorf("CheckPathPolicy(%q, false) = %v, want nil", path, err)
			}
		})
	}
}

func TestDeleteFile_BlocksRoot(t *testing.T) {
	// Attempting to delete root should always be blocked
	err := DeleteFile("/", false, false)
	if err != ErrDeleteRoot {
		t.Errorf("DeleteFile(\"/\", false, false) = %v, want %v", err, ErrDeleteRoot)
	}

	err = DeleteFile("/", true, true)
	if err != ErrDeleteRoot {
		t.Errorf("DeleteFile(\"/\", true, true) = %v, want %v", err, ErrDeleteRoot)
	}
}

func TestDeleteFile_BlocksHardDeny(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping Unix delete tests on Windows")
	}

	// Should not be able to delete files in /dev even with force
	err := DeleteFile("/dev/null", true, false)
	if err != ErrHardDeny {
		t.Errorf("DeleteFile(\"/dev/null\", true, false) = %v, want %v", err, ErrHardDeny)
	}
}

func TestDeleteFile_RequiresForceForDangerous(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping Unix delete tests on Windows")
	}

	// Without force, should reject dangerous path
	err := DeleteFile("/usr/bin/nonexistent", false, false)
	if err != ErrDangerousPath {
		t.Errorf("DeleteFile(\"/usr/bin/nonexistent\", false, false) = %v, want %v", err, ErrDangerousPath)
	}
}

func TestDeleteFile_NonEmptyDirectory(t *testing.T) {
	// Create a temp directory with a file
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	testFile := filepath.Join(subDir, "testfile.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	// Try to delete non-empty directory without recursive
	err := DeleteFile(subDir, false, false)
	if err != ErrDeleteNonEmpty {
		t.Errorf("DeleteFile non-empty dir without recursive = %v, want %v", err, ErrDeleteNonEmpty)
	}

	// Recursive delete requires force
	err = DeleteFile(subDir, false, true)
	if err == nil || err.Error() != "recursive delete requires force=true" {
		t.Errorf("DeleteFile recursive without force = %v, want 'recursive delete requires force=true'", err)
	}

	// Recursive delete with force should work
	err = DeleteFile(subDir, true, true)
	if err != nil {
		t.Errorf("DeleteFile recursive with force = %v, want nil", err)
	}

	// Verify directory was deleted
	if _, err := os.Stat(subDir); !os.IsNotExist(err) {
		t.Error("Directory was not deleted")
	}
}

func TestDeleteFile_RegularFile(t *testing.T) {
	// Create a temp file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "testfile.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatal(err)
	}

	// Delete should work
	err := DeleteFile(testFile, false, false)
	if err != nil {
		t.Errorf("DeleteFile regular file = %v, want nil", err)
	}

	// Verify file was deleted
	if _, err := os.Stat(testFile); !os.IsNotExist(err) {
		t.Error("File was not deleted")
	}
}

func TestChmodFile_NotSupportedOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Skipping Windows chmod test on non-Windows")
	}

	_, err := ChmodFile("/tmp/test", "0755", false)
	if err != ErrChmodWindows {
		t.Errorf("ChmodFile on Windows = %v, want %v", err, ErrChmodWindows)
	}
}

func TestChmodFile_BlocksHardDeny(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping Unix chmod tests on Windows")
	}

	_, err := ChmodFile("/dev/null", "0644", true)
	if err != ErrHardDeny {
		t.Errorf("ChmodFile(\"/dev/null\", ...) = %v, want %v", err, ErrHardDeny)
	}
}

func TestChmodFile_RequiresForceForDangerous(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping Unix chmod tests on Windows")
	}

	_, err := ChmodFile("/usr/bin/ls", "0755", false)
	if err != ErrDangerousPath {
		t.Errorf("ChmodFile(\"/usr/bin/ls\", ..., false) = %v, want %v", err, ErrDangerousPath)
	}
}

func TestChmodFile_Success(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping Unix chmod tests on Windows")
	}

	// Create a temp file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "testfile.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	// Chmod should work
	path, err := ChmodFile(testFile, "0755", false)
	if err != nil {
		t.Errorf("ChmodFile = %v, want nil", err)
	}
	if path != testFile {
		t.Errorf("ChmodFile path = %q, want %q", path, testFile)
	}

	// Verify mode was changed
	info, err := os.Stat(testFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Errorf("File mode = %o, want %o", info.Mode().Perm(), 0755)
	}
}

func TestParseMode(t *testing.T) {
	tests := []struct {
		input   string
		want    os.FileMode
		wantErr bool
	}{
		{"0644", 0644, false},
		{"0755", 0755, false},
		{"644", 0644, false},
		{"755", 0755, false},
		{"0600", 0600, false},
		{"0777", 0777, false},
		{"", 0, true},
		{"invalid", 0, true},
		{"999", 0, true},   // Invalid octal
		{"0888", 0, true},  // Invalid octal digit
		{"01000", 0, true}, // Too large
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseMode(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseMode(%q) = %o, want error", tt.input, got)
				}
			} else {
				if err != nil {
					t.Errorf("parseMode(%q) error = %v", tt.input, err)
				}
				if got != tt.want {
					t.Errorf("parseMode(%q) = %o, want %o", tt.input, got, tt.want)
				}
			}
		})
	}
}

func TestUploadManager_AtomicWrite(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "uploaded.txt")
	content := []byte("Hello, World!")

	mgr := NewUploadManager()

	// Start upload
	err := mgr.StartUpload("req1", testFile, int64(len(content)), "0644", false, true)
	if err != nil {
		t.Fatalf("StartUpload failed: %v", err)
	}

	// Verify temp file exists (and final file doesn't yet)
	if _, err := os.Stat(testFile); !os.IsNotExist(err) {
		t.Error("Final file should not exist yet")
	}

	// Write chunk
	err = mgr.WriteChunk("req1", 0, content)
	if err != nil {
		t.Fatalf("WriteChunk failed: %v", err)
	}

	// Finish upload
	path, size, err := mgr.FinishUpload("req1", "")
	if err != nil {
		t.Fatalf("FinishUpload failed: %v", err)
	}
	if path != testFile {
		t.Errorf("FinishUpload path = %q, want %q", path, testFile)
	}
	if size != int64(len(content)) {
		t.Errorf("FinishUpload size = %d, want %d", size, len(content))
	}

	// Verify file exists with correct content
	data, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(data) != string(content) {
		t.Errorf("File content = %q, want %q", string(data), string(content))
	}
}

func TestUploadManager_BlocksHardDenyPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping Unix path tests on Windows")
	}

	mgr := NewUploadManager()

	err := mgr.StartUpload("req1", "/dev/testfile", 100, "", false, true)
	if err != ErrHardDeny {
		t.Errorf("StartUpload to /dev = %v, want %v", err, ErrHardDeny)
	}
}

func TestUploadManager_RequiresForceForDangerous(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping Unix path tests on Windows")
	}

	mgr := NewUploadManager()

	// Without force
	err := mgr.StartUpload("req1", "/usr/local/bin/testfile", 100, "", false, true)
	if err != ErrDangerousPath {
		t.Errorf("StartUpload to /usr without force = %v, want %v", err, ErrDangerousPath)
	}
}

func TestUploadManager_DuplicateRequestId(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")

	mgr := NewUploadManager()

	// Start first upload
	err := mgr.StartUpload("req1", testFile, 100, "", false, true)
	if err != nil {
		t.Fatalf("First StartUpload failed: %v", err)
	}

	// Try to start another with same request ID
	err = mgr.StartUpload("req1", testFile, 100, "", false, true)
	if err != ErrUploadInProgress {
		t.Errorf("Duplicate StartUpload = %v, want %v", err, ErrUploadInProgress)
	}

	// Clean up
	mgr.CancelUpload("req1")
}

func TestUploadManager_NotFound(t *testing.T) {
	mgr := NewUploadManager()

	err := mgr.WriteChunk("nonexistent", 0, []byte("data"))
	if err != ErrUploadNotFound {
		t.Errorf("WriteChunk nonexistent = %v, want %v", err, ErrUploadNotFound)
	}

	_, _, err = mgr.FinishUpload("nonexistent", "")
	if err != ErrUploadNotFound {
		t.Errorf("FinishUpload nonexistent = %v, want %v", err, ErrUploadNotFound)
	}
}

func TestUploadManager_ChecksumVerification(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "checksum.txt")
	content := []byte("Hello, World!")
	// SHA256 of "Hello, World!"
	correctChecksum := "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
	wrongChecksum := "0000000000000000000000000000000000000000000000000000000000000000"

	mgr := NewUploadManager()

	// Upload with correct checksum
	err := mgr.StartUpload("req1", testFile, int64(len(content)), "", false, true)
	if err != nil {
		t.Fatal(err)
	}
	err = mgr.WriteChunk("req1", 0, content)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = mgr.FinishUpload("req1", correctChecksum)
	if err != nil {
		t.Errorf("FinishUpload with correct checksum = %v, want nil", err)
	}

	// Upload with wrong checksum
	err = mgr.StartUpload("req2", testFile, int64(len(content)), "", false, true)
	if err != nil {
		t.Fatal(err)
	}
	err = mgr.WriteChunk("req2", 0, content)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = mgr.FinishUpload("req2", wrongChecksum)
	if err != ErrChecksumMismatch {
		t.Errorf("FinishUpload with wrong checksum = %v, want %v", err, ErrChecksumMismatch)
	}
}

func TestUploadManager_CancelUpload(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "cancel.txt")

	mgr := NewUploadManager()

	// Start an upload
	err := mgr.StartUpload("req-cancel", testFile, 100, "", false, true)
	if err != nil {
		t.Fatal(err)
	}

	// Cancel the upload
	mgr.CancelUpload("req-cancel")

	// Trying to write to cancelled upload should fail
	err = mgr.WriteChunk("req-cancel", 0, []byte("data"))
	if err != ErrUploadNotFound {
		t.Errorf("WriteChunk after cancel = %v, want %v", err, ErrUploadNotFound)
	}

	// Cancel on non-existent request should not panic
	mgr.CancelUpload("non-existent")
}

func TestUploadManager_MultipleChunks(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "multi.txt")

	mgr := NewUploadManager()

	err := mgr.StartUpload("req-multi", testFile, 20, "", false, true)
	if err != nil {
		t.Fatal(err)
	}

	// Write chunks at different offsets
	err = mgr.WriteChunk("req-multi", 0, []byte("Hello"))
	if err != nil {
		t.Fatal(err)
	}
	err = mgr.WriteChunk("req-multi", 5, []byte(", "))
	if err != nil {
		t.Fatal(err)
	}
	err = mgr.WriteChunk("req-multi", 7, []byte("World!"))
	if err != nil {
		t.Fatal(err)
	}

	path, size, err := mgr.FinishUpload("req-multi", "")
	if err != nil {
		t.Fatalf("FinishUpload: %v", err)
	}
	if path != testFile {
		t.Errorf("path = %q, want %q", path, testFile)
	}
	if size != 13 {
		t.Errorf("size = %d, want %d", size, 13)
	}

	// Verify content
	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "Hello, World!" {
		t.Errorf("content = %q, want %q", string(content), "Hello, World!")
	}
}

func TestUploadManager_FileExistsNoOverwrite(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "exists.txt")

	// Create existing file
	if err := os.WriteFile(testFile, []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}

	mgr := NewUploadManager()

	// Without overwrite, should fail
	err := mgr.StartUpload("req1", testFile, 10, "", false, false)
	if err == nil {
		t.Error("expected error when file exists and overwrite=false")
	}
}

func TestUploadManager_CustomMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode tests not portable to Windows")
	}

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "custom_mode.txt")

	mgr := NewUploadManager()

	err := mgr.StartUpload("req-mode", testFile, 5, "0755", false, true)
	if err != nil {
		t.Fatal(err)
	}

	err = mgr.WriteChunk("req-mode", 0, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = mgr.FinishUpload("req-mode", "")
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(testFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("mode = %o, want %o", info.Mode().Perm(), 0o755)
	}
}

func TestUploadManager_InvalidMode(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "bad_mode.txt")

	mgr := NewUploadManager()

	err := mgr.StartUpload("req-badmode", testFile, 5, "invalid", false, true)
	if err != ErrInvalidMode {
		t.Errorf("StartUpload with invalid mode = %v, want %v", err, ErrInvalidMode)
	}
}

func TestDeleteFile_EmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	emptyDir := filepath.Join(tmpDir, "empty")
	if err := os.Mkdir(emptyDir, 0o755); err != nil {
		t.Fatal(err)
	}

	err := DeleteFile(emptyDir, false, false)
	if err != nil {
		t.Errorf("DeleteFile empty dir = %v, want nil", err)
	}

	if _, err := os.Stat(emptyDir); !os.IsNotExist(err) {
		t.Error("directory should have been deleted")
	}
}

func TestDeleteFile_Symlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink tests not portable to Windows")
	}

	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "target.txt")
	link := filepath.Join(tmpDir, "link")

	if err := os.WriteFile(target, []byte("target"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation failed: %v", err)
	}

	err := DeleteFile(link, false, false)
	if err != nil {
		t.Errorf("DeleteFile symlink = %v, want nil", err)
	}

	// Symlink should be deleted
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Error("symlink should have been deleted")
	}
	// Target should still exist
	if _, err := os.Stat(target); os.IsNotExist(err) {
		t.Error("target should still exist")
	}
}

func TestDeleteFile_NonExistent(t *testing.T) {
	err := DeleteFile("/path/that/does/not/exist/file.txt", false, false)
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestDeleteFile_PathValidation(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr error
	}{
		{"empty path", "", ErrEmptyPath},
		{"relative path", "relative/path", ErrNotAbsolute},
		{"path with traversal", "/tmp/../etc/passwd", ErrPathTraversal},
		{"path with NUL", "/tmp/file\x00name", ErrContainsNUL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := DeleteFile(tt.path, false, false)
			if err != tt.wantErr {
				t.Errorf("DeleteFile(%q) = %v, want %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestChmodFile_PathValidation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod not supported on Windows")
	}

	tests := []struct {
		name    string
		path    string
		wantErr error
	}{
		{"empty path", "", ErrEmptyPath},
		{"relative path", "relative/path", ErrNotAbsolute},
		{"path with traversal", "/tmp/../etc/passwd", ErrPathTraversal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ChmodFile(tt.path, "0644", false)
			if err != tt.wantErr {
				t.Errorf("ChmodFile(%q) = %v, want %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestChmodFile_InvalidMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod not supported on Windows")
	}

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		mode    string
		wantErr bool
	}{
		{"0644", false},
		{"0755", false},
		{"777", false},
		{"", true},
		{"invalid", true},
		{"999", true},
		{"0888", true},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			_, err := ChmodFile(testFile, tt.mode, false)
			if (err != nil) != tt.wantErr {
				t.Errorf("ChmodFile mode %q error = %v, wantErr %v", tt.mode, err, tt.wantErr)
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
		{"/path/..hidden/file", false},
		{"/path/test../file", false},
		{"", false},
		{"/", false},
		{"..", true},
		{"...", false},
		{`C:\Windows\..\System32`, true},
		{`C:\path\..`, true},
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

func TestValidatePath_WindowsPaths(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows path tests only run on Windows")
	}

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"valid windows path", `C:\Users\test`, false},
		{"traversal in windows path", `C:\Users\..\System`, true},
		{"unc path", `\\server\share`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidatePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestCheckPathPolicy_CaseInsensitive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping Unix path tests on Windows")
	}

	// Policy checks should be case-insensitive
	tests := []struct {
		path    string
		force   bool
		wantErr error
	}{
		{"/DEV/null", false, ErrHardDeny},
		{"/Dev/null", false, ErrHardDeny},
		{"/PROC/1/cmdline", false, ErrHardDeny},
		{"/Bin/bash", false, ErrDangerousPath},
		{"/BIN/bash", false, ErrDangerousPath},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			err := CheckPathPolicy(tt.path, tt.force)
			if err != tt.wantErr {
				t.Errorf("CheckPathPolicy(%q, %v) = %v, want %v", tt.path, tt.force, err, tt.wantErr)
			}
		})
	}
}
