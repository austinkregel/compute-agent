package backup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/austinkregel/compute-agent/pkg/config"
	"github.com/austinkregel/compute-agent/pkg/logging"
	"github.com/austinkregel/compute-agent/pkg/transport"
)

type noopEmitter struct{}

func (noopEmitter) Emit(string, any) error { return nil }

// realTempDir is t.TempDir() resolved through symlinks. On macOS the temp root
// lives under /var -> /private/var, so a raw t.TempDir() path resolves through a
// symlinked ancestor — which validateSourceDir correctly refuses. Real backup
// sources on a server are canonical paths, so the tests use canonical temp dirs
// to assert their actual intent (copy/plan/allowlist), not the symlink guard.
func realTempDir(t *testing.T) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks(tempdir): %v", err)
	}
	return real
}

func TestGeneratePlan(t *testing.T) {
	tmp := realTempDir(t)
	src := filepath.Join(tmp, "src")
	dest := filepath.Join(tmp, "dest")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "keep.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	skipDir := filepath.Join(src, "skip")
	if err := os.Mkdir(skipDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skipDir, "ignore.txt"), []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}

	log, err := logging.New(logging.Options{Level: "error"})
	if err != nil {
		t.Fatalf("log init: %v", err)
	}
	coord := NewCoordinator(&config.Config{}, log, noopEmitter{})
	req := transport.BackupRequest{
		PlanID:      "plan-1",
		SourceDirs:  []string{src},
		DestRoot:    dest,
		IgnoreGlobs: []string{"*/skip/*"},
	}
	rec, err := coord.generatePlan(context.Background(), req)
	if err != nil {
		t.Fatalf("plan failed: %v", err)
	}
	if rec.TotalFiles != 1 {
		t.Fatalf("expected 1 file, got %d", rec.TotalFiles)
	}
	if len(rec.Files) != 1 {
		t.Fatalf("expected tracked files, got %d", len(rec.Files))
	}
	if rec.Files[0].Relative == "" {
		t.Fatalf("expected relative path to be set")
	}
}

func TestGeneratePlan_MultipleSourceDirs(t *testing.T) {
	tmp := realTempDir(t)
	src1 := filepath.Join(tmp, "src1")
	src2 := filepath.Join(tmp, "src2")
	dest := filepath.Join(tmp, "dest")

	os.Mkdir(src1, 0o755)
	os.Mkdir(src2, 0o755)
	os.WriteFile(filepath.Join(src1, "file1.txt"), []byte("content1"), 0o644)
	os.WriteFile(filepath.Join(src2, "file2.txt"), []byte("content2"), 0o644)

	log, _ := logging.New(logging.Options{Level: "error"})
	coord := NewCoordinator(&config.Config{}, log, noopEmitter{})
	req := transport.BackupRequest{
		PlanID:     "plan-1",
		SourceDirs: []string{src1, src2},
		DestRoot:   dest,
	}

	rec, err := coord.generatePlan(context.Background(), req)
	if err != nil {
		t.Fatalf("plan failed: %v", err)
	}

	if rec.TotalFiles != 2 {
		t.Errorf("expected 2 files, got %d", rec.TotalFiles)
	}
	if rec.TotalBytes != 16 { // 8 bytes each
		t.Errorf("expected 16 bytes, got %d", rec.TotalBytes)
	}
}

func TestGeneratePlan_NestedDirectories(t *testing.T) {
	tmp := realTempDir(t)
	src := filepath.Join(tmp, "src")
	dest := filepath.Join(tmp, "dest")

	os.MkdirAll(filepath.Join(src, "level1", "level2"), 0o755)
	os.WriteFile(filepath.Join(src, "root.txt"), []byte("root"), 0o644)
	os.WriteFile(filepath.Join(src, "level1", "file1.txt"), []byte("level1"), 0o644)
	os.WriteFile(filepath.Join(src, "level1", "level2", "file2.txt"), []byte("level2"), 0o644)

	log, _ := logging.New(logging.Options{Level: "error"})
	coord := NewCoordinator(&config.Config{}, log, noopEmitter{})
	req := transport.BackupRequest{
		PlanID:     "plan-1",
		SourceDirs: []string{src},
		DestRoot:   dest,
	}

	rec, err := coord.generatePlan(context.Background(), req)
	if err != nil {
		t.Fatalf("plan failed: %v", err)
	}

	if rec.TotalFiles != 3 {
		t.Errorf("expected 3 files, got %d", rec.TotalFiles)
	}
}

func TestGeneratePlan_IgnoreGlobs(t *testing.T) {
	tmp := realTempDir(t)
	src := filepath.Join(tmp, "src")
	dest := filepath.Join(tmp, "dest")

	os.Mkdir(src, 0o755)
	os.WriteFile(filepath.Join(src, "keep.txt"), []byte("keep"), 0o644)
	os.WriteFile(filepath.Join(src, "ignore.log"), []byte("ignore"), 0o644)
	os.WriteFile(filepath.Join(src, "also.log"), []byte("also"), 0o644)

	log, _ := logging.New(logging.Options{Level: "error"})
	coord := NewCoordinator(&config.Config{}, log, noopEmitter{})
	req := transport.BackupRequest{
		PlanID:      "plan-1",
		SourceDirs:  []string{src},
		DestRoot:    dest,
		IgnoreGlobs: []string{"**/*.log"},
	}

	rec, err := coord.generatePlan(context.Background(), req)
	if err != nil {
		t.Fatalf("plan failed: %v", err)
	}

	if rec.TotalFiles != 1 {
		t.Errorf("expected 1 file after ignore, got %d", rec.TotalFiles)
	}
	// Check that the remaining file is keep.txt
	found := false
	for _, f := range rec.Files {
		if f.Relative == "src/keep.txt" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'src/keep.txt' to be in files, got %v", rec.Files)
	}
}

func TestGeneratePlan_SampleLimit(t *testing.T) {
	tmp := realTempDir(t)
	src := filepath.Join(tmp, "src")
	dest := filepath.Join(tmp, "dest")

	os.Mkdir(src, 0o755)
	// Create 30 files with unique names
	for i := 0; i < 30; i++ {
		filename := filepath.Join(src, "file"+string(rune('a'+i%26))+string(rune('a'+i/26))+".txt")
		os.WriteFile(filename, []byte("data"), 0o644)
	}

	log, _ := logging.New(logging.Options{Level: "error"})
	coord := NewCoordinator(&config.Config{}, log, noopEmitter{})
	req := transport.BackupRequest{
		PlanID:     "plan-1",
		SourceDirs: []string{src},
		DestRoot:   dest,
	}

	rec, err := coord.generatePlan(context.Background(), req)
	if err != nil {
		t.Fatalf("plan failed: %v", err)
	}

	if rec.TotalFiles != 30 {
		t.Errorf("expected 30 files, got %d", rec.TotalFiles)
	}
	if len(rec.Sample) != 25 {
		t.Errorf("expected sample size 25, got %d", len(rec.Sample))
	}
}

func TestGeneratePlan_NoSourceDirs(t *testing.T) {
	log, _ := logging.New(logging.Options{Level: "error"})
	coord := NewCoordinator(&config.Config{}, log, noopEmitter{})
	req := transport.BackupRequest{
		PlanID:     "plan-1",
		SourceDirs: []string{},
		DestRoot:   "/dest",
	}

	_, err := coord.generatePlan(context.Background(), req)
	if err == nil {
		t.Error("expected error for no source directories")
	}
}

func TestGeneratePlan_EmptyDestRoot(t *testing.T) {
	tmp := realTempDir(t)
	src := filepath.Join(tmp, "src")
	os.Mkdir(src, 0o755)

	log, _ := logging.New(logging.Options{Level: "error"})
	coord := NewCoordinator(&config.Config{}, log, noopEmitter{})
	req := transport.BackupRequest{
		PlanID:     "plan-1",
		SourceDirs: []string{src},
		DestRoot:   "",
	}

	_, err := coord.generatePlan(context.Background(), req)
	if err == nil {
		t.Error("expected error for empty destRoot")
	}
}

func TestGeneratePlan_RemoteHost(t *testing.T) {
	tmp := realTempDir(t)
	src := filepath.Join(tmp, "src")
	os.Mkdir(src, 0o755)

	log, _ := logging.New(logging.Options{Level: "error"})
	coord := NewCoordinator(&config.Config{}, log, noopEmitter{})
	req := transport.BackupRequest{
		PlanID:     "plan-1",
		Host:       "remote.example.com",
		SourceDirs: []string{src},
		DestRoot:   "/dest",
	}

	_, err := coord.generatePlan(context.Background(), req)
	if err != nil {
		t.Fatalf("expected remote host plan to succeed, got err: %v", err)
	}
}

func TestPlan_EmitsEvent(t *testing.T) {
	tmp := realTempDir(t)
	src := filepath.Join(tmp, "src")
	dest := filepath.Join(tmp, "dest")
	os.Mkdir(src, 0o755)
	os.WriteFile(filepath.Join(src, "file.txt"), []byte("data"), 0o644)

	events := make([]string, 0)
	emitter := &testEmitter{
		emitFunc: func(event string, payload any) error {
			events = append(events, event)
			return nil
		},
	}

	log, _ := logging.New(logging.Options{Level: "error"})
	coord := NewCoordinator(&config.Config{}, log, emitter)
	req := transport.BackupRequest{
		PlanID:     "plan-1",
		SourceDirs: []string{src},
		DestRoot:   dest,
	}

	err := coord.Plan(context.Background(), req)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}

	if len(events) != 1 || events[0] != "backup_plan" {
		t.Errorf("expected 'backup_plan' event, got %v", events)
	}
}

func TestRun_UnknownPlan(t *testing.T) {
	log, _ := logging.New(logging.Options{Level: "error"})
	coord := NewCoordinator(&config.Config{}, log, noopEmitter{})
	req := transport.BackupRequest{
		PlanID:     "unknown-plan",
		SourceDirs: []string{"/src"},
		DestRoot:   "/dest",
	}

	err := coord.Run(context.Background(), req)
	if err == nil {
		t.Error("expected error for unknown plan")
	}
}

func TestBackup_PathTraversal_Blocked(t *testing.T) {
	tmp := realTempDir(t)
	src := filepath.Join(tmp, "src")
	dest := filepath.Join(tmp, "dest")
	outside := filepath.Join(tmp, "outside.txt")

	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	srcFile := filepath.Join(src, "file.txt")
	if err := os.WriteFile(srcFile, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	log, _ := logging.New(logging.Options{Level: "error"})
	coord := NewCoordinator(&config.Config{}, log, noopEmitter{})

	// Simulate a poisoned plan record (e.g., malformed Relative path) that would
	// attempt to escape DestRoot during Run().
	coord.jobs.Store("plan-evil", &jobRecord{
		Request: transport.BackupRequest{
			PlanID:     "plan-evil",
			SourceDirs: []string{src},
			DestRoot:   dest,
		},
		Files: []fileEntry{{
			Source:   srcFile,
			Relative: "../../outside.txt",
			Size:     4,
		}},
		TotalFiles: 1,
		TotalBytes: 4,
	})

	err := coord.Run(context.Background(), transport.BackupRequest{
		PlanID:   "plan-evil",
		DestRoot: dest,
	})
	if err == nil {
		t.Fatalf("expected path traversal attempt to be blocked")
	}
	if _, statErr := os.Stat(outside); statErr == nil {
		t.Fatalf("expected outside file to not be created: %s", outside)
	}
}

func TestBackup_SourcePathTraversal_Blocked(t *testing.T) {
	tmp := realTempDir(t)
	allowedRoot := filepath.Join(tmp, "allowed")
	forbiddenRoot := filepath.Join(tmp, "forbidden")
	link := filepath.Join(tmp, "link-to-forbidden")
	dest := filepath.Join(tmp, "dest")

	if err := os.MkdirAll(allowedRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(forbiddenRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(forbiddenRoot, "secret.txt"), []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(forbiddenRoot, link); err != nil {
		t.Skipf("symlink not supported on this platform: %v", err)
	}

	log, _ := logging.New(logging.Options{Level: "error"})
	coord := NewCoordinator(&config.Config{}, log, noopEmitter{})

	// SourceDir is a symlink that points outside any intended allowed root.
	_, err := coord.generatePlan(context.Background(), transport.BackupRequest{
		PlanID:     "plan-1",
		SourceDirs: []string{link},
		DestRoot:   dest,
	})
	if err == nil {
		t.Fatalf("expected symlink source dir to be blocked")
	}
}

func TestRun_CopiesFiles(t *testing.T) {
	tmp := realTempDir(t)
	src := filepath.Join(tmp, "src")
	dest := filepath.Join(tmp, "dest")
	os.Mkdir(src, 0o755)
	os.WriteFile(filepath.Join(src, "file1.txt"), []byte("content1"), 0o644)
	os.WriteFile(filepath.Join(src, "file2.txt"), []byte("content2"), 0o644)

	events := make([]string, 0)
	emitter := &testEmitter{
		emitFunc: func(event string, payload any) error {
			events = append(events, event)
			return nil
		},
	}

	log, _ := logging.New(logging.Options{Level: "error"})
	coord := NewCoordinator(&config.Config{}, log, emitter)
	req := transport.BackupRequest{
		PlanID:     "plan-1",
		SourceDirs: []string{src},
		DestRoot:   dest,
	}

	// Generate plan first
	err := coord.Plan(context.Background(), req)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}

	// Run backup
	err = coord.Run(context.Background(), req)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// Verify files were copied
	if _, err := os.Stat(filepath.Join(dest, "src", "file1.txt")); err != nil {
		t.Errorf("file1.txt not copied: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "src", "file2.txt")); err != nil {
		t.Errorf("file2.txt not copied: %v", err)
	}

	// Verify content
	data1, _ := os.ReadFile(filepath.Join(dest, "src", "file1.txt"))
	if string(data1) != "content1" {
		t.Errorf("file1.txt content mismatch: got %q", string(data1))
	}

	// Verify events
	if len(events) < 3 {
		t.Errorf("expected at least 3 events (plan + progress + complete), got %d", len(events))
	}
	hasComplete := false
	for _, e := range events {
		if e == "backup_complete" {
			hasComplete = true
			break
		}
	}
	if !hasComplete {
		t.Error("expected 'backup_complete' event")
	}
}

func TestRun_ProgressReporting(t *testing.T) {
	tmp := realTempDir(t)
	src := filepath.Join(tmp, "src")
	dest := filepath.Join(tmp, "dest")
	os.Mkdir(src, 0o755)
	os.WriteFile(filepath.Join(src, "file1.txt"), []byte("data1"), 0o644)
	os.WriteFile(filepath.Join(src, "file2.txt"), []byte("data2"), 0o644)

	progressEvents := 0
	emitter := &testEmitter{
		emitFunc: func(event string, payload any) error {
			if event == "backup_progress" {
				progressEvents++
			}
			return nil
		},
	}

	log, _ := logging.New(logging.Options{Level: "error"})
	coord := NewCoordinator(&config.Config{}, log, emitter)
	req := transport.BackupRequest{
		PlanID:     "plan-1",
		SourceDirs: []string{src},
		DestRoot:   dest,
	}

	err := coord.Plan(context.Background(), req)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}

	err = coord.Run(context.Background(), req)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if progressEvents < 2 {
		t.Errorf("expected at least 2 progress events, got %d", progressEvents)
	}
}

func TestRun_ContextCancellation(t *testing.T) {
	tmp := realTempDir(t)
	src := filepath.Join(tmp, "src")
	dest := filepath.Join(tmp, "dest")
	os.Mkdir(src, 0o755)
	os.WriteFile(filepath.Join(src, "file.txt"), []byte("data"), 0o644)

	log, _ := logging.New(logging.Options{Level: "error"})
	coord := NewCoordinator(&config.Config{}, log, noopEmitter{})
	req := transport.BackupRequest{
		PlanID:     "plan-1",
		SourceDirs: []string{src},
		DestRoot:   dest,
	}

	err := coord.Plan(context.Background(), req)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err = coord.Run(ctx, req)
	if err == nil {
		t.Error("expected error from cancelled context")
	}
}

func TestCopyFile_UsesRestrictivePermissions(t *testing.T) {
	tmp := realTempDir(t)
	src := filepath.Join(tmp, "source.txt")
	dest := filepath.Join(tmp, "dest.txt")

	os.WriteFile(src, []byte("content"), 0o755) // Executable

	err := copyFile(src, dest)
	if err != nil {
		t.Fatalf("copyFile failed: %v", err)
	}

	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("stat dest: %v", err)
	}

	mode := info.Mode().Perm()
	if mode != 0o600 {
		t.Errorf("expected permissions 0600, got %o", mode)
	}
}

func TestBackup_FilePermissions_Secure(t *testing.T) {
	tmp := realTempDir(t)
	src := filepath.Join(tmp, "source.txt")
	dest := filepath.Join(tmp, "destdir", "sub", "dest.txt")

	if err := os.WriteFile(src, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := copyFile(src, dest); err != nil {
		t.Fatalf("copyFile failed: %v", err)
	}

	// File should not be world/group readable.
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("stat dest: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("expected dest permissions 0600, got %o", got)
	}

	// Newly created directories should be restrictive as well.
	dirInfo, err := os.Stat(filepath.Dir(dest))
	if err != nil {
		t.Fatalf("stat dest dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("expected dest dir permissions 0700, got %o", got)
	}
}

func TestNormalizeGlobsAndMatchesAny(t *testing.T) {
	globs := normalizeGlobs([]string{"", "  ", "**/*.log", " tmp/** "})
	if len(globs) != 2 {
		t.Fatalf("expected 2 normalized globs, got %d: %v", len(globs), globs)
	}

	if !matchesAny("a/b/c.log", []string{"**/*.log"}) {
		t.Fatalf("expected path to match glob")
	}
	if matchesAny("a/b/c.txt", []string{"**/*.log"}) {
		t.Fatalf("expected path to not match glob")
	}
}

func TestParseInt64WithCommas(t *testing.T) {
	got, err := parseInt64WithCommas("  1,234,567 ")
	if err != nil {
		t.Fatalf("parseInt64WithCommas error: %v", err)
	}
	if got != 1234567 {
		t.Fatalf("parseInt64WithCommas got %d want %d", got, 1234567)
	}
}

func TestMaxHelpers(t *testing.T) {
	if got := max(1, 2); got != 2 {
		t.Fatalf("max(1,2)=%d want 2", got)
	}
	if got := max(5, 2); got != 5 {
		t.Fatalf("max(5,2)=%d want 5", got)
	}
	if got := max64(1, 2); got != 2 {
		t.Fatalf("max64(1,2)=%d want 2", got)
	}
	if got := max64(5, 2); got != 5 {
		t.Fatalf("max64(5,2)=%d want 5", got)
	}
}

func TestSanitizePlanID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"plan-123", "plan-123"},
		{"plan_456", "plan_456"},
		{"plan.789", "plan.789"},
		{"Plan-ABC", "Plan-ABC"},
		{"plan with spaces", "plan_with_spaces"},
		{"plan/with/slashes", "plan_with_slashes"},
		{"plan:with:colons", "plan_with_colons"},
		{"", "unknown"},
		{"   ", "unknown"},
		// The regex replaces consecutive non-allowed chars with a single underscore
		{"plan<>|?*", "plan_"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizePlanID(tt.input)
			if got != tt.want {
				t.Errorf("sanitizePlanID(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSafeJoin(t *testing.T) {
	tmp := realTempDir(t)

	tests := []struct {
		name     string
		destRoot string
		relative string
		wantErr  bool
	}{
		{"simple relative", tmp, "file.txt", false},
		{"nested relative", tmp, "subdir/file.txt", false},
		{"traversal blocked", tmp, "../outside.txt", true},
		{"absolute path blocked", tmp, "/etc/passwd", true},
		{"double traversal", tmp, "sub/../../../etc", true},
		{"empty relative", tmp, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := safeJoin(tt.destRoot, tt.relative)
			if (err != nil) != tt.wantErr {
				t.Errorf("safeJoin(%q, %q) error = %v, wantErr %v", tt.destRoot, tt.relative, err, tt.wantErr)
			}
		})
	}
}

func TestIsWithin(t *testing.T) {
	tests := []struct {
		name   string
		root   string
		target string
		want   bool
	}{
		{"same path", "/tmp", "/tmp", true},
		{"child path", "/tmp", "/tmp/subdir", true},
		{"deep child", "/tmp", "/tmp/a/b/c/d", true},
		{"sibling path", "/tmp", "/var", false},
		{"parent path", "/tmp/subdir", "/tmp", false},
		{"traversal escape", "/tmp", "/tmp/../etc", false},
		{"root", "/", "/any/path", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isWithin(tt.root, tt.target)
			if got != tt.want {
				t.Errorf("isWithin(%q, %q) = %v, want %v", tt.root, tt.target, got, tt.want)
			}
		})
	}
}

func TestMatchesAny(t *testing.T) {
	tests := []struct {
		path  string
		globs []string
		want  bool
	}{
		{"path/to/file.log", []string{"**/*.log"}, true},
		{"path/to/file.txt", []string{"**/*.log"}, false},
		{"node_modules/pkg/index.js", []string{"**/node_modules/**"}, true},
		{"src/app.js", []string{"**/node_modules/**"}, false},
		{"path/to/file.txt", []string{}, false},
		{".git/config", []string{"**/.git/**"}, true},
		{"file.txt", []string{"*.txt"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			globs := normalizeGlobs(tt.globs)
			got := matchesAny(tt.path, globs)
			if got != tt.want {
				t.Errorf("matchesAny(%q, %v) = %v, want %v", tt.path, tt.globs, got, tt.want)
			}
		})
	}
}

func TestCopyFileWithProgress(t *testing.T) {
	tmp := realTempDir(t)
	src := filepath.Join(tmp, "source.txt")
	dest := filepath.Join(tmp, "dest.txt")
	content := []byte("Hello, this is test content for copying!")

	if err := os.WriteFile(src, content, 0o644); err != nil {
		t.Fatal(err)
	}

	var progressCalls int
	var lastCopied int64
	var lastDone bool

	err := copyFileWithProgress(context.Background(), src, dest, func(copied int64, done bool) {
		progressCalls++
		lastCopied = copied
		lastDone = done
	})
	if err != nil {
		t.Fatalf("copyFileWithProgress error: %v", err)
	}

	if progressCalls == 0 {
		t.Error("expected progress callback to be called")
	}
	if lastCopied != int64(len(content)) {
		t.Errorf("final copied = %d, want %d", lastCopied, len(content))
	}
	if !lastDone {
		t.Error("expected final callback to have done=true")
	}

	// Verify file content
	gotContent, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotContent) != string(content) {
		t.Errorf("content mismatch")
	}
}

func TestCopyFileWithProgress_ContextCancellation(t *testing.T) {
	tmp := realTempDir(t)
	src := filepath.Join(tmp, "source.txt")
	dest := filepath.Join(tmp, "dest.txt")

	// Create a larger file
	content := make([]byte, 100*1024) // 100KB
	for i := range content {
		content[i] = byte(i % 256)
	}
	if err := os.WriteFile(src, content, 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := copyFileWithProgress(ctx, src, dest, nil)
	if err == nil {
		t.Error("expected error from cancelled context")
	}
}

func TestPersistAndLoadPlan(t *testing.T) {
	log, _ := logging.New(logging.Options{Level: "error"})
	coord := NewCoordinator(&config.Config{}, log, noopEmitter{})

	tmp := realTempDir(t)
	src := filepath.Join(tmp, "src")
	dest := filepath.Join(tmp, "dest")
	os.Mkdir(src, 0o755)
	os.WriteFile(filepath.Join(src, "file.txt"), []byte("content"), 0o644)

	req := transport.BackupRequest{
		PlanID:     "test-plan-persist",
		SourceDirs: []string{src},
		DestRoot:   dest,
	}

	rec, err := coord.generatePlan(context.Background(), req)
	if err != nil {
		t.Fatalf("generatePlan: %v", err)
	}

	// Persist the plan
	if err := coord.persistPlan(req.PlanID, rec); err != nil {
		t.Fatalf("persistPlan: %v", err)
	}

	// Load the plan
	loaded, err := coord.loadPlan(req.PlanID)
	if err != nil {
		t.Fatalf("loadPlan: %v", err)
	}

	if loaded.TotalFiles != rec.TotalFiles {
		t.Errorf("TotalFiles mismatch: got %d, want %d", loaded.TotalFiles, rec.TotalFiles)
	}
	if loaded.TotalBytes != rec.TotalBytes {
		t.Errorf("TotalBytes mismatch: got %d, want %d", loaded.TotalBytes, rec.TotalBytes)
	}
}

func TestPersistProgress(t *testing.T) {
	log, _ := logging.New(logging.Options{Level: "error"})
	coord := NewCoordinator(&config.Config{}, log, noopEmitter{})

	planID := "test-plan-progress"
	err := coord.persistProgress(planID, "current_file.txt", 12345)
	if err != nil {
		t.Fatalf("persistProgress: %v", err)
	}

	// Verify the progress file was created
	progressPath := coord.progressFilePath(planID)
	if _, err := os.Stat(progressPath); os.IsNotExist(err) {
		t.Error("progress file was not created")
	}
}

func TestAtomicWriteFile(t *testing.T) {
	tmp := realTempDir(t)
	path := filepath.Join(tmp, "atomic.txt")
	content := []byte("atomic content")

	err := atomicWriteFile(path, content, 0o600)
	if err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}

	// Verify content
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// atomicWriteFile adds a newline
	if string(got) != string(content)+"\n" {
		t.Errorf("content = %q, want %q", string(got), string(content)+"\n")
	}

	// Verify permissions
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("permissions = %o, want %o", info.Mode().Perm(), 0o600)
	}
}

func TestValidateSourceDir_AllowedRoots(t *testing.T) {
	tmp := realTempDir(t)
	allowed := filepath.Join(tmp, "allowed")
	forbidden := filepath.Join(tmp, "forbidden")
	os.Mkdir(allowed, 0o755)
	os.Mkdir(forbidden, 0o755)

	log, _ := logging.New(logging.Options{Level: "error"})
	coord := NewCoordinator(&config.Config{
		Backup: config.BackupConfig{
			AllowedSourceRoots: []string{allowed},
		},
	}, log, noopEmitter{})

	// Allowed path should pass
	_, err := coord.validateSourceDir(allowed)
	if err != nil {
		t.Errorf("validateSourceDir for allowed path: %v", err)
	}

	// Forbidden path should fail
	_, err = coord.validateSourceDir(forbidden)
	if err == nil {
		t.Error("expected error for forbidden path")
	}
}

func TestIsAllowedDestRoot(t *testing.T) {
	tmp := realTempDir(t)
	allowed := filepath.Join(tmp, "allowed")
	forbidden := filepath.Join(tmp, "forbidden")
	os.Mkdir(allowed, 0o755)
	os.Mkdir(forbidden, 0o755)

	log, _ := logging.New(logging.Options{Level: "error"})
	coord := NewCoordinator(&config.Config{
		Backup: config.BackupConfig{
			AllowedDestRoots: []string{allowed},
		},
	}, log, noopEmitter{})

	if !coord.isAllowedDestRoot(allowed) {
		t.Error("expected allowed dest root to be accepted")
	}
	if !coord.isAllowedDestRoot(filepath.Join(allowed, "subdir")) {
		t.Error("expected child of allowed dest root to be accepted")
	}
	if coord.isAllowedDestRoot(forbidden) {
		t.Error("expected forbidden dest root to be rejected")
	}
}

func TestIsAllowedDestRoot_NoConfig(t *testing.T) {
	log, _ := logging.New(logging.Options{Level: "error"})

	// With nil config
	coord := NewCoordinator(nil, log, noopEmitter{})
	if !coord.isAllowedDestRoot("/any/path") {
		t.Error("expected any path to be allowed when no config")
	}

	// With empty allowlist
	coord2 := NewCoordinator(&config.Config{}, log, noopEmitter{})
	if !coord2.isAllowedDestRoot("/any/path") {
		t.Error("expected any path to be allowed when allowlist empty")
	}
}

func TestEmitError(t *testing.T) {
	var emittedEvent string
	var emittedPayload map[string]any

	emitter := &testEmitter{
		emitFunc: func(event string, payload any) error {
			emittedEvent = event
			if m, ok := payload.(map[string]any); ok {
				emittedPayload = m
			}
			return nil
		},
	}

	log, _ := logging.New(logging.Options{Level: "error"})
	coord := NewCoordinator(&config.Config{}, log, emitter)

	testErr := errors.New("test error")
	coord.emitError("plan-123", testErr)

	if emittedEvent != "backup_error" {
		t.Errorf("expected 'backup_error' event, got %q", emittedEvent)
	}
	if emittedPayload["planId"] != "plan-123" {
		t.Errorf("expected planId 'plan-123', got %v", emittedPayload["planId"])
	}
	if emittedPayload["error"] != "test error" {
		t.Errorf("expected error 'test error', got %v", emittedPayload["error"])
	}
}

func TestGeneratePlan_EmptySourceDir(t *testing.T) {
	log, _ := logging.New(logging.Options{Level: "error"})
	coord := NewCoordinator(&config.Config{}, log, noopEmitter{})
	req := transport.BackupRequest{
		PlanID:     "plan-1",
		SourceDirs: []string{"", "   "},
		DestRoot:   "/dest",
	}

	_, err := coord.generatePlan(context.Background(), req)
	if err == nil {
		t.Error("expected error for empty source dirs")
	}
}

type testEmitter struct {
	emitFunc func(string, any) error
}

func (t *testEmitter) Emit(event string, payload any) error {
	return t.emitFunc(event, payload)
}
