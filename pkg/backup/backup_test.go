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

type noopEmitter struct{}

func (noopEmitter) Emit(string, any) error { return nil }

func TestGeneratePlan(t *testing.T) {
	tmp := t.TempDir()
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
	tmp := t.TempDir()
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
	tmp := t.TempDir()
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
	tmp := t.TempDir()
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
	tmp := t.TempDir()
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
	tmp := t.TempDir()
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
	tmp := t.TempDir()
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
	tmp := t.TempDir()
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
	tmp := t.TempDir()
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
	tmp := t.TempDir()
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
	tmp := t.TempDir()
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
	tmp := t.TempDir()
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
	tmp := t.TempDir()
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
	tmp := t.TempDir()
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
	tmp := t.TempDir()
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

type testEmitter struct {
	emitFunc func(string, any) error
}

func (t *testEmitter) Emit(event string, payload any) error {
	return t.emitFunc(event, payload)
}
