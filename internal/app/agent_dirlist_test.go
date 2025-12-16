package app

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/austinkregel/compute-agent/pkg/config"
	"github.com/austinkregel/compute-agent/pkg/logging"
	"github.com/austinkregel/compute-agent/pkg/transport"
)

func TestBuildDirListResponse_Local_SuccessAndSorting(t *testing.T) {
	tmp := t.TempDir()
	_ = os.Mkdir(filepath.Join(tmp, "bdir"), 0o755)
	_ = os.Mkdir(filepath.Join(tmp, "adir"), 0o755)
	_ = os.WriteFile(filepath.Join(tmp, "b.txt"), []byte("b"), 0o644)
	_ = os.WriteFile(filepath.Join(tmp, "a.txt"), []byte("a"), 0o644)

	a := newTestAgentForDirList(t, &config.Config{ClientID: "cid", DirBrowse: config.DirBrowseConfig{AllowedRoots: []string{tmp}}})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp := a.buildDirListResponse(ctx, transport.DirListRequest{Mode: "local", RequestID: "r1", Path: tmp})
	if resp.Error != "" {
		t.Fatalf("unexpected error: %s", resp.Error)
	}
	if resp.ClientID != "cid" {
		t.Fatalf("expected clientID cid, got %q", resp.ClientID)
	}
	if resp.Path != tmp {
		t.Fatalf("expected normalized path %q, got %q", tmp, resp.Path)
	}
	if len(resp.Entries) < 4 {
		t.Fatalf("expected entries, got %d", len(resp.Entries))
	}
	// dirs first then files; within each group lexicographic
	if resp.Entries[0].Type != "dir" || resp.Entries[0].Name != "adir" {
		t.Fatalf("expected first entry adir dir, got %+v", resp.Entries[0])
	}
	if resp.Entries[1].Type != "dir" || resp.Entries[1].Name != "bdir" {
		t.Fatalf("expected second entry bdir dir, got %+v", resp.Entries[1])
	}
}

func TestBuildDirListResponse_Local_DisallowedRoot(t *testing.T) {
	tmp := t.TempDir()
	other := t.TempDir()
	a := newTestAgentForDirList(t, &config.Config{ClientID: "cid", DirBrowse: config.DirBrowseConfig{AllowedRoots: []string{other}}})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp := a.buildDirListResponse(ctx, transport.DirListRequest{Mode: "local", RequestID: "r1", Path: tmp})
	if resp.Error == "" {
		t.Fatalf("expected error")
	}
}

func TestBuildDirListResponse_Local_InvalidPath(t *testing.T) {
	a := newTestAgentForDirList(t, &config.Config{ClientID: "cid"})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp := a.buildDirListResponse(ctx, transport.DirListRequest{Mode: "local", RequestID: "r1", Path: "relative/path"})
	if resp.Error == "" {
		t.Fatalf("expected error")
	}
}

func TestBuildDirListResponse_Remote_EarlyErrors(t *testing.T) {
	a := newTestAgentForDirList(t, &config.Config{ClientID: "cid"})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp := a.buildDirListResponse(ctx, transport.DirListRequest{Mode: "remote", RequestID: "r1", Path: "/"})
	if resp.Error == "" {
		t.Fatalf("expected missing host error")
	}

	resp2 := a.buildDirListResponse(ctx, transport.DirListRequest{Mode: "remote", RequestID: "r2", Host: "h", Protocol: "smb"})
	if resp2.Error == "" {
		t.Fatalf("expected missing share/profile error")
	}

	resp3 := a.buildDirListResponse(ctx, transport.DirListRequest{Mode: "remote", RequestID: "r3", Host: "h", Protocol: "smb", Share: "sh", Profile: "nope"})
	if resp3.Error != "unknown smb profile" {
		t.Fatalf("expected unknown smb profile error, got %q", resp3.Error)
	}

	resp4 := a.buildDirListResponse(ctx, transport.DirListRequest{Mode: "remote", RequestID: "r4", Host: "h", Protocol: "nope"})
	if resp4.Error == "" {
		t.Fatalf("expected unsupported protocol error")
	}
}

func TestHandleLogTailStartStop_Guardrails(t *testing.T) {
	// Use empty log path so tailer goroutine exits immediately.
	a := newTestAgentForDirList(t, &config.Config{ClientID: "cid", Logging: config.LoggingConfig{FilePath: ""}})

	a.handleLogTailStart(transport.LogTailStart{Session: "", Lines: 10})
	if len(a.logTail) != 0 {
		t.Fatalf("expected no session to be created")
	}

	a.handleLogTailStart(transport.LogTailStart{Session: "s1", Lines: -1})
	// should create and then quickly clean up
	deadline := time.Now().Add(2 * time.Second)
	for {
		a.logTailMu.Lock()
		n := len(a.logTail)
		a.logTailMu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected tail session to clean up")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Stop with empty session should be no-op.
	a.handleLogTailStop(transport.LogTailStop{Session: ""})
}

func newTestAgentForDirList(t *testing.T, cfg *config.Config) *Agent {
	t.Helper()
	log, err := logging.New(logging.Options{File: "", Level: "error"})
	if err != nil {
		t.Fatalf("init logger: %v", err)
	}
	if cfg.Logging.FilePath == "" {
		cfg.Logging.FilePath = ""
	}
	if cfg.Transport.Path == "" {
		cfg.Transport.Path = "/socket.io"
	}
	if cfg.ServerURL == "" {
		cfg.ServerURL = "https://example.com"
	}
	if cfg.AuthToken == "" {
		cfg.AuthToken = "token"
	}

	tr, err := transport.New(transport.Config{
		ServerURL:     cfg.ServerURL,
		ClientID:      cfg.ClientID,
		AuthToken:     cfg.AuthToken,
		Namespace:     "/agents",
		SocketPath:    cfg.Transport.Path,
		SkipTLSVerify: true,
	}, log, transport.Handlers{})
	if err != nil {
		t.Fatalf("init transport: %v", err)
	}

	// Windows path cleaning differs; keep tests that assert exact paths on non-windows.
	if runtime.GOOS == "windows" {
		// Not skipping entirely; our tests avoid strict path assertions on windows.
	}

	return &Agent{cfg: cfg, log: log, transport: tr, logTail: map[string]*tailHandle{}}
}
