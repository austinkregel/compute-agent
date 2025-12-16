package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/austinkregel/compute-agent/pkg/config"
	"github.com/austinkregel/compute-agent/pkg/logging"
	"github.com/austinkregel/compute-agent/pkg/transport"
)

func TestEmitLastLines_EmptyFile(t *testing.T) {
	a := newTestAgentForLogTail(t)

	p := filepath.Join(t.TempDir(), "agent.log")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatalf("open temp file: %v", err)
	}
	defer f.Close()

	off, err := a.emitLastLines(f, "sess", 10)
	if err != nil {
		t.Fatalf("emitLastLines error: %v", err)
	}
	if off != 0 {
		t.Fatalf("expected offset 0 for empty file, got %d", off)
	}
}

func TestEmitLastLines_ReturnsFileSizeForNonEmpty(t *testing.T) {
	a := newTestAgentForLogTail(t)

	contents := "line1\nline2\nline3\n"
	p := filepath.Join(t.TempDir(), "agent.log")
	if err := os.WriteFile(p, []byte(contents), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat temp file: %v", err)
	}
	wantSize := info.Size()

	f, err := os.Open(p)
	if err != nil {
		t.Fatalf("open temp file: %v", err)
	}
	defer f.Close()

	off, err := a.emitLastLines(f, "sess", 2)
	if err != nil {
		t.Fatalf("emitLastLines error: %v", err)
	}
	if off != wantSize {
		t.Fatalf("expected offset %d, got %d", wantSize, off)
	}
}

func TestEmitLastLines_TrailingNewlinesDontError(t *testing.T) {
	a := newTestAgentForLogTail(t)

	contents := "line1\nline2\n\n\n"
	p := filepath.Join(t.TempDir(), "agent.log")
	if err := os.WriteFile(p, []byte(contents), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	f, err := os.Open(p)
	if err != nil {
		t.Fatalf("open temp file: %v", err)
	}
	defer f.Close()

	if _, err := a.emitLastLines(f, "sess", 10); err != nil {
		t.Fatalf("emitLastLines error: %v", err)
	}
}

func newTestAgentForLogTail(t *testing.T) *Agent {
	log, err := logging.New(logging.Options{File: "", Level: "info"})
	if err != nil {
		t.Fatalf("init logger: %v", err)
	}

	// Create a transport client that won't be connected; Emit will be best-effort.
	tr, err := transport.New(transport.Config{
		ServerURL:     "https://example.com",
		ClientID:      "test-client",
		AuthToken:     "test-token",
		Namespace:     "/agents",
		SocketPath:    "/socket.io",
		SkipTLSVerify: true,
	}, log, transport.Handlers{})
	if err != nil {
		t.Fatalf("init transport: %v", err)
	}

	cfg := &config.Config{Logging: config.LoggingConfig{FilePath: ""}}
	return &Agent{
		cfg:       cfg,
		log:       log,
		transport: tr,
		logTail:   map[string]*tailHandle{},
	}
}
