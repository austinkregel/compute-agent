package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/austinkregel/compute-agent/pkg/config"
	"github.com/austinkregel/compute-agent/pkg/logging"
	"github.com/austinkregel/compute-agent/pkg/transport"
)

func TestBuildDirListResponse_Local_SuccessAndCorrelation(t *testing.T) {
	tmp := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmp, "dir1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "file1.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		ClientID:  "test-client",
		ServerURL: "https://example.com",
		AuthToken: "token",
		Transport: config.TransportConfig{Path: "/socket.io"},
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	agent, _ := New(cfg, log)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp := agent.buildDirListResponse(ctx, transport.DirListRequest{
		ClientID:  "test-client",
		RequestID: "req-123",
		Mode:      "local",
		Path:      tmp,
	})

	if resp.RequestID != "req-123" {
		t.Fatalf("expected requestId to match, got %q", resp.RequestID)
	}
	if resp.ClientID != "test-client" {
		t.Fatalf("expected clientId to match cfg, got %q", resp.ClientID)
	}
	if resp.Error != "" {
		t.Fatalf("expected no error, got %q", resp.Error)
	}
	if len(resp.Entries) < 2 {
		t.Fatalf("expected entries, got %d", len(resp.Entries))
	}
}

func TestBuildDirListResponse_Local_AllowlistBlocks(t *testing.T) {
	tmp := t.TempDir()
	cfg := &config.Config{
		ClientID:  "test-client",
		ServerURL: "https://example.com",
		AuthToken: "token",
		Transport: config.TransportConfig{Path: "/socket.io"},
		DirBrowse: config.DirBrowseConfig{
			AllowedRoots: []string{filepath.Join(tmp, "nope")},
		},
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	agent, _ := New(cfg, log)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp := agent.buildDirListResponse(ctx, transport.DirListRequest{
		RequestID: "req-1",
		Mode:      "local",
		Path:      tmp,
	})
	if resp.Error == "" {
		t.Fatalf("expected allowlist to block")
	}
}

func TestBuildDirListResponse_Remote_RequiresHost(t *testing.T) {
	cfg := &config.Config{
		ClientID:  "test-client",
		ServerURL: "https://example.com",
		AuthToken: "token",
		Transport: config.TransportConfig{Path: "/socket.io"},
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	agent, _ := New(cfg, log)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp := agent.buildDirListResponse(ctx, transport.DirListRequest{
		RequestID: "req-remote",
		Mode:      "remote",
		Path:      "/",
	})
	if resp.Error == "" {
		t.Fatalf("expected error for missing host")
	}
}
