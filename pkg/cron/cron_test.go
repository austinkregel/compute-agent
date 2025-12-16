package cron

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNewBridge(t *testing.T) {
	b := NewBridge(nil, nil)
	if b == nil {
		t.Fatal("NewBridge returned nil")
	}
}

func TestBridge_Fetch_Success(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cron bridge uses crontab command; not available on windows")
	}

	tmp := t.TempDir()
	installFakeCrontab(t, tmp, `#!/bin/sh
set -eu
if [ "${1:-}" = "-l" ]; then
  echo "# test crontab"
  echo "* * * * * echo hi"
  exit 0
fi
echo "unexpected args: $@" 1>&2
exit 2
`)
	withPath(t, tmp)

	b := NewBridge(nil, nil)
	out, err := b.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if !strings.Contains(out, "* * * * * echo hi") {
		t.Fatalf("Fetch() output missing expected line, got %q", out)
	}
}

func TestBridge_Fetch_ErrorIncludesOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cron bridge uses crontab command; not available on windows")
	}

	tmp := t.TempDir()
	installFakeCrontab(t, tmp, `#!/bin/sh
set -eu
if [ "${1:-}" = "-l" ]; then
  echo "no crontab for user" 1>&2
  exit 1
fi
exit 2
`)
	withPath(t, tmp)

	b := NewBridge(nil, nil)
	_, err := b.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "crontab -l failed") {
		t.Fatalf("expected error to mention crontab -l failed, got %q", msg)
	}
	if !strings.Contains(msg, "no crontab for user") {
		t.Fatalf("expected error to include command output, got %q", msg)
	}
}

func TestBridge_Apply_Success(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cron bridge uses crontab command; not available on windows")
	}

	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "installed.txt")
	installFakeCrontab(t, tmp, `#!/bin/sh
set -eu
if [ "${1:-}" = "-" ]; then
  : "${CRON_OUT:?CRON_OUT must be set}"
  cat > "$CRON_OUT"
  exit 0
fi
exit 2
`)
	withPath(t, tmp)

	oldOut := os.Getenv("CRON_OUT")
	t.Cleanup(func() {
		if oldOut == "" {
			_ = os.Unsetenv("CRON_OUT")
		} else {
			_ = os.Setenv("CRON_OUT", oldOut)
		}
	})
	_ = os.Setenv("CRON_OUT", outPath)

	b := NewBridge(nil, nil)
	cronText := "* * * * * echo installed\n"
	if err := b.Apply(context.Background(), cronText); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if string(data) != cronText {
		t.Fatalf("installed cron mismatch: got %q want %q", string(data), cronText)
	}
}

func TestBridge_Apply_ErrorIncludesOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cron bridge uses crontab command; not available on windows")
	}

	tmp := t.TempDir()
	installFakeCrontab(t, tmp, `#!/bin/sh
set -eu
if [ "${1:-}" = "-" ]; then
  echo "bad crontab" 1>&2
  exit 1
fi
exit 2
`)
	withPath(t, tmp)

	b := NewBridge(nil, nil)
	err := b.Apply(context.Background(), "not important\n")
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "crontab - failed") {
		t.Fatalf("expected error to mention crontab - failed, got %q", msg)
	}
	if !strings.Contains(msg, "bad crontab") {
		t.Fatalf("expected error to include command output, got %q", msg)
	}
}

func TestBridge_ApplyBase64_Success(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cron bridge uses crontab command; not available on windows")
	}

	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "installed.txt")
	installFakeCrontab(t, tmp, `#!/bin/sh
set -eu
if [ "${1:-}" = "-" ]; then
  : "${CRON_OUT:?CRON_OUT must be set}"
  cat > "$CRON_OUT"
  exit 0
fi
exit 2
`)
	withPath(t, tmp)

	oldOut := os.Getenv("CRON_OUT")
	t.Cleanup(func() {
		if oldOut == "" {
			_ = os.Unsetenv("CRON_OUT")
		} else {
			_ = os.Setenv("CRON_OUT", oldOut)
		}
	})
	_ = os.Setenv("CRON_OUT", outPath)

	b := NewBridge(nil, nil)
	cronText := "@reboot echo hi\n"
	b64 := base64.StdEncoding.EncodeToString([]byte(cronText))
	if err := b.ApplyBase64(context.Background(), b64); err != nil {
		t.Fatalf("ApplyBase64() error = %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if string(data) != cronText {
		t.Fatalf("installed cron mismatch: got %q want %q", string(data), cronText)
	}
}

func TestBridge_ApplyBase64_DecodeError(t *testing.T) {
	b := NewBridge(nil, nil)
	if err := b.ApplyBase64(context.Background(), "###not-base64###"); err == nil {
		t.Fatal("expected error")
	} else if !strings.Contains(err.Error(), "decode base64 cron") {
		t.Fatalf("expected decode error, got %q", err.Error())
	}
}

func installFakeCrontab(t *testing.T, dir string, script string) {
	t.Helper()
	path := filepath.Join(dir, "crontab")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake crontab: %v", err)
	}
}

func withPath(t *testing.T, dir string) {
	t.Helper()
	old := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", old) })
	_ = os.Setenv("PATH", dir+string(os.PathListSeparator)+old)
}
