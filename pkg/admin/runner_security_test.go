package admin

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/austinkregel/compute-agent/pkg/config"
	"github.com/austinkregel/compute-agent/pkg/logging"
)

func TestTokenizeCommandLine(t *testing.T) {
	tests := []struct {
		in      string
		want    []string
		wantErr bool
	}{
		{in: "echo hello", want: []string{"echo", "hello"}},
		{in: `echo "hello world"`, want: []string{"echo", "hello world"}},
		{in: "echo 'hello world'", want: []string{"echo", "hello world"}},
		{in: `echo a\ b`, want: []string{"echo", "a b"}},
		{in: `echo "a\"b"`, want: []string{"echo", `a"b`}},
		{in: `echo "unterminated`, wantErr: true},
		{in: `echo a\`, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := tokenizeCommandLine(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (tokens=%v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("len(tokens)=%d want %d (tokens=%v)", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("token[%d]=%q want %q (tokens=%v)", i, got[i], tc.want[i], got)
				}
			}
		})
	}
}

func TestHasForbiddenShellChars(t *testing.T) {
	ok := []string{
		"echo ok",
		"sleep 1",
	}
	bad := []string{
		"echo ok; echo pwned",
		"echo ok | cat",
		"echo `id`",
		"echo $(id)",
		"echo $HOME",
		"echo ok && echo pwned",
		"echo ok || echo pwned",
		"echo ok\nwhoami",
	}

	for _, s := range ok {
		if hasForbiddenShellChars(s) {
			t.Fatalf("expected allowed string, got forbidden: %q", s)
		}
	}
	for _, s := range bad {
		if !hasForbiddenShellChars(s) {
			t.Fatalf("expected forbidden string, got allowed: %q", s)
		}
	}
}

func TestParseCronUpdatePipeline(t *testing.T) {
	cron := "SHELL=/bin/sh\n* * * * * echo hi\n"
	b64 := base64.StdEncoding.EncodeToString([]byte(cron))

	tests := []string{
		"echo " + b64 + " | base64 -d | crontab -",
		`echo "` + b64 + `" | base64 -d | crontab -`,
		"  echo   " + b64 + "   |   base64 -d   |  crontab -  ",
	}
	for _, cmd := range tests {
		got, ok := parseCronUpdatePipeline(cmd)
		if !ok {
			t.Fatalf("expected pipeline to match: %q", cmd)
		}
		if string(got) != cron {
			t.Fatalf("decoded cron mismatch: got %q want %q", string(got), cron)
		}
	}

	if _, ok := parseCronUpdatePipeline("echo " + b64 + " | cat"); ok {
		t.Fatalf("expected non-cron pipeline to not match")
	}
}

func TestRunCommand_DoesNotAllowPrefixExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell command test not portable to windows")
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	cfg := &config.Config{
		Admin: config.AdminConfig{
			Allowed:       []string{"echo"},
			MaxConcurrent: 1,
		},
	}
	r := NewRunner(cfg, log, ShellCallbacks{})

	res := r.RunCommand(context.Background(), CommandRequest{
		Command: "echoo hi",
		Timeout: time.Second,
	})
	if res.Summary.Code != 126 {
		t.Fatalf("expected blocked, got code=%d stdout=%q stderr=%q err=%q", res.Summary.Code, res.Stdout, res.Stderr, res.Error)
	}
}

func TestRunCommand_AllowedCwd_AllowsSubdir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell command test not portable to windows")
	}
	tmp := t.TempDir()
	sub := filepath.Join(tmp, "sub")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}

	log, _ := logging.New(logging.Options{Level: "error"})
	cfg := &config.Config{
		Admin: config.AdminConfig{
			Allowed:       []string{"pwd"},
			AllowedCwds:   []string{tmp},
			MaxConcurrent: 1,
		},
	}
	r := NewRunner(cfg, log, ShellCallbacks{})

	res := r.RunCommand(context.Background(), CommandRequest{
		Command: "pwd",
		Cwd:     sub,
		Timeout: time.Second,
	})
	if res.Summary.Code != 0 {
		t.Fatalf("expected allowed, got code=%d stdout=%q stderr=%q err=%q", res.Summary.Code, res.Stdout, res.Stderr, res.Error)
	}
}

func TestRateLimit_WindowReset_AllowsAgain(t *testing.T) {
	log, _ := logging.New(logging.Options{Level: "error"})
	cfg := &config.Config{
		Admin: config.AdminConfig{
			Allowed:            []string{"echo"},
			MaxConcurrent:      1,
			RateLimitMax:       1,
			RateLimitWindowSec: 60,
		},
	}
	r := NewRunner(cfg, log, ShellCallbacks{})

	if !r.allowRequest() {
		t.Fatal("expected first request allowed")
	}
	if r.allowRequest() {
		t.Fatal("expected second request rate limited")
	}

	// Simulate window expiration without sleeping.
	r.rateMu.Lock()
	r.rateWindowStart = time.Now().Add(-2 * time.Minute)
	r.rateMu.Unlock()

	if !r.allowRequest() {
		t.Fatal("expected request allowed after window reset")
	}
}
