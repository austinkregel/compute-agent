package telemetry

import (
	"os"
	"strings"
	"testing"
)

func TestParseAptGetSimulatedUpgradeCount(t *testing.T) {
	out := `
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
Calculating upgrade... Done
Inst libc6 [2.35-0ubuntu3.4] (2.35-0ubuntu3.5 Ubuntu:22.04/jammy-updates [amd64])
Inst openssl [3.0.2-0ubuntu1.15] (3.0.2-0ubuntu1.16 Ubuntu:22.04/jammy-updates [amd64])
Conf libc6 (2.35-0ubuntu3.5 Ubuntu:22.04/jammy-updates [amd64])
Conf openssl (3.0.2-0ubuntu1.16 Ubuntu:22.04/jammy-updates [amd64])
`
	if got := parseAptGetSimulatedUpgradeCount(out); got != 2 {
		t.Fatalf("count mismatch: got %d want %d", got, 2)
	}
}

func TestParseSoftwareUpdateList(t *testing.T) {
	out := `
Software Update Tool

Finding available software
Software Update found the following new or updated software:
* Label: macOS Ventura 13.6.1-22G313
	Title: macOS Ventura 13.6.1, 774355K [recommended] [restart]
	Action: restart
* Label: Security Update 2025-001 (Sonoma)
	Title: Security Update 2025-001, 12345K [recommended]
	Action: install
`
	avail, sec, restart := parseSoftwareUpdateList(out)
	if avail != 2 {
		t.Fatalf("available mismatch: got %d want %d", avail, 2)
	}
	if sec != 1 {
		t.Fatalf("security mismatch: got %d want %d", sec, 1)
	}
	if !restart {
		t.Fatalf("restartRequired mismatch: got %v want %v", restart, true)
	}
}

func TestTelemetrySanitizedEnv_AllowsOnlyKnownKeys(t *testing.T) {
	// Set a mix of allowed and disallowed env vars.
	oldPath := os.Getenv("PATH")
	oldSecret := os.Getenv("SUPER_SECRET_TOKEN")
	t.Cleanup(func() {
		_ = os.Setenv("PATH", oldPath)
		if oldSecret == "" {
			_ = os.Unsetenv("SUPER_SECRET_TOKEN")
		} else {
			_ = os.Setenv("SUPER_SECRET_TOKEN", oldSecret)
		}
	})

	_ = os.Setenv("PATH", "/tmp/testpath")
	_ = os.Setenv("SUPER_SECRET_TOKEN", "shh")

	env := telemetrySanitizedEnv()
	joined := strings.Join(env, "\n")

	if !strings.Contains(joined, "PATH=/tmp/testpath") {
		t.Fatalf("expected PATH to be present in sanitized env, got %q", joined)
	}
	if strings.Contains(joined, "SUPER_SECRET_TOKEN=") {
		t.Fatalf("did not expect secret env var to be present, got %q", joined)
	}
}

func TestTruncateOneLine(t *testing.T) {
	in := "  hello\r\nworld\n  "
	got := truncateOneLine(in, 100)
	if got != "hello  world" {
		t.Fatalf("truncateOneLine cleanup mismatch: got %q", got)
	}

	long := "abcdefghijklmnopqrstuvwxyz"
	got2 := truncateOneLine(long, 10)
	if got2 != "abcdefghij…" {
		t.Fatalf("truncateOneLine trunc mismatch: got %q", got2)
	}
}

func TestParseIntFromFirstMatch(t *testing.T) {
	tests := []struct {
		in   string
		want int
		ok   bool
	}{
		{"", 0, false},
		{"no digits here", 0, false},
		{"x=12", 12, true},
		{"  007 apples", 7, true},
		{"abc 99 bottles", 99, true},
	}
	for _, tt := range tests {
		got, ok := parseIntFromFirstMatch(tt.in)
		if ok != tt.ok || got != tt.want {
			t.Fatalf("parseIntFromFirstMatch(%q) = (%d,%v), want (%d,%v)", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

