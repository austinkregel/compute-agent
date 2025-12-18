package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// UpdateInfo is a best-effort snapshot of OS update availability.
//
// Notes:
//   - This intentionally reports counts, not package/title lists, to keep payloads small and avoid
//     leaking potentially sensitive software inventory.
//   - Security count is best-effort (varies by platform/package manager); if unknown it may be 0.
type UpdateInfo struct {
	Available       int    `json:"available"`
	Security        int    `json:"security"`
	RestartRequired bool   `json:"restartRequired"`
	LastChecked     string `json:"lastChecked"`
	CheckError      string `json:"checkError,omitempty"`
}

// UpdateChecker periodically refreshes update availability and caches the last result.
// It is safe for concurrent use.
type UpdateChecker struct {
	interval time.Duration

	mu   sync.RWMutex
	last UpdateInfo
}

func NewUpdateChecker(interval time.Duration) *UpdateChecker {
	if interval <= 0 {
		interval = 12 * time.Hour
	}
	return &UpdateChecker{interval: interval}
}

// Snapshot returns the last cached update info (may be zero-valued if never checked).
func (c *UpdateChecker) Snapshot() UpdateInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.last
}

// CheckNow runs an update check immediately, updates the cache, and returns the latest result.
func (c *UpdateChecker) CheckNow(ctx context.Context) UpdateInfo {
	info := UpdateInfo{
		LastChecked: time.Now().UTC().Format(time.RFC3339Nano),
	}

	// Bound execution time: update mechanisms can hang due to locks/network.
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	available, security, restart, err := checkUpdatesPlatform(ctx)
	if err != nil {
		info.CheckError = err.Error()
	} else {
		info.Available = max0(available)
		info.Security = max0(security)
		info.RestartRequired = restart
	}

	c.mu.Lock()
	c.last = info
	c.mu.Unlock()
	return info
}

// Run refreshes update status on a fixed interval until ctx is cancelled.
func (c *UpdateChecker) Run(ctx context.Context) error {
	// Emit one result on start so dashboards can show state without waiting 12h.
	c.CheckNow(ctx)

	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			c.CheckNow(ctx)
		}
	}
}

func checkUpdatesPlatform(ctx context.Context) (available int, security int, restartRequired bool, err error) {
	switch runtime.GOOS {
	case "linux":
		return checkUpdatesLinuxApt(ctx)
	case "darwin":
		return checkUpdatesMacOS(ctx)
	case "windows":
		return checkUpdatesWindows(ctx)
	default:
		return 0, 0, false, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

func checkUpdatesLinuxApt(ctx context.Context) (available int, security int, restartRequired bool, err error) {
	// We intentionally do NOT run `apt-get update` here; we only report based on current cache.
	// This keeps the check lightweight and avoids generating network traffic.
	//
	// `apt-get -s upgrade` prints one "Inst <pkg> ..." line per upgrade candidate.
	stdout, _, code, runErr := runCmd(ctx, "apt-get", "-s", "upgrade")
	if runErr != nil {
		// Debian-based hosts might not have apt-get (minimal containers). Treat as unsupported.
		return 0, 0, false, fmt.Errorf("apt-get upgrade simulation failed (code %d): %w", code, runErr)
	}
	available = parseAptGetSimulatedUpgradeCount(stdout)

	// Best-effort restart required signal (Ubuntu/Debian often use this file).
	restartRequired = fileExists("/var/run/reboot-required")

	// Security count varies by distro and configuration; keep best-effort as 0 for now.
	// We’ll provide a human-readable SecurityPatchStatus separately in telemetry.
	return available, 0, restartRequired, nil
}

func parseAptGetSimulatedUpgradeCount(stdout string) int {
	n := 0
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Inst ") {
			n++
		}
	}
	return n
}

func checkUpdatesMacOS(ctx context.Context) (available int, security int, restartRequired bool, err error) {
	// `softwareupdate -l` output varies by macOS version. We do conservative parsing:
	// - Count update labels (lines beginning with '* Label:')
	// - Detect restart requirement via an "Action: restart" line.
	stdout, _, code, runErr := runCmd(ctx, "softwareupdate", "-l")
	if runErr != nil {
		return 0, 0, false, fmt.Errorf("softwareupdate -l failed (code %d): %w", code, runErr)
	}
	available, security, restartRequired = parseSoftwareUpdateList(stdout)
	return available, security, restartRequired, nil
}

func parseSoftwareUpdateList(stdout string) (available int, security int, restartRequired bool) {
	for _, raw := range strings.Split(stdout, "\n") {
		line := strings.TrimSpace(raw)
		low := strings.ToLower(line)
		if strings.HasPrefix(line, "* Label:") {
			available++
			// Crude but useful: some updates contain "Security" in title/label.
			if strings.Contains(low, "security") {
				security++
			}
		}
		if strings.HasPrefix(low, "action:") && strings.Contains(low, "restart") {
			restartRequired = true
		}
	}
	return available, security, restartRequired
}

func checkUpdatesWindows(ctx context.Context) (available int, security int, restartRequired bool, err error) {
	// Use Windows Update COM through PowerShell (no external modules required).
	// This is best-effort; if Windows Update service is disabled, it may fail.
	//
	// We intentionally output JSON for robust parsing.
	const ps = `
$ErrorActionPreference = "Stop"
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$r = $searcher.Search("IsInstalled=0 and IsHidden=0")
$items = @()
for ($i = 0; $i -lt $r.Updates.Count; $i++) {
  $u = $r.Updates.Item($i)
  $cats = @()
  foreach ($c in $u.Categories) { $cats += $c.Name }
  $items += [pscustomobject]@{
    title = $u.Title
    rebootRequired = [bool]$u.RebootRequired
    categories = $cats
  }
}
[pscustomobject]@{ count = $r.Updates.Count; updates = $items } | ConvertTo-Json -Depth 4
`
	stdout, _, code, runErr := runCmd(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps)
	if runErr != nil {
		return 0, 0, false, fmt.Errorf("windows update search failed (code %d): %w", code, runErr)
	}

	type wu struct {
		Count   int `json:"count"`
		Updates []struct {
			RebootRequired bool     `json:"rebootRequired"`
			Categories     []string `json:"categories"`
		} `json:"updates"`
	}
	var payload wu
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		return 0, 0, false, fmt.Errorf("parse windows update json: %w", err)
	}

	available = payload.Count
	for _, u := range payload.Updates {
		if u.RebootRequired {
			restartRequired = true
		}
		for _, c := range u.Categories {
			cl := strings.ToLower(strings.TrimSpace(c))
			if cl == "security updates" || cl == "critical updates" {
				security++
				break
			}
		}
	}

	// Also check common reboot-pending registry keys; if present, report restart required.
	if pending, _ := windowsRebootPending(ctx); pending {
		restartRequired = true
	}
	return available, security, restartRequired, nil
}

func windowsRebootPending(ctx context.Context) (bool, error) {
	// Registry probing via PowerShell to avoid extra Go dependencies (x/sys/windows).
	// JSON output is unnecessary; returns "true"/"false".
	const ps = `
$ErrorActionPreference = "SilentlyContinue"
$paths = @(
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
  "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations"
)
$pending = $false
foreach ($p in $paths) { if (Test-Path $p) { $pending = $true; break } }
if ($pending) { "true" } else { "false" }
`
	stdout, _, _, err := runCmd(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(stdout)) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("unexpected reboot pending output: %q", strings.TrimSpace(stdout))
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func runCmd(ctx context.Context, name string, args ...string) (stdout string, stderr string, exitCode int, err error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = telemetrySanitizedEnv()

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	runErr := cmd.Run()
	stdout = outBuf.String()
	stderr = errBuf.String()
	if runErr == nil {
		return stdout, stderr, 0, nil
	}

	// If the command isn't found, treat as unsupported.
	var ee *exec.Error
	if errors.As(runErr, &ee) && ee.Err == exec.ErrNotFound {
		return stdout, stderr, 127, runErr
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		exitCode = exitErr.ExitCode()
		// Preserve stderr context in the wrapped error (bounded).
		return stdout, stderr, exitCode, fmt.Errorf("%w: %s", runErr, truncateOneLine(stderr, 240))
	}
	if errors.Is(runErr, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return stdout, stderr, 124, runErr
	}
	return stdout, stderr, 1, runErr
}

func telemetrySanitizedEnv() []string {
	// Intentionally minimal, to reduce leakage of secrets into child processes.
	allow := []string{
		"PATH",
		"HOME",
		"USER",
		"LANG",
		"LC_ALL",
		"TERM",
		"TMPDIR",
		"TEMP",
		// Windows:
		"SystemRoot",
		"ComSpec",
	}
	out := make([]string, 0, len(allow))
	for _, key := range allow {
		if val, ok := os.LookupEnv(key); ok {
			out = append(out, key+"="+val)
		}
	}
	return out
}

func truncateOneLine(s string, max int) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func max0(v int) int {
	if v < 0 {
		return 0
	}
	return v
}

// parseIntFromFirstMatch extracts the first integer found in s (useful for some outputs).
func parseIntFromFirstMatch(s string) (int, bool) {
	s = strings.TrimSpace(s)
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			continue
		}
		j := i
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		n, err := strconv.Atoi(s[i:j])
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}
