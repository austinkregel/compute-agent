//go:build linux

package sysalerts

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// collectAlerts gathers log entries from Linux kernel logs.
// It tries /dev/kmsg first (requires CAP_SYSLOG or root), then falls back to journalctl.
func collectAlerts(since time.Time, categories []string, log Logger) []logEntry {
	// Try /dev/kmsg first (direct kernel ring buffer access)
	entries, err := readKmsg(since)
	if err != nil {
		log.Debug("kmsg read failed, falling back to journalctl", "error", err)
		// Fall back to journalctl
		entries, err = readJournalctl(since)
		if err != nil {
			log.Debug("journalctl fallback failed", "error", err)
			// Last resort: try dmesg command
			entries, err = readDmesg(since)
			if err != nil {
				log.Debug("dmesg fallback failed", "error", err)
				return nil
			}
		}
	}

	// Filter by category if specified
	if len(categories) > 0 {
		filtered := make([]logEntry, 0, len(entries))
		for _, e := range entries {
			match := classifyMessage(e.message)
			if match != nil && categoryAllowed(match.category, categories) {
				filtered = append(filtered, e)
			}
		}
		return filtered
	}

	// Only return entries that match our patterns
	matched := make([]logEntry, 0)
	for _, e := range entries {
		if classifyMessage(e.message) != nil {
			matched = append(matched, e)
		}
	}
	return matched
}

// readKmsg reads from /dev/kmsg (kernel log buffer).
// Format: priority,sequence,timestamp,-;message
// Example: 6,1234,5678901234,-;Some kernel message
func readKmsg(since time.Time) ([]logEntry, error) {
	file, err := os.Open("/dev/kmsg")
	if err != nil {
		return nil, fmt.Errorf("open /dev/kmsg: %w", err)
	}
	defer file.Close()

	// Set non-blocking mode for reading
	// Note: We read whatever is available without blocking

	var entries []logEntry
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 8192), 8192)

	bootTime := getBootTime()

	// Read with a timeout to avoid blocking forever
	done := make(chan struct{})
	go func() {
		defer close(done)
		for scanner.Scan() {
			line := scanner.Text()
			entry, ok := parseKmsgLine(line, bootTime)
			if !ok {
				continue
			}
			if entry.timestamp.Before(since) {
				continue
			}
			entries = append(entries, entry)
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		// Timeout - return what we have
	}

	if err := scanner.Err(); err != nil {
		// Ignore errors from non-blocking read
		if !strings.Contains(err.Error(), "resource temporarily unavailable") {
			return entries, fmt.Errorf("scan /dev/kmsg: %w", err)
		}
	}

	return entries, nil
}

// parseKmsgLine parses a line from /dev/kmsg.
// Format: priority,sequence,timestamp,-;message
func parseKmsgLine(line string, bootTime time.Time) (logEntry, bool) {
	// Find the semicolon that separates metadata from message
	idx := strings.Index(line, ";")
	if idx < 0 {
		return logEntry{}, false
	}

	meta := line[:idx]
	msg := line[idx+1:]

	// Parse metadata: priority,sequence,timestamp,-
	parts := strings.Split(meta, ",")
	if len(parts) < 3 {
		return logEntry{}, false
	}

	priority, _ := strconv.Atoi(parts[0])
	level := priority & 7 // Lowest 3 bits are the level

	// Timestamp is in microseconds since boot
	usec, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return logEntry{}, false
	}

	ts := bootTime.Add(time.Duration(usec) * time.Microsecond)

	return logEntry{
		timestamp: ts,
		message:   strings.TrimSpace(msg),
		source:    "kmsg",
		level:     level,
	}, true
}

// readJournalctl reads kernel logs using journalctl.
func readJournalctl(since time.Time) ([]logEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sinceStr := since.Format("2006-01-02 15:04:05")
	cmd := exec.CommandContext(ctx, "journalctl",
		"-k",                       // Kernel messages only
		"--since", sinceStr,        // Only messages since this time
		"--no-pager",               // Don't page output
		"-o", "short-iso-precise",  // ISO timestamp format
		"--no-hostname",            // Don't include hostname
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = minimalEnv()

	if err := cmd.Run(); err != nil {
		// Check if journalctl is not available
		if strings.Contains(err.Error(), "executable file not found") {
			return nil, fmt.Errorf("journalctl not found")
		}
		return nil, fmt.Errorf("journalctl: %w (stderr: %s)", err, stderr.String())
	}

	var entries []logEntry
	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		line := scanner.Text()
		entry, ok := parseJournalctlLine(line)
		if !ok {
			continue
		}
		if entry.timestamp.Before(since) {
			continue
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// parseJournalctlLine parses a journalctl output line.
// Format: 2024-01-15T10:30:45.123456+0000 kernel: message
func parseJournalctlLine(line string) (logEntry, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return logEntry{}, false
	}

	// Try to find the timestamp (ISO format)
	// Example: 2024-01-15T10:30:45.123456+0000 kernel: message
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return logEntry{}, false
	}

	// Parse timestamp
	tsStr := parts[0]
	ts, err := time.Parse("2006-01-02T15:04:05.999999-0700", tsStr)
	if err != nil {
		// Try alternative formats
		ts, err = time.Parse("2006-01-02T15:04:05.999999Z07:00", tsStr)
		if err != nil {
			ts, err = time.Parse(time.RFC3339, tsStr)
			if err != nil {
				return logEntry{}, false
			}
		}
	}

	// Extract message (skip "kernel:" prefix if present)
	msg := ""
	if len(parts) >= 3 {
		msg = parts[2]
	} else if len(parts) == 2 {
		msg = parts[1]
	}
	msg = strings.TrimPrefix(msg, "kernel: ")
	msg = strings.TrimSpace(msg)

	return logEntry{
		timestamp: ts,
		message:   msg,
		source:    "journald",
		level:     6, // Default to info
	}, true
}

// readDmesg reads kernel logs using the dmesg command.
func readDmesg(since time.Time) ([]logEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "dmesg",
		"--time-format=iso", // ISO timestamp format
		"--decode",          // Decode facility and level
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = minimalEnv()

	if err := cmd.Run(); err != nil {
		// Try without --time-format (older dmesg versions)
		cmd = exec.CommandContext(ctx, "dmesg", "-T")
		stdout.Reset()
		stderr.Reset()
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		cmd.Env = minimalEnv()

		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("dmesg: %w", err)
		}
	}

	bootTime := getBootTime()
	var entries []logEntry
	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		line := scanner.Text()
		entry, ok := parseDmesgLine(line, bootTime)
		if !ok {
			continue
		}
		if entry.timestamp.Before(since) {
			continue
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// parseDmesgLine parses a dmesg output line.
// Formats:
//   - ISO: 2024-01-15T10:30:45,123456+0000 kern  :info  : [  123.456789] message
//   - Human: [Mon Jan 15 10:30:45 2024] message
//   - Relative: [  123.456789] message
func parseDmesgLine(line string, bootTime time.Time) (logEntry, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return logEntry{}, false
	}

	var ts time.Time
	var msg string
	var level int = 6 // default to info

	// Try ISO format first: 2024-01-15T10:30:45,123456+0000
	if len(line) > 30 && line[4] == '-' && line[7] == '-' {
		// ISO format with optional level info
		idx := strings.Index(line, "]")
		if idx > 0 {
			// Find the timestamp part
			tsEnd := strings.Index(line, " ")
			if tsEnd > 0 {
				tsStr := strings.Replace(line[:tsEnd], ",", ".", 1)
				parsed, err := time.Parse("2006-01-02T15:04:05.999999-0700", tsStr)
				if err == nil {
					ts = parsed
					// Find message after the bracket
					msg = strings.TrimSpace(line[idx+1:])
				}
			}
		}
	}

	// Try human-readable format: [Mon Jan 15 10:30:45 2024]
	if ts.IsZero() && strings.HasPrefix(line, "[") {
		idx := strings.Index(line, "]")
		if idx > 0 {
			tsStr := strings.TrimSpace(line[1:idx])
			// Try parsing as human-readable date
			parsed, err := time.Parse("Mon Jan 2 15:04:05 2006", tsStr)
			if err == nil {
				ts = parsed
				msg = strings.TrimSpace(line[idx+1:])
			} else {
				// Try parsing as relative time: [  123.456789]
				tsStr = strings.TrimSpace(tsStr)
				if sec, err := strconv.ParseFloat(tsStr, 64); err == nil {
					ts = bootTime.Add(time.Duration(sec * float64(time.Second)))
					msg = strings.TrimSpace(line[idx+1:])
				}
			}
		}
	}

	if ts.IsZero() || msg == "" {
		return logEntry{}, false
	}

	return logEntry{
		timestamp: ts,
		message:   msg,
		source:    "dmesg",
		level:     level,
	}, true
}

// getBootTime returns the system boot time.
func getBootTime() time.Time {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Now().Add(-time.Hour * 24) // Fallback
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "btime ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if sec, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
					return time.Unix(sec, 0)
				}
			}
		}
	}

	return time.Now().Add(-time.Hour * 24) // Fallback
}

// minimalEnv returns a minimal environment for subprocess execution.
func minimalEnv() []string {
	return []string{
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		"LC_ALL=C",
		"LANG=C",
	}
}
