package sysalerts

import (
	"testing"
	"time"
)

// mockLogger implements the Logger interface for testing.
type mockLogger struct{}

func (mockLogger) Debug(string, ...any) {}
func (mockLogger) Info(string, ...any)  {}
func (mockLogger) Warn(string, ...any)  {}
func (mockLogger) Error(string, ...any) {}

func TestClassifyMessage(t *testing.T) {
	tests := []struct {
		name             string
		message          string
		expectedCategory string
		expectedSeverity string
		shouldMatch      bool
	}{
		// Kernel panics
		{
			name:             "kernel panic",
			message:          "Kernel panic - not syncing: Fatal exception",
			expectedCategory: "kernel_panic",
			expectedSeverity: "critical",
			shouldMatch:      true,
		},
		{
			name:             "kernel oops",
			message:          "Oops: 0000 [#1] SMP NOPTI",
			expectedCategory: "kernel_panic",
			expectedSeverity: "critical",
			shouldMatch:      true,
		},
		{
			name:             "kernel bug",
			message:          "BUG: unable to handle kernel NULL pointer dereference",
			expectedCategory: "kernel_panic",
			expectedSeverity: "critical",
			shouldMatch:      true,
		},

		// OOM
		{
			name:             "oom kill",
			message:          "oom-kill: Killed process 1234 (java) total-vm:8388608kB",
			expectedCategory: "oom",
			expectedSeverity: "critical",
			shouldMatch:      true,
		},
		{
			name:             "out of memory",
			message:          "Out of memory: Kill process 1234 (mysqld) score 900",
			expectedCategory: "oom",
			expectedSeverity: "critical",
			shouldMatch:      true,
		},
		{
			name:             "killed process",
			message:          "Killed process 9876 (node) due to OOM",
			expectedCategory: "oom",
			expectedSeverity: "critical",
			shouldMatch:      true,
		},

		// Memory errors
		{
			name:             "page allocation failure",
			message:          "nginx: page allocation failure: order:0",
			expectedCategory: "memory",
			expectedSeverity: "critical",
			shouldMatch:      true,
		},
		{
			name:             "slub error",
			message:          "SLUB: allocation failed: GFP_KERNEL",
			expectedCategory: "memory",
			expectedSeverity: "critical",
			shouldMatch:      true,
		},

		// Hardware errors
		{
			name:             "machine check exception",
			message:          "Machine Check Exception: Hardware error detected",
			expectedCategory: "hardware",
			expectedSeverity: "critical",
			shouldMatch:      true,
		},
		{
			name:             "mce error",
			message:          "MCE: CPU 0: error detected",
			expectedCategory: "hardware",
			expectedSeverity: "critical",
			shouldMatch:      true,
		},
		{
			name:             "acpi error",
			message:          "ACPI Error: Method parse/execution failed",
			expectedCategory: "hardware",
			expectedSeverity: "error",
			shouldMatch:      true,
		},

		// Segfaults
		{
			name:             "segfault",
			message:          "nginx[1234]: segfault at 0000000000000000 ip 00007f8a",
			expectedCategory: "segfault",
			expectedSeverity: "error",
			shouldMatch:      true,
		},
		{
			name:             "general protection fault",
			message:          "general protection fault: 0000 [#1] SMP PTI",
			expectedCategory: "segfault",
			expectedSeverity: "error",
			shouldMatch:      true,
		},

		// Disk I/O
		{
			name:             "io error",
			message:          "Buffer I/O error on dev sda1, logical block 12345",
			expectedCategory: "disk_io",
			expectedSeverity: "error",
			shouldMatch:      true,
		},
		{
			name:             "ata error",
			message:          "ata1.00: error: { UNC }",
			expectedCategory: "disk_io",
			expectedSeverity: "error",
			shouldMatch:      true,
		},
		{
			name:             "ext4 error",
			message:          "EXT4-fs error (device sda1): ext4_find_entry",
			expectedCategory: "disk_io",
			expectedSeverity: "error",
			shouldMatch:      true,
		},

		// Driver/firmware
		{
			name:             "firmware failed",
			message:          "failed to load firmware iwlwifi-8000C-36.ucode",
			expectedCategory: "driver",
			expectedSeverity: "warning",
			shouldMatch:      true,
		},
		{
			name:             "module failed",
			message:          "module nvidia failed to initialize",
			expectedCategory: "driver",
			expectedSeverity: "warning",
			shouldMatch:      true,
		},

		// Thermal
		{
			name:             "temperature above threshold",
			message:          "CPU0: Core temperature above threshold, cpu clock throttled",
			expectedCategory: "thermal",
			expectedSeverity: "warning",
			shouldMatch:      true,
		},
		{
			name:             "thermal zone critical",
			message:          "thermal zone acpitz0 reached critical temperature",
			expectedCategory: "thermal",
			expectedSeverity: "critical",
			shouldMatch:      true,
		},

		// Watchdog
		{
			name:             "soft lockup",
			message:          "watchdog: BUG: soft lockup - CPU#0 stuck for 22s!",
			expectedCategory: "watchdog",
			expectedSeverity: "error",
			shouldMatch:      true,
		},
		{
			name:             "hard lockup",
			message:          "NMI watchdog: hard lockup detected on CPU#1",
			expectedCategory: "watchdog",
			expectedSeverity: "critical",
			shouldMatch:      true,
		},
		{
			name:             "rcu stall",
			message:          "rcu_sched self-detected stall on CPU 0",
			expectedCategory: "watchdog",
			expectedSeverity: "error",
			shouldMatch:      true,
		},

		// Network
		{
			name:             "link down",
			message:          "eth0: Link is down",
			expectedCategory: "network",
			expectedSeverity: "warning",
			shouldMatch:      true,
		},

		// No match
		{
			name:             "normal message",
			message:          "Starting Apache web server...",
			expectedCategory: "",
			expectedSeverity: "",
			shouldMatch:      false,
		},
		{
			name:             "empty message",
			message:          "",
			expectedCategory: "",
			expectedSeverity: "",
			shouldMatch:      false,
		},
		{
			name:             "unrelated log",
			message:          "User admin logged in from 192.168.1.1",
			expectedCategory: "",
			expectedSeverity: "",
			shouldMatch:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			match := classifyMessage(tc.message)
			if tc.shouldMatch {
				if match == nil {
					t.Errorf("expected match for %q but got nil", tc.message)
					return
				}
				if match.category != tc.expectedCategory {
					t.Errorf("expected category %q but got %q", tc.expectedCategory, match.category)
				}
				if match.severity != tc.expectedSeverity {
					t.Errorf("expected severity %q but got %q", tc.expectedSeverity, match.severity)
				}
			} else {
				if match != nil {
					t.Errorf("expected no match for %q but got category=%q severity=%q",
						tc.message, match.category, match.severity)
				}
			}
		})
	}
}

func TestCategoryAllowed(t *testing.T) {
	tests := []struct {
		name       string
		category   string
		allowed    []string
		wantResult bool
	}{
		{
			name:       "empty allowed list allows all",
			category:   "kernel_panic",
			allowed:    nil,
			wantResult: true,
		},
		{
			name:       "category in list",
			category:   "oom",
			allowed:    []string{"kernel_panic", "oom", "memory"},
			wantResult: true,
		},
		{
			name:       "category not in list",
			category:   "network",
			allowed:    []string{"kernel_panic", "oom"},
			wantResult: false,
		},
		{
			name:       "case insensitive match",
			category:   "KERNEL_PANIC",
			allowed:    []string{"kernel_panic"},
			wantResult: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := categoryAllowed(tc.category, tc.allowed)
			if result != tc.wantResult {
				t.Errorf("categoryAllowed(%q, %v) = %v, want %v",
					tc.category, tc.allowed, result, tc.wantResult)
			}
		})
	}
}

func TestMonitorSnapshot(t *testing.T) {
	cfg := MonitorConfig{
		Enabled:       true,
		ScanInterval:  60,
		MaxAlerts:     10,
		LookbackHours: 1,
		MaxMessageLen: 100,
	}

	m := NewMonitor(cfg, mockLogger{})

	// Initial snapshot should be empty
	snap := m.Snapshot()
	if snap == nil {
		t.Fatal("expected non-nil snapshot")
	}
	if len(snap.Alerts) != 0 {
		t.Errorf("expected 0 alerts, got %d", len(snap.Alerts))
	}
	if snap.HasCritical {
		t.Error("expected HasCritical to be false")
	}
}

func TestMonitorDeduplication(t *testing.T) {
	cfg := MonitorConfig{
		Enabled:       true,
		MaxAlerts:     50,
		LookbackHours: 1,
		MaxMessageLen: 500,
	}

	m := NewMonitor(cfg, mockLogger{})

	// Simulate processing duplicate entries. Anchor to a minute boundary so the
	// three timestamps can't straddle one: the dedup ID truncates to the minute
	// (see entryToAlert), so a `time.Now()` landing in the last ~2s of a minute
	// would otherwise split these across two IDs and flake the count.
	now := time.Now().Truncate(time.Minute)
	entries := []logEntry{
		{timestamp: now, message: "kernel panic - test", source: "test"},
		{timestamp: now.Add(time.Second), message: "kernel panic - test", source: "test"},
		{timestamp: now.Add(2 * time.Second), message: "kernel panic - test", source: "test"},
	}

	m.processEntries(entries, now)

	snap := m.Snapshot()
	if snap == nil {
		t.Fatal("expected non-nil snapshot")
	}

	// Should deduplicate to 1 alert with count 3
	if len(snap.Alerts) != 1 {
		t.Errorf("expected 1 alert after dedup, got %d", len(snap.Alerts))
	}
	if len(snap.Alerts) > 0 && snap.Alerts[0].Count != 3 {
		t.Errorf("expected count 3, got %d", snap.Alerts[0].Count)
	}
}

func TestMonitorMaxAlerts(t *testing.T) {
	cfg := MonitorConfig{
		Enabled:       true,
		MaxAlerts:     5,
		LookbackHours: 1,
		MaxMessageLen: 500,
	}

	m := NewMonitor(cfg, mockLogger{})

	// Add more alerts than the limit
	now := time.Now()
	entries := []logEntry{}
	for i := 0; i < 10; i++ {
		// Each message is unique to avoid deduplication
		entries = append(entries, logEntry{
			timestamp: now.Add(time.Duration(i) * time.Minute),
			message:   "I/O error on device " + string(rune('a'+i)),
			source:    "test",
		})
	}

	m.processEntries(entries, now)

	snap := m.Snapshot()
	if len(snap.Alerts) != 5 {
		t.Errorf("expected 5 alerts (max limit), got %d", len(snap.Alerts))
	}
}

func TestMonitorMessageTruncation(t *testing.T) {
	cfg := MonitorConfig{
		Enabled:       true,
		MaxAlerts:     10,
		LookbackHours: 1,
		MaxMessageLen: 50,
	}

	m := NewMonitor(cfg, mockLogger{})

	// Create a long message
	longMsg := "kernel panic - " + string(make([]byte, 100)) // Will exceed 50 chars
	for i := range longMsg[15:] {
		longMsg = longMsg[:15] + string(rune('a'+i%26)) + longMsg[16:]
	}
	longMsg = "kernel panic - " + "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"

	entries := []logEntry{{
		timestamp: time.Now(),
		message:   longMsg,
		source:    "test",
	}}

	m.processEntries(entries, time.Now())

	snap := m.Snapshot()
	if len(snap.Alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(snap.Alerts))
	}

	if len(snap.Alerts[0].Message) > 50 {
		t.Errorf("message not truncated: len=%d", len(snap.Alerts[0].Message))
	}
}

func TestAllCategories(t *testing.T) {
	cats := AllCategories()
	if len(cats) == 0 {
		t.Error("expected non-empty list of categories")
	}

	// Check for expected categories
	expected := map[string]bool{
		"kernel_panic": false,
		"oom":          false,
		"memory":       false,
		"hardware":     false,
		"segfault":     false,
		"disk_io":      false,
		"driver":       false,
		"thermal":      false,
		"watchdog":     false,
		"network":      false,
	}

	for _, c := range cats {
		if _, ok := expected[c]; ok {
			expected[c] = true
		}
	}

	for cat, found := range expected {
		if !found {
			t.Errorf("expected category %q not found in AllCategories()", cat)
		}
	}
}
