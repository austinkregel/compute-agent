package sysalerts

import (
	"regexp"
	"strings"
)

// patternMatch represents a matched alert pattern.
type patternMatch struct {
	severity string
	category string
}

// alertPattern defines a pattern to match in log messages.
type alertPattern struct {
	regex    *regexp.Regexp
	severity string
	category string
}

// Compiled patterns for detecting critical system events.
// Patterns are checked in order; first match wins.
var alertPatterns = []alertPattern{
	// Kernel panics (critical)
	{regexp.MustCompile(`(?i)kernel\s*panic`), "critical", "kernel_panic"},
	{regexp.MustCompile(`(?i)^Oops:`), "critical", "kernel_panic"},
	{regexp.MustCompile(`(?i)^BUG:`), "critical", "kernel_panic"},
	{regexp.MustCompile(`(?i)Kernel\s+BUG\s+at`), "critical", "kernel_panic"},
	{regexp.MustCompile(`(?i)Unable\s+to\s+handle\s+kernel`), "critical", "kernel_panic"},

	// OOM killer (critical)
	{regexp.MustCompile(`(?i)oom-kill:`), "critical", "oom"},
	{regexp.MustCompile(`(?i)Out\s+of\s+memory:`), "critical", "oom"},
	{regexp.MustCompile(`(?i)Killed\s+process\s+\d+`), "critical", "oom"},
	{regexp.MustCompile(`(?i)invoked\s+oom-killer`), "critical", "oom"},

	// Memory errors (critical)
	{regexp.MustCompile(`(?i)page\s+allocation\s+failure`), "critical", "memory"},
	{regexp.MustCompile(`(?i)SLUB:\s+.*failed`), "critical", "memory"},
	{regexp.MustCompile(`(?i)memory\s+corruption`), "critical", "memory"},
	{regexp.MustCompile(`(?i)Bad\s+page\s+state`), "critical", "memory"},
	{regexp.MustCompile(`(?i)double\s+free\s+detected`), "critical", "memory"},

	// Hardware errors (critical)
	{regexp.MustCompile(`(?i)Machine\s+Check\s+Exception`), "critical", "hardware"},
	{regexp.MustCompile(`(?i)\bMCE\b.*error`), "critical", "hardware"},
	{regexp.MustCompile(`(?i)Hardware\s+Error`), "critical", "hardware"},
	{regexp.MustCompile(`(?i)Uncorrectable\s+error`), "critical", "hardware"},
	{regexp.MustCompile(`(?i)ACPI\s+Error`), "error", "hardware"},
	{regexp.MustCompile(`(?i)PCI.*error`), "error", "hardware"},

	// Segmentation faults (error)
	{regexp.MustCompile(`(?i)segfault\s+at`), "error", "segfault"},
	{regexp.MustCompile(`(?i)general\s+protection\s+fault`), "error", "segfault"},
	{regexp.MustCompile(`(?i)invalid\s+opcode`), "error", "segfault"},
	{regexp.MustCompile(`(?i)stack\s+segment`), "error", "segfault"},
	{regexp.MustCompile(`(?i)SIGSEGV`), "error", "segfault"},

	// Disk I/O errors (error)
	{regexp.MustCompile(`(?i)I/O\s+error`), "error", "disk_io"},
	{regexp.MustCompile(`(?i)ata\d+.*error`), "error", "disk_io"},
	{regexp.MustCompile(`(?i)end_request:\s+I/O\s+error`), "error", "disk_io"},
	{regexp.MustCompile(`(?i)SCSI\s+error`), "error", "disk_io"},
	{regexp.MustCompile(`(?i)device\s+offline`), "error", "disk_io"},
	{regexp.MustCompile(`(?i)medium\s+error`), "error", "disk_io"},
	{regexp.MustCompile(`(?i)write\s+error`), "error", "disk_io"},
	{regexp.MustCompile(`(?i)read\s+error`), "error", "disk_io"},
	{regexp.MustCompile(`(?i)EXT4-fs\s+error`), "error", "disk_io"},
	{regexp.MustCompile(`(?i)XFS.*error`), "error", "disk_io"},
	{regexp.MustCompile(`(?i)BTRFS.*error`), "error", "disk_io"},

	// Driver/firmware failures (warning)
	{regexp.MustCompile(`(?i)failed\s+to\s+load\s+firmware`), "warning", "driver"},
	{regexp.MustCompile(`(?i)module.*failed`), "warning", "driver"},
	{regexp.MustCompile(`(?i)driver.*failed`), "warning", "driver"},
	{regexp.MustCompile(`(?i)firmware.*failed`), "warning", "driver"},
	{regexp.MustCompile(`(?i)probe\s+failed`), "warning", "driver"},
	{regexp.MustCompile(`(?i)initialization\s+failed`), "warning", "driver"},

	// Thermal events (warning)
	{regexp.MustCompile(`(?i)temperature\s+above\s+threshold`), "warning", "thermal"},
	{regexp.MustCompile(`(?i)thermal\s+zone.*critical`), "critical", "thermal"},
	{regexp.MustCompile(`(?i)CPU\d+.*throttl`), "warning", "thermal"},
	{regexp.MustCompile(`(?i)overheating`), "warning", "thermal"},

	// Watchdog (error)
	{regexp.MustCompile(`(?i)soft\s+lockup`), "error", "watchdog"},
	{regexp.MustCompile(`(?i)hard\s+lockup`), "critical", "watchdog"},
	{regexp.MustCompile(`(?i)RCU.*stall`), "error", "watchdog"},
	{regexp.MustCompile(`(?i)rcu_sched.*stall`), "error", "watchdog"},
	{regexp.MustCompile(`(?i)watchdog.*triggered`), "error", "watchdog"},
	{regexp.MustCompile(`(?i)hung_task`), "warning", "watchdog"},

	// Network errors (warning)
	{regexp.MustCompile(`(?i)link\s+is\s+down`), "warning", "network"},
	{regexp.MustCompile(`(?i)carrier\s+lost`), "warning", "network"},
	{regexp.MustCompile(`(?i)TX\s+timeout`), "warning", "network"},
	{regexp.MustCompile(`(?i)netdev\s+watchdog`), "warning", "network"},
}

// classifyMessage checks if a message matches any alert pattern.
// Returns nil if no match is found.
func classifyMessage(msg string) *patternMatch {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return nil
	}

	for _, p := range alertPatterns {
		if p.regex.MatchString(msg) {
			return &patternMatch{
				severity: p.severity,
				category: p.category,
			}
		}
	}
	return nil
}

// categoryAllowed checks if a category is in the allowed list.
// If allowedCategories is empty, all categories are allowed.
func categoryAllowed(category string, allowedCategories []string) bool {
	if len(allowedCategories) == 0 {
		return true
	}
	for _, c := range allowedCategories {
		if strings.EqualFold(c, category) {
			return true
		}
	}
	return false
}

// AllCategories returns all supported alert category names.
func AllCategories() []string {
	return []string{
		"kernel_panic",
		"oom",
		"memory",
		"hardware",
		"segfault",
		"disk_io",
		"driver",
		"thermal",
		"watchdog",
		"network",
	}
}
