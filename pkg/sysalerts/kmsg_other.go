//go:build !linux

package sysalerts

import (
	"time"
)

// collectAlerts is a stub for non-Linux platforms.
// OS alert collection is currently only supported on Linux.
func collectAlerts(since time.Time, categories []string, log Logger) []logEntry {
	// On non-Linux platforms, return empty results.
	// Future: implement Windows Event Log support via wevtutil or WMI.
	return nil
}
