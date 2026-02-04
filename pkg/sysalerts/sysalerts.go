// Package sysalerts monitors system logs for critical OS-level warnings and errors.
// It reads from /dev/kmsg (Linux) or falls back to journalctl, detecting kernel panics,
// segfaults, OOM events, hardware errors, and other critical system issues.
package sysalerts

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"sync"
	"time"
)

// Alert represents a single detected OS-level warning or error.
type Alert struct {
	ID        string `json:"id"`        // Hash for deduplication
	Timestamp string `json:"ts"`        // RFC3339 timestamp
	Severity  string `json:"severity"`  // critical, error, warning
	Category  string `json:"category"`  // kernel_panic, segfault, memory, hardware, disk_io, driver, oom
	Message   string `json:"message"`   // Truncated log line (max 500 chars)
	Source    string `json:"source"`    // kmsg, journald, dmesg
	Count     int    `json:"count"`     // Occurrences if deduplicated
}

// AlertSnapshot contains recent alerts for transmission to the server.
type AlertSnapshot struct {
	Alerts       []Alert `json:"alerts"`       // Recent alerts (newest first)
	Since        string  `json:"since"`        // Scan window start (RFC3339)
	TotalCount   int     `json:"totalCount"`   // Total alerts in window
	HasCritical  bool    `json:"hasCritical"`  // True if any critical alerts present
	LastScanTime string  `json:"lastScanTime"` // When alerts were last collected
}

// MonitorConfig configures the alert monitor behavior.
type MonitorConfig struct {
	Enabled       bool   // Whether monitoring is enabled
	ScanInterval  int    // Scan interval in seconds (default 300 = 5 min)
	MaxAlerts     int    // Maximum alerts to keep (default 50)
	LookbackHours int    // How far back to scan on startup (default 24)
	MaxMessageLen int    // Maximum message length before truncation (default 500)
	Categories    []string // Filter to specific categories (empty = all)
}

// Monitor collects and caches OS-level alerts from system logs.
type Monitor struct {
	cfg MonitorConfig
	log Logger

	mu           sync.RWMutex
	alerts       []Alert
	alertsByID   map[string]*Alert
	lastScanTime time.Time
	scanSince    time.Time
}

// Logger is a minimal logging interface for the monitor.
type Logger interface {
	Debug(msg string, keysAndValues ...any)
	Info(msg string, keysAndValues ...any)
	Warn(msg string, keysAndValues ...any)
	Error(msg string, keysAndValues ...any)
}

// noopLogger discards all log messages.
type noopLogger struct{}

func (noopLogger) Debug(string, ...any) {}
func (noopLogger) Info(string, ...any)  {}
func (noopLogger) Warn(string, ...any)  {}
func (noopLogger) Error(string, ...any) {}

// DefaultConfig returns sensible defaults for the monitor.
func DefaultConfig() MonitorConfig {
	return MonitorConfig{
		Enabled:       true,
		ScanInterval:  300, // 5 minutes
		MaxAlerts:     50,
		LookbackHours: 24,
		MaxMessageLen: 500,
		Categories:    nil, // all categories
	}
}

// NewMonitor creates a new alert monitor with the given configuration.
func NewMonitor(cfg MonitorConfig, log Logger) *Monitor {
	if log == nil {
		log = noopLogger{}
	}
	if cfg.MaxAlerts <= 0 {
		cfg.MaxAlerts = 50
	}
	if cfg.LookbackHours <= 0 {
		cfg.LookbackHours = 24
	}
	if cfg.MaxMessageLen <= 0 {
		cfg.MaxMessageLen = 500
	}
	if cfg.ScanInterval <= 0 {
		cfg.ScanInterval = 300
	}

	m := &Monitor{
		cfg:        cfg,
		log:        log,
		alerts:     make([]Alert, 0),
		alertsByID: make(map[string]*Alert),
		scanSince:  time.Now().Add(-time.Duration(cfg.LookbackHours) * time.Hour),
	}
	return m
}

// Snapshot returns the current alert snapshot for transmission.
// This is safe to call concurrently.
func (m *Monitor) Snapshot() *AlertSnapshot {
	if m == nil {
		return nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.alerts) == 0 {
		return &AlertSnapshot{
			Alerts:       []Alert{},
			Since:        m.scanSince.UTC().Format(time.RFC3339),
			TotalCount:   0,
			HasCritical:  false,
			LastScanTime: m.lastScanTime.UTC().Format(time.RFC3339),
		}
	}

	// Copy alerts (newest first)
	alerts := make([]Alert, len(m.alerts))
	copy(alerts, m.alerts)

	hasCritical := false
	for _, a := range alerts {
		if a.Severity == "critical" {
			hasCritical = true
			break
		}
	}

	return &AlertSnapshot{
		Alerts:       alerts,
		Since:        m.scanSince.UTC().Format(time.RFC3339),
		TotalCount:   len(alerts),
		HasCritical:  hasCritical,
		LastScanTime: m.lastScanTime.UTC().Format(time.RFC3339),
	}
}

// Scan collects new alerts from system logs. Call this periodically.
func (m *Monitor) Scan() {
	if m == nil || !m.cfg.Enabled {
		return
	}

	now := time.Now()
	entries := collectAlerts(m.scanSince, m.cfg.Categories, m.log)
	m.processEntries(entries, now)
	m.lastScanTime = now
}

// processEntries adds new log entries, deduplicating and enforcing limits.
func (m *Monitor) processEntries(entries []logEntry, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, entry := range entries {
		alert := m.entryToAlert(entry, now)
		if alert == nil {
			continue
		}

		// Check if we already have this alert (dedupe by ID)
		if existing, ok := m.alertsByID[alert.ID]; ok {
			existing.Count++
			// Update timestamp to most recent occurrence
			existing.Timestamp = alert.Timestamp
			continue
		}

		// Add new alert
		m.alerts = append(m.alerts, *alert)
		m.alertsByID[alert.ID] = &m.alerts[len(m.alerts)-1]
	}

	// Sort by timestamp (newest first) and enforce limit
	sort.Slice(m.alerts, func(i, j int) bool {
		return m.alerts[i].Timestamp > m.alerts[j].Timestamp
	})

	if len(m.alerts) > m.cfg.MaxAlerts {
		// Remove oldest alerts
		for _, a := range m.alerts[m.cfg.MaxAlerts:] {
			delete(m.alertsByID, a.ID)
		}
		m.alerts = m.alerts[:m.cfg.MaxAlerts]
	}

	// Update alertsByID pointers after sort
	m.alertsByID = make(map[string]*Alert)
	for i := range m.alerts {
		m.alertsByID[m.alerts[i].ID] = &m.alerts[i]
	}
}

// entryToAlert converts a log entry to an Alert, returning nil if it doesn't match.
func (m *Monitor) entryToAlert(entry logEntry, now time.Time) *Alert {
	match := classifyMessage(entry.message)
	if match == nil {
		return nil
	}

	// Truncate message if needed
	msg := entry.message
	if len(msg) > m.cfg.MaxMessageLen {
		msg = msg[:m.cfg.MaxMessageLen-3] + "..."
	}

	// Generate dedup ID from category + truncated message hash
	// Round timestamp to minute for grouping similar alerts
	truncatedTs := entry.timestamp.Truncate(time.Minute).UTC().Format(time.RFC3339)
	idInput := match.category + "|" + truncatedTs + "|" + msg
	hash := sha256.Sum256([]byte(idInput))
	id := hex.EncodeToString(hash[:8]) // 16-char hex ID

	return &Alert{
		ID:        id,
		Timestamp: entry.timestamp.UTC().Format(time.RFC3339),
		Severity:  match.severity,
		Category:  match.category,
		Message:   msg,
		Source:    entry.source,
		Count:     1,
	}
}

// logEntry represents a parsed log line from the system.
type logEntry struct {
	timestamp time.Time
	message   string
	source    string // "kmsg", "journald", "dmesg"
	level     int    // kernel log level (0-7)
}
