package telephony

import (
	"context"

	"github.com/austinkregel/compute-agent/pkg/logging"
)

// Manager is the agent-facing API: it owns the companion Client and
// translates companion pushes into control-plane emits. Signed-command
// handlers (agent/internal/app) call its methods; agent.New wires Emit.
type Manager struct {
	client *Client
	log    *logging.Logger
	emit   func(event string, payload any) error
}

// NewManager creates a telephony manager. Call Run to start the companion
// connection loop.
func NewManager(cfg Config, log *logging.Logger, emit func(event string, payload any) error) *Manager {
	m := &Manager{log: log, emit: emit}
	m.client = NewClient(cfg, log)
	m.client.OnEvent = m.handleCompanionEvent
	return m
}

// Run blocks, maintaining the companion connection until ctx is canceled.
func (m *Manager) Run(ctx context.Context) error {
	return m.client.Run(ctx)
}

// Connected reports whether the companion app is currently reachable —
// backs the "telephony" capability probe (agent/internal/app/capabilities.go).
func (m *Manager) Connected() bool {
	return m.client.Connected()
}

func (m *Manager) handleCompanionEvent(event string, payload map[string]any) {
	switch event {
	case "sms.received":
		if err := m.emit("sms_received", payload); err != nil {
			m.log.Debug("failed to emit sms_received", "error", err)
		}
	default:
		m.log.Debug("unhandled companion event", "event", event)
	}
}

// HostTelemetry fetches platform telemetry the agent cannot read for itself.
//
// On Android the agent runs inside the companion app's uid, which cannot open
// /sys/class/power_supply or /sys/class/thermal. The app reads the same facts
// through BatteryManager and PowerManager and returns them here, so battery
// and thermal data survive the move onto a phone instead of being dropped.
func (m *Manager) HostTelemetry(ctx context.Context) (any, error) {
	return m.client.Request(ctx, "host.telemetry", map[string]any{})
}

// SendSMS sends a text message via the companion app.
func (m *Manager) SendSMS(ctx context.Context, to, body string) (map[string]any, error) {
	result, err := m.client.Request(ctx, "sms.send", map[string]any{"to": to, "body": body})
	if err != nil {
		return nil, err
	}
	obj, _ := result.(map[string]any)
	return obj, nil
}

// ListThreads lists SMS conversation threads (most recent first).
func (m *Manager) ListThreads(ctx context.Context, limit int) ([]any, error) {
	result, err := m.client.Request(ctx, "sms.threads", map[string]any{"limit": limit})
	if err != nil {
		return nil, err
	}
	arr, _ := result.([]any)
	return arr, nil
}

// ListMessages lists messages within one SMS thread (oldest first).
func (m *Manager) ListMessages(ctx context.Context, threadID string, limit int) ([]any, error) {
	result, err := m.client.Request(ctx, "sms.messages", map[string]any{"threadId": threadID, "limit": limit})
	if err != nil {
		return nil, err
	}
	arr, _ := result.([]any)
	return arr, nil
}
