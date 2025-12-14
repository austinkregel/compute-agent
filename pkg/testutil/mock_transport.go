package testutil

import (
	"sync"
)

// MockEmitter implements transport.Emitter for testing.
// It records all emitted events for assertion.
type MockEmitter struct {
	mu       sync.RWMutex
	events   []EmittedEvent
	connected bool
}

// EmittedEvent captures an event emission for testing.
type EmittedEvent struct {
	Event   string
	Payload any
}

// NewMockEmitter creates a new mock emitter.
func NewMockEmitter() *MockEmitter {
	return &MockEmitter{
		events:    make([]EmittedEvent, 0),
		connected: true,
	}
}

// Emit records the event and payload.
func (m *MockEmitter) Emit(event string, payload any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, EmittedEvent{
		Event:   event,
		Payload: payload,
	})
	return nil
}

// Events returns all emitted events.
func (m *MockEmitter) Events() []EmittedEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]EmittedEvent, len(m.events))
	copy(result, m.events)
	return result
}

// Clear removes all recorded events.
func (m *MockEmitter) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = m.events[:0]
}

// SetConnected sets the connection state.
func (m *MockEmitter) SetConnected(connected bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connected = connected
}

// IsConnected returns the connection state.
func (m *MockEmitter) IsConnected() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.connected
}

// FindEvent returns the first event matching the event name, or nil.
func (m *MockEmitter) FindEvent(eventName string) *EmittedEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for i := range m.events {
		if m.events[i].Event == eventName {
			return &m.events[i]
		}
	}
	return nil
}

// CountEvents returns the number of events with the given name.
func (m *MockEmitter) CountEvents(eventName string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	count := 0
	for i := range m.events {
		if m.events[i].Event == eventName {
			count++
		}
	}
	return count
}




