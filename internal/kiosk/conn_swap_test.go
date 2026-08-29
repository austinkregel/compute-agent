package kiosk

import (
	"testing"

	"nhooyr.io/websocket"
)

// A page that reconnects before the old socket's handler exits must not be
// disconnected by that handler's cleanup. Before this was fixed, the exiting
// handler nil'd the shared field and silently disabled every content/stats
// push while the page sat there rendering a frozen layout.
func TestClearWSConn_IgnoresSupersededConnection(t *testing.T) {
	m := &manager{}

	// Two distinct non-nil connection identities; never dialed, only compared.
	connA := &websocket.Conn{}
	connB := &websocket.Conn{}

	if prev := m.setWSConn(connA); prev != nil {
		t.Fatalf("first setWSConn returned prev=%v, want nil", prev)
	}

	// Page reconnects: B supersedes A, and A is handed back for closing.
	prev := m.setWSConn(connB)
	if prev != connA {
		t.Fatalf("setWSConn(B) returned %v, want connA so the caller can close it", prev)
	}

	// A's handler now exits and runs its deferred cleanup.
	m.clearWSConn(connA)

	m.wsMu.Lock()
	live := m.wsConn
	m.wsMu.Unlock()
	if live != connB {
		t.Fatalf("live conn = %v after stale cleanup, want connB", live)
	}

	m.mu.RLock()
	connected := m.connected
	m.mu.RUnlock()
	if !connected {
		t.Error("connected = false after stale cleanup, want true")
	}
}

func TestClearWSConn_ClearsCurrentConnection(t *testing.T) {
	m := &manager{}
	conn := &websocket.Conn{}
	m.setWSConn(conn)
	m.clearWSConn(conn)

	m.wsMu.Lock()
	live := m.wsConn
	m.wsMu.Unlock()
	if live != nil {
		t.Fatalf("live conn = %v, want nil", live)
	}

	m.mu.RLock()
	connected := m.connected
	m.mu.RUnlock()
	if connected {
		t.Error("connected = true after clearing the live connection, want false")
	}
}
