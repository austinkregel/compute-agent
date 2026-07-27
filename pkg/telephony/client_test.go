package telephony

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/austinkregel/compute-agent/pkg/logging"
)

func testLog(t *testing.T) *logging.Logger {
	t.Helper()
	l, err := logging.New(logging.Options{Level: "error"})
	if err != nil {
		t.Fatalf("create test logger: %v", err)
	}
	return l
}

// fakeCompanion is a minimal companion-protocol server for tests: it accepts
// one connection, performs the hello handshake, and dispatches "request"
// messages to a caller-supplied responder.
//
// serveOnce runs on a background goroutine in every test (started via
// `go fc.serveOnce(t)`), so it must never call t.Fatal*/FailNow — those are
// only safe from the goroutine running the test function itself. Failures
// here use t.Errorf (safe from any goroutine) and return early instead.
type fakeCompanion struct {
	listener  net.Listener
	token     string
	responder func(op string, payload map[string]any) (ok bool, payload2 any, errMsg string)
}

func newFakeCompanion(t *testing.T, token string) *fakeCompanion {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	fc := &fakeCompanion{listener: ln, token: token}
	t.Cleanup(func() { ln.Close() })
	return fc
}

func (fc *fakeCompanion) addr() string { return fc.listener.Addr().String() }

// serveOnce accepts a single connection, handles the hello handshake, and
// (if accepted) serves requests on a further goroutine. Returns the accepted
// net.Conn, or nil if accept/handshake failed (caller must check).
func (fc *fakeCompanion) serveOnce(t *testing.T) net.Conn {
	t.Helper()
	conn, err := fc.listener.Accept()
	if err != nil {
		t.Errorf("accept: %v", err)
		return nil
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Errorf("read hello: %v", err)
		return nil
	}
	var hello struct {
		Type  string `json:"type"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(line), &hello); err != nil {
		t.Errorf("unmarshal hello: %v", err)
		return nil
	}
	ok := hello.Type == "hello" && hello.Token == fc.token
	if !writeJSONLine(t, conn, map[string]any{"type": "hello_ack", "ok": ok}) {
		return nil
	}
	if !ok {
		conn.Close()
		return conn
	}

	go func() {
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			var msg map[string]any
			if err := json.Unmarshal([]byte(line), &msg); err != nil {
				continue
			}
			if msg["type"] != "request" || fc.responder == nil {
				continue
			}
			id, _ := msg["id"].(string)
			op, _ := msg["op"].(string)
			payload, _ := msg["payload"].(map[string]any)
			ok, respPayload, errMsg := fc.responder(op, payload)
			resp := map[string]any{"type": "response", "id": id, "ok": ok}
			if ok {
				resp["payload"] = respPayload
			} else {
				resp["error"] = errMsg
			}
			writeJSONLine(t, conn, resp)
		}
	}()

	return conn
}

// writeJSONLine reports failures via t.Errorf (goroutine-safe) and returns
// false on failure instead of aborting the test.
func writeJSONLine(t *testing.T, conn net.Conn, v map[string]any) bool {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Errorf("marshal: %v", err)
		return false
	}
	if _, err := conn.Write(append(data, '\n')); err != nil {
		t.Errorf("write: %v", err)
		return false
	}
	return true
}

func waitForConnected(t *testing.T, c *Client) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c.Connected() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out waiting for companion connection")
}

func TestClient_HandshakeSuccess(t *testing.T) {
	fc := newFakeCompanion(t, "secret")
	go fc.serveOnce(t)

	client := NewClient(Config{CompanionAddr: fc.addr(), CompanionToken: "secret"}, testLog(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go client.Run(ctx)

	waitForConnected(t, client)
}

func TestClient_HandshakeRejected(t *testing.T) {
	fc := newFakeCompanion(t, "secret")
	go fc.serveOnce(t)

	client := NewClient(Config{CompanionAddr: fc.addr(), CompanionToken: "wrong-token"}, testLog(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go client.Run(ctx)

	// Give it time to attempt and fail the handshake; it should never report connected.
	time.Sleep(200 * time.Millisecond)
	if client.Connected() {
		t.Error("expected Connected() to stay false after a rejected handshake")
	}
}

func TestClient_Request_NotConnected(t *testing.T) {
	client := NewClient(Config{CompanionAddr: "127.0.0.1:1", CompanionToken: "x"}, testLog(t))
	_, err := client.Request(context.Background(), "sms.send", nil)
	if err != ErrNotConnected {
		t.Errorf("expected ErrNotConnected, got %v", err)
	}
}

func TestManager_SendSMS(t *testing.T) {
	fc := newFakeCompanion(t, "secret")
	fc.responder = func(op string, payload map[string]any) (bool, any, string) {
		if op != "sms.send" {
			return false, nil, "unexpected op"
		}
		return true, map[string]any{"messageId": "m1", "status": "sent", "to": payload["to"]}, ""
	}
	go fc.serveOnce(t)

	mgr := NewManager(Config{CompanionAddr: fc.addr(), CompanionToken: "secret"}, testLog(t), func(event string, payload any) error {
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go mgr.Run(ctx)
	waitForConnected(t, mgr.client)

	result, err := mgr.SendSMS(context.Background(), "+15551234", "hi")
	if err != nil {
		t.Fatalf("SendSMS: %v", err)
	}
	if result["messageId"] != "m1" || result["status"] != "sent" {
		t.Errorf("unexpected result: %+v", result)
	}
}

func TestManager_SendSMS_CompanionError(t *testing.T) {
	fc := newFakeCompanion(t, "secret")
	fc.responder = func(op string, payload map[string]any) (bool, any, string) {
		return false, nil, "sms permission not granted"
	}
	go fc.serveOnce(t)

	mgr := NewManager(Config{CompanionAddr: fc.addr(), CompanionToken: "secret"}, testLog(t), func(string, any) error { return nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go mgr.Run(ctx)
	waitForConnected(t, mgr.client)

	_, err := mgr.SendSMS(context.Background(), "+15551234", "hi")
	if err == nil || err.Error() != "sms permission not granted" {
		t.Errorf("expected companion error to propagate, got %v", err)
	}
}

func TestManager_ListThreadsAndMessages(t *testing.T) {
	fc := newFakeCompanion(t, "secret")
	fc.responder = func(op string, payload map[string]any) (bool, any, string) {
		switch op {
		case "sms.threads":
			return true, []any{map[string]any{"threadId": "1", "address": "+1555", "snippet": "hey"}}, ""
		case "sms.messages":
			return true, []any{map[string]any{"messageId": "m1", "body": "hey", "direction": "in"}}, ""
		default:
			return false, nil, "unexpected op"
		}
	}
	go fc.serveOnce(t)

	mgr := NewManager(Config{CompanionAddr: fc.addr(), CompanionToken: "secret"}, testLog(t), func(string, any) error { return nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go mgr.Run(ctx)
	waitForConnected(t, mgr.client)

	threads, err := mgr.ListThreads(context.Background(), 50)
	if err != nil {
		t.Fatalf("ListThreads: %v", err)
	}
	if len(threads) != 1 {
		t.Fatalf("expected 1 thread, got %d", len(threads))
	}

	messages, err := mgr.ListMessages(context.Background(), "1", 200)
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}
}

func TestManager_PushEvent_TranslatesToEmit(t *testing.T) {
	fc := newFakeCompanion(t, "secret")
	connCh := make(chan net.Conn, 1)
	go func() { connCh <- fc.serveOnce(t) }()

	emitted := make(chan struct {
		event   string
		payload any
	}, 1)
	mgr := NewManager(Config{CompanionAddr: fc.addr(), CompanionToken: "secret"}, testLog(t), func(event string, payload any) error {
		emitted <- struct {
			event   string
			payload any
		}{event, payload}
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go mgr.Run(ctx)
	waitForConnected(t, mgr.client)

	conn := <-connCh
	if conn == nil {
		t.Fatal("fake companion failed to accept connection")
	}
	writeJSONLine(t, conn, map[string]any{
		"type": "event", "event": "sms.received",
		"payload": map[string]any{"address": "+1555", "body": "hello"},
	})

	select {
	case e := <-emitted:
		if e.event != "sms_received" {
			t.Errorf("expected sms_received, got %q", e.event)
		}
		payload, _ := e.payload.(map[string]any)
		if payload["address"] != "+1555" {
			t.Errorf("unexpected payload: %+v", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for pushed event")
	}
}
