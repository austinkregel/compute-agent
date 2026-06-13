package transport

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"nhooyr.io/websocket"

	"github.com/austinkregel/compute-agent/pkg/cmdsig"
	"github.com/austinkregel/compute-agent/pkg/logging"
)

func TestHandshakeURL(t *testing.T) {
	cfg := Config{
		ServerURL:  "https://example.com",
		ClientID:   "test-client",
		AuthToken:  "secret-token",
		SocketPath: "/ws/agent",
	}

	client := &Client{cfg: cfg}

	urlStr, err := client.handshakeURL()
	if err != nil {
		t.Fatalf("handshakeURL: %v", err)
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}

	// Check path
	if u.Path != "/ws/agent" {
		t.Errorf("expected path '/ws/agent', got %q", u.Path)
	}

	// Check query parameters
	q := u.Query()
	if q.Get("clientId") != "test-client" {
		t.Errorf("expected clientId 'test-client', got %q", q.Get("clientId"))
	}

	tsStr := q.Get("ts")
	if tsStr == "" {
		t.Error("expected timestamp in query params")
	}

	sig := q.Get("sig")
	if sig == "" {
		t.Error("expected signature in query params")
	}

	// Verify signature
	payload := `{"clientId":"test-client","ts":` + tsStr + `}`
	expectedSig := hmac.New(sha256.New, []byte("secret-token"))
	expectedSig.Write([]byte(payload))
	expectedSigHex := hex.EncodeToString(expectedSig.Sum(nil))

	if sig != expectedSigHex {
		t.Errorf("signature mismatch: got %q, expected %q", sig, expectedSigHex)
	}
}

func TestNextDelay(t *testing.T) {
	tests := []struct {
		name     string
		current  time.Duration
		max      time.Duration
		expected time.Duration
	}{
		{
			name:     "exponential backoff",
			current:  time.Second,
			max:      30 * time.Second,
			expected: 2 * time.Second,
		},
		{
			name:     "doubles again",
			current:  2 * time.Second,
			max:      30 * time.Second,
			expected: 4 * time.Second,
		},
		{
			name:     "capped at max",
			current:  20 * time.Second,
			max:      30 * time.Second,
			expected: 30 * time.Second,
		},
		{
			name:     "exactly at max",
			current:  30 * time.Second,
			max:      30 * time.Second,
			expected: 30 * time.Second,
		},
		{
			name:     "over max",
			current:  40 * time.Second,
			max:      30 * time.Second,
			expected: 30 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nextDelay(tt.current, tt.max)
			if got != tt.expected {
				t.Errorf("nextDelay() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNew_Validation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: Config{
				ServerURL:  "https://example.com",
				ClientID:   "test",
				AuthToken:  "token",
				SocketPath: "/ws/agent",
			},
			wantErr: false,
		},
		{
			name: "missing server URL",
			cfg: Config{
				ClientID:  "test",
				AuthToken: "token",
			},
			wantErr: true,
		},
		{
			name: "missing client ID",
			cfg: Config{
				ServerURL: "https://example.com",
				AuthToken: "token",
			},
			wantErr: true,
		},
		{
			name: "missing auth token",
			cfg: Config{
				ServerURL: "https://example.com",
				ClientID:  "test",
			},
			wantErr: true,
		},
		{
			name: "whitespace server URL",
			cfg: Config{
				ServerURL:  "   ",
				ClientID:   "test",
				AuthToken:  "token",
				SocketPath: "/ws/agent",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.cfg, nil, Handlers{})
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNew_Defaults(t *testing.T) {
	cfg := Config{
		ServerURL: "https://example.com",
		ClientID:  "test",
		AuthToken: "token",
	}

	client, err := New(cfg, nil, Handlers{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if client.cfg.SocketPath != "/ws/agent" {
		t.Errorf("expected default socket path '/ws/agent', got %q", client.cfg.SocketPath)
	}
	if client.cfg.ReconnectMin != time.Second {
		t.Errorf("expected default ReconnectMin 1s, got %v", client.cfg.ReconnectMin)
	}
	if client.cfg.ReconnectMax != 30*time.Second {
		t.Errorf("expected default ReconnectMax 30s, got %v", client.cfg.ReconnectMax)
	}
	if client.cfg.HeartbeatInterval != 20*time.Second {
		t.Errorf("expected default HeartbeatInterval 20s, got %v", client.cfg.HeartbeatInterval)
	}
	if client.cfg.PongTimeout != 90*time.Second {
		t.Errorf("expected default PongTimeout 90s, got %v", client.cfg.PongTimeout)
	}
}

func TestEmit_NotConnected(t *testing.T) {
	cfg := Config{
		ServerURL:  "https://example.com",
		ClientID:   "test",
		AuthToken:  "token",
		SocketPath: "/ws/agent",
	}

	client, err := New(cfg, nil, Handlers{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	err = client.Emit("test_event", map[string]string{"key": "value"})
	if err != ErrNotConnected {
		t.Errorf("Emit() error = %v, want %v", err, ErrNotConnected)
	}
}

func TestRegisterEventHandlers(t *testing.T) {
	cfg := Config{
		ServerURL:  "https://example.com",
		ClientID:   "test",
		AuthToken:  "token",
		SocketPath: "/ws/agent",
	}

	handlers := Handlers{
		Hello:         func() {},
		AdminRun:      func(AdminCommand) {},
		ShellStart:    func(ShellStart) {},
		ShellInput:    func(ShellInput) {},
		ShellResize:   func(ShellResize) {},
		ShellClose:    func(ShellClose) {},
		BackupPlan:    func(BackupRequest) {},
		BackupStart:   func(BackupRequest) {},
		SyncKeys:      func(SyncKeysRequest) {},
		UpdateAgent:   func(UpdateAgentRequest) {},
	}

	client, err := New(cfg, nil, handlers)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if client.handlers.Hello == nil {
		t.Error("Hello handler not set")
	}
	if client.handlers.AdminRun == nil {
		t.Error("AdminRun handler not set")
	}
	if client.handlers.ShellStart == nil {
		t.Error("ShellStart handler not set")
	}
	if client.handlers.ShellInput == nil {
		t.Error("ShellInput handler not set")
	}
	if client.handlers.ShellResize == nil {
		t.Error("ShellResize handler not set")
	}
	if client.handlers.ShellClose == nil {
		t.Error("ShellClose handler not set")
	}
	if client.handlers.BackupPlan == nil {
		t.Error("BackupPlan handler not set")
	}
	if client.handlers.BackupStart == nil {
		t.Error("BackupStart handler not set")
	}
	if client.handlers.SyncKeys == nil {
		t.Error("SyncKeys handler not set")
	}
	if client.handlers.UpdateAgent == nil {
		t.Error("UpdateAgent handler not set")
	}
}

func TestRegisterEventHandlers_NilHandlers(t *testing.T) {
	cfg := Config{
		ServerURL:  "https://example.com",
		ClientID:   "test",
		AuthToken:  "token",
		SocketPath: "/ws/agent",
	}

	handlers := Handlers{}

	client, err := New(cfg, nil, handlers)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if client.handlers.Hello != nil {
		t.Error("expected nil Hello handler")
	}
}

func TestHTTPTransport_SkipTLSVerify(t *testing.T) {
	cfg := Config{
		ServerURL:     "https://example.com",
		ClientID:      "test",
		AuthToken:     "token",
		SkipTLSVerify: true,
	}

	client := &Client{cfg: cfg}

	transport := client.httpTransport()
	if transport == nil {
		t.Fatal("httpTransport() returned nil")
	}

	tr, ok := transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", transport)
	}
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("expected InsecureSkipVerify=true when SkipTLSVerify enabled")
	}
}

func TestHTTPTransport_NoSkipTLSVerify(t *testing.T) {
	cfg := Config{
		ServerURL:     "https://example.com",
		ClientID:      "test",
		AuthToken:     "token",
		SkipTLSVerify: false,
	}

	client := &Client{cfg: cfg}

	transport := client.httpTransport()
	if transport == nil {
		t.Fatal("httpTransport() returned nil")
	}

	tr, ok := transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", transport)
	}
	if tr.TLSClientConfig != nil && tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=false when SkipTLSVerify is disabled")
	}
}

func TestHandshakeURL_SignatureFormat(t *testing.T) {
	cfg := Config{
		ServerURL:  "https://example.com",
		ClientID:   "test-client",
		AuthToken:  "secret",
		SocketPath: "/ws/agent",
	}

	client := &Client{cfg: cfg}

	url1, err := client.handshakeURL()
	if err != nil {
		t.Fatalf("handshakeURL: %v", err)
	}

	// Call again to verify different timestamps produce different signatures
	time.Sleep(10 * time.Millisecond)
	url2, err := client.handshakeURL()
	if err != nil {
		t.Fatalf("handshakeURL: %v", err)
	}

	if url1 == url2 {
		t.Error("expected different URLs due to different timestamps")
	}

	// Verify both have valid hex signatures
	u1, _ := url.Parse(url1)
	u2, _ := url.Parse(url2)

	sig1 := u1.Query().Get("sig")
	sig2 := u2.Query().Get("sig")

	if len(sig1) != 64 { // SHA256 hex = 64 chars
		t.Errorf("expected 64-char hex signature, got %d chars", len(sig1))
	}

	if len(sig2) != 64 {
		t.Errorf("expected 64-char hex signature, got %d chars", len(sig2))
	}

	if _, err := hex.DecodeString(sig1); err != nil {
		t.Errorf("sig1 is not valid hex: %v", err)
	}
	if _, err := hex.DecodeString(sig2); err != nil {
		t.Errorf("sig2 is not valid hex: %v", err)
	}
}

func TestClient_TouchTraffic(t *testing.T) {
	client := &Client{cfg: Config{
		ServerURL: "https://example.com",
		ClientID:  "test",
		AuthToken: "token",
	}}

	if client.lastTraffic.Load() != 0 {
		t.Error("expected initial lastTraffic to be 0")
	}

	client.touchTraffic()
	if client.lastTraffic.Load() == 0 {
		t.Error("expected lastTraffic to be set after touchTraffic()")
	}

	now := time.Now().UnixNano()
	diff := now - client.lastTraffic.Load()
	if diff < 0 || diff > int64(time.Second) {
		t.Error("lastTraffic should be within the last second")
	}
}

func TestClient_HelloAcked(t *testing.T) {
	client := &Client{cfg: Config{
		ServerURL: "https://example.com",
		ClientID:  "test",
		AuthToken: "token",
	}}

	if client.helloAcked.Load() {
		t.Error("expected initial helloAcked to be false")
	}

	client.helloAcked.Store(true)
	if !client.helloAcked.Load() {
		t.Error("expected helloAcked to be true after Store(true)")
	}
}

func TestClient_CurrentConn_NilWhenNotSet(t *testing.T) {
	client := &Client{cfg: Config{
		ServerURL: "https://example.com",
		ClientID:  "test",
		AuthToken: "token",
	}}

	if conn := client.currentConn(); conn != nil {
		t.Error("expected nil conn when not connected")
	}
}

func TestNew_CustomTimeouts(t *testing.T) {
	cfg := Config{
		ServerURL:         "https://example.com",
		ClientID:          "test",
		AuthToken:         "token",
		SocketPath:        "/ws/agent",
		ReconnectMin:      5 * time.Second,
		ReconnectMax:      60 * time.Second,
		HeartbeatInterval: 30 * time.Second,
		PongTimeout:       120 * time.Second,
	}

	client, err := New(cfg, nil, Handlers{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if client.cfg.ReconnectMin != 5*time.Second {
		t.Errorf("expected ReconnectMin 5s, got %v", client.cfg.ReconnectMin)
	}
	if client.cfg.ReconnectMax != 60*time.Second {
		t.Errorf("expected ReconnectMax 60s, got %v", client.cfg.ReconnectMax)
	}
	if client.cfg.HeartbeatInterval != 30*time.Second {
		t.Errorf("expected HeartbeatInterval 30s, got %v", client.cfg.HeartbeatInterval)
	}
	if client.cfg.PongTimeout != 120*time.Second {
		t.Errorf("expected PongTimeout 120s, got %v", client.cfg.PongTimeout)
	}
}

func TestNextDelay_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		current  time.Duration
		max      time.Duration
		expected time.Duration
	}{
		{
			name:     "zero current",
			current:  0,
			max:      30 * time.Second,
			expected: 0,
		},
		{
			name:     "negative current doubles",
			current:  -1 * time.Second,
			max:      30 * time.Second,
			expected: -2 * time.Second,
		},
		{
			name:     "small max",
			current:  100 * time.Millisecond,
			max:      150 * time.Millisecond,
			expected: 150 * time.Millisecond,
		},
		{
			name:     "equal values",
			current:  10 * time.Second,
			max:      10 * time.Second,
			expected: 10 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nextDelay(tt.current, tt.max)
			if got != tt.expected {
				t.Errorf("nextDelay(%v, %v) = %v, want %v", tt.current, tt.max, got, tt.expected)
			}
		})
	}
}

// --- Type-level tests (unchanged) ---

func TestDirListEntry_Fields(t *testing.T) {
	entry := DirListEntry{
		Name:       "testfile.txt",
		Type:       "file",
		Size:       1024,
		Mode:       "-rw-r--r--",
		ModTime:    "2024-01-15T10:30:00Z",
		IsSymlink:  false,
		LinkTarget: "",
	}

	if entry.Name != "testfile.txt" {
		t.Errorf("Name = %q, want %q", entry.Name, "testfile.txt")
	}
	if entry.Type != "file" {
		t.Errorf("Type = %q, want %q", entry.Type, "file")
	}
	if entry.Size != 1024 {
		t.Errorf("Size = %d, want %d", entry.Size, 1024)
	}
}

func TestDirListRequest_Fields(t *testing.T) {
	req := DirListRequest{
		ClientID:  "client-1",
		RequestID: "req-1",
		Mode:      "remote",
		Path:      "/home/user",
		Host:      "example.com",
		User:      "testuser",
		Port:      22,
		Protocol:  "ssh",
	}

	if req.Mode != "remote" {
		t.Errorf("Mode = %q, want %q", req.Mode, "remote")
	}
	if req.Host != "example.com" {
		t.Errorf("Host = %q, want %q", req.Host, "example.com")
	}
}

func TestFilePutStartRequest_Fields(t *testing.T) {
	req := FilePutStartRequest{
		ClientID:  "client-1",
		RequestID: "upload-1",
		Path:      "/tmp/upload.txt",
		Size:      2048,
		Mode:      "0644",
		Force:     true,
		Overwrite: true,
	}

	if req.Size != 2048 {
		t.Errorf("Size = %d, want %d", req.Size, 2048)
	}
	if !req.Force {
		t.Error("Force should be true")
	}
	if !req.Overwrite {
		t.Error("Overwrite should be true")
	}
}

func TestFileDeleteRequest_Fields(t *testing.T) {
	req := FileDeleteRequest{
		ClientID:  "client-1",
		RequestID: "delete-1",
		Path:      "/tmp/todelete.txt",
		Force:     false,
		Recursive: true,
	}

	if !req.Recursive {
		t.Error("Recursive should be true")
	}
	if req.Force {
		t.Error("Force should be false")
	}
}

func TestFileChmodRequest_Fields(t *testing.T) {
	req := FileChmodRequest{
		ClientID:  "client-1",
		RequestID: "chmod-1",
		Path:      "/tmp/file.txt",
		Mode:      "0755",
		Force:     true,
	}

	if req.Mode != "0755" {
		t.Errorf("Mode = %q, want %q", req.Mode, "0755")
	}
}

func TestKioskSetRequest_Fields(t *testing.T) {
	req := KioskSetRequest{
		RequestID: "kiosk-1",
		Content: KioskContent{
			Kind:  "message",
			Title: "Welcome",
			Text:  "Hello, World!",
		},
		TS: "2024-01-15T10:30:00Z",
	}

	if req.Content.Kind != "message" {
		t.Errorf("Content.Kind = %q, want %q", req.Content.Kind, "message")
	}
	if req.Content.Title != "Welcome" {
		t.Errorf("Content.Title = %q, want %q", req.Content.Title, "Welcome")
	}
	if req.Content.Text != "Hello, World!" {
		t.Errorf("Content.Text = %q, want %q", req.Content.Text, "Hello, World!")
	}
}

func TestKioskContent_Variants(t *testing.T) {
	tests := []struct {
		name    string
		content KioskContent
	}{
		{
			name:    "blank content",
			content: KioskContent{Kind: "blank"},
		},
		{
			name: "message content",
			content: KioskContent{
				Kind:  "message",
				Title: "Title",
				Text:  "Text",
			},
		},
		{
			name: "url content",
			content: KioskContent{
				Kind: "url",
				URL:  "https://example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.content.Kind == "" {
				t.Error("Kind should not be empty")
			}
		})
	}
}

func TestKioskStatus_Fields(t *testing.T) {
	status := KioskStatus{
		Running:   true,
		Connected: true,
		Content: KioskContent{
			Kind: "url",
			URL:  "https://example.com",
		},
		LastError: "",
		TS:        "2024-01-15T10:30:00Z",
	}

	if !status.Running {
		t.Error("Running should be true")
	}
	if !status.Connected {
		t.Error("Connected should be true")
	}
	if status.Content.Kind != "url" {
		t.Errorf("Content.Kind = %q, want %q", status.Content.Kind, "url")
	}
}

// --- WebSocket integration tests ---

// mockWSServer creates a test WebSocket server that speaks the agent protocol.
func mockWSServer(t *testing.T, handler func(conn *websocket.Conn)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true,
		})
		if err != nil {
			t.Logf("websocket accept error: %v", err)
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "")
		handler(conn)
	}))
}

func testLog(t *testing.T) *logging.Logger {
	t.Helper()
	l, err := logging.New(logging.Options{Level: "error"})
	if err != nil {
		t.Fatalf("create test logger: %v", err)
	}
	return l
}

func sendJSON(conn *websocket.Conn, msg Message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return conn.Write(context.Background(), websocket.MessageText, data)
}

func TestConnectOnce_HelloAck(t *testing.T) {
	helloCalled := make(chan struct{}, 1)

	srv := mockWSServer(t, func(conn *websocket.Conn) {
		nonce, _ := cmdsig.GenerateSessionNonce()
		ackData, _ := json.Marshal(HelloAckPayload{SessionNonce: nonce})
		sendJSON(conn, Message{Event: "hello_ack", Data: ackData})

		// Keep connection open until client disconnects
		for {
			_, _, err := conn.Read(context.Background())
			if err != nil {
				return
			}
		}
	})
	defer srv.Close()

	cfg := Config{
		ServerURL:  srv.URL,
		ClientID:   "test",
		AuthToken:  "secret",
		SocketPath: "/ws/agent",
	}

	client := &Client{
		cfg: cfg,
		log: testLog(t),
		handlers: Handlers{
			Hello: func() {
				helloCalled <- struct{}{}
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Run connectOnce in a goroutine (it blocks on the read loop)
	go func() {
		_ = client.connectOnce(ctx)
	}()

	select {
	case <-helloCalled:
		// Success - Hello handler was called
	case <-ctx.Done():
		t.Fatal("timeout waiting for hello callback")
	}

	if !client.helloAcked.Load() {
		t.Error("expected helloAcked to be true after hello_ack")
	}

	if client.getVerifier() == nil {
		t.Error("expected verifier to be set after hello_ack with nonce")
	}
}

func TestConnectOnce_PingPong(t *testing.T) {
	pongReceived := make(chan int64, 1)

	srv := mockWSServer(t, func(conn *websocket.Conn) {
		// Send hello_ack first
		nonce, _ := cmdsig.GenerateSessionNonce()
		ackData, _ := json.Marshal(HelloAckPayload{SessionNonce: nonce})
		sendJSON(conn, Message{Event: "hello_ack", Data: ackData})

		// Send a ping
		pingData, _ := json.Marshal(map[string]int64{"ts": 1234567890})
		sendJSON(conn, Message{Event: "ping", Data: pingData})

		// Read the pong response
		_, data, err := conn.Read(context.Background())
		if err != nil {
			return
		}
		var msg Message
		json.Unmarshal(data, &msg)
		if msg.Event == "pong" {
			var pong struct {
				TS int64 `json:"ts"`
			}
			json.Unmarshal(msg.Data, &pong)
			pongReceived <- pong.TS
		}
	})
	defer srv.Close()

	cfg := Config{
		ServerURL:  srv.URL,
		ClientID:   "test",
		AuthToken:  "secret",
		SocketPath: "/ws/agent",
	}

	client := &Client{
		cfg:      cfg,
		log:      testLog(t),
		handlers: Handlers{Hello: func() {}},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_ = client.connectOnce(ctx)
	}()

	select {
	case ts := <-pongReceived:
		if ts != 1234567890 {
			t.Errorf("expected pong ts 1234567890, got %d", ts)
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for pong")
	}
}

func TestConnectOnce_SignedCommand(t *testing.T) {
	shellStarted := make(chan string, 1)

	srv := mockWSServer(t, func(conn *websocket.Conn) {
		authToken := "secret"
		nonce, _ := cmdsig.GenerateSessionNonce()
		sessionKey := cmdsig.DeriveSessionKey(authToken, nonce)
		signer := cmdsig.NewSigner(sessionKey)

		// Send hello_ack
		ackData, _ := json.Marshal(HelloAckPayload{SessionNonce: nonce})
		sendJSON(conn, Message{Event: "hello_ack", Data: ackData})

		// Allow a small delay for the client to process hello_ack
		time.Sleep(50 * time.Millisecond)

		// Send signed shell_start command
		envelope, _ := signer.Sign("shell_start", map[string]string{"session": "sess-abc"})
		envData, _ := json.Marshal(envelope)
		sendJSON(conn, Message{Event: "signed_command", Data: envData})

		// Keep alive
		for {
			_, _, err := conn.Read(context.Background())
			if err != nil {
				return
			}
		}
	})
	defer srv.Close()

	cfg := Config{
		ServerURL:  srv.URL,
		ClientID:   "test",
		AuthToken:  "secret",
		SocketPath: "/ws/agent",
	}

	client := &Client{
		cfg: cfg,
		log: testLog(t),
		handlers: Handlers{
			Hello: func() {},
			ShellStart: func(msg ShellStart) {
				shellStarted <- msg.Session
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_ = client.connectOnce(ctx)
	}()

	select {
	case session := <-shellStarted:
		if session != "sess-abc" {
			t.Errorf("expected session 'sess-abc', got %q", session)
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for shell_start handler")
	}
}

func TestConnectOnce_RejectsUnsignedCommand(t *testing.T) {
	rejectionReceived := make(chan bool, 1)

	srv := mockWSServer(t, func(conn *websocket.Conn) {
		nonce, _ := cmdsig.GenerateSessionNonce()
		ackData, _ := json.Marshal(HelloAckPayload{SessionNonce: nonce})
		sendJSON(conn, Message{Event: "hello_ack", Data: ackData})

		time.Sleep(50 * time.Millisecond)

		// Send an unsigned admin_run directly (should be rejected/ignored)
		data, _ := json.Marshal(map[string]any{"cmd": map[string]string{"command": "evil"}})
		sendJSON(conn, Message{Event: "admin_run", Data: data})

		// Keep alive for a bit
		time.Sleep(200 * time.Millisecond)
		rejectionReceived <- true
	})
	defer srv.Close()

	adminCalled := false

	cfg := Config{
		ServerURL:  srv.URL,
		ClientID:   "test",
		AuthToken:  "secret",
		SocketPath: "/ws/agent",
	}

	client := &Client{
		cfg: cfg,
		log: testLog(t),
		handlers: Handlers{
			Hello: func() {},
			AdminRun: func(cmd AdminCommand) {
				adminCalled = true
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_ = client.connectOnce(ctx)
	}()

	select {
	case <-rejectionReceived:
		// Expected
	case <-ctx.Done():
		t.Fatal("timeout")
	}

	if adminCalled {
		t.Error("admin handler should NOT have been called for unsigned command")
	}
}

func TestEmit_SendsJSONEnvelope(t *testing.T) {
	received := make(chan Message, 1)

	srv := mockWSServer(t, func(conn *websocket.Conn) {
		// Send hello_ack
		nonce, _ := cmdsig.GenerateSessionNonce()
		ackData, _ := json.Marshal(HelloAckPayload{SessionNonce: nonce})
		sendJSON(conn, Message{Event: "hello_ack", Data: ackData})

		// Read the first message the agent sends
		_, data, err := conn.Read(context.Background())
		if err != nil {
			return
		}
		var msg Message
		json.Unmarshal(data, &msg)
		received <- msg
	})
	defer srv.Close()

	cfg := Config{
		ServerURL:  srv.URL,
		ClientID:   "test",
		AuthToken:  "secret",
		SocketPath: "/ws/agent",
	}

	ready := make(chan struct{}, 1)
	client := &Client{
		cfg: cfg,
		log: testLog(t),
		handlers: Handlers{
			Hello: func() {
				ready <- struct{}{}
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_ = client.connectOnce(ctx)
	}()

	// Wait for connection to be established
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal("timeout waiting for connection")
	}

	// Emit a stats event
	err := client.Emit("stats", map[string]any{"cpu": 42.5})
	if err != nil {
		t.Fatalf("Emit error: %v", err)
	}

	select {
	case msg := <-received:
		if msg.Event != "stats" {
			t.Errorf("expected event 'stats', got %q", msg.Event)
		}
		var data map[string]any
		json.Unmarshal(msg.Data, &data)
		if data["cpu"] != 42.5 {
			t.Errorf("expected cpu 42.5, got %v", data["cpu"])
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for emitted message")
	}
}

func TestDispatchSignedCommand_AllEvents(t *testing.T) {
	events := []string{
		"admin_run", "shell_start", "shell_input", "shell_resize", "shell_close",
		"log_tail_start", "log_tail_stop",
		"backup_plan", "backup_start",
		"sync_keys", "agent_update", "switch_variant", "check_updates",
		"dir_list_request", "exec_request", "exec_allowlist", "file_get_request",
		"file_put_start", "file_put_chunk", "file_put_finish",
		"file_delete_request", "file_chmod_request",
		"file_mkdir_request", "file_rename_request",
		"kiosk_set",
	}

	for _, event := range events {
		t.Run(event, func(t *testing.T) {
			called := false
			var mu sync.Mutex

			handlers := Handlers{}
			switch event {
			case "admin_run":
				handlers.AdminRun = func(AdminCommand) { mu.Lock(); called = true; mu.Unlock() }
			case "shell_start":
				handlers.ShellStart = func(ShellStart) { mu.Lock(); called = true; mu.Unlock() }
			case "shell_input":
				handlers.ShellInput = func(ShellInput) { mu.Lock(); called = true; mu.Unlock() }
			case "shell_resize":
				handlers.ShellResize = func(ShellResize) { mu.Lock(); called = true; mu.Unlock() }
			case "shell_close":
				handlers.ShellClose = func(ShellClose) { mu.Lock(); called = true; mu.Unlock() }
			case "log_tail_start":
				handlers.LogTailStart = func(LogTailStart) { mu.Lock(); called = true; mu.Unlock() }
			case "log_tail_stop":
				handlers.LogTailStop = func(LogTailStop) { mu.Lock(); called = true; mu.Unlock() }
			case "backup_plan":
				handlers.BackupPlan = func(BackupRequest) { mu.Lock(); called = true; mu.Unlock() }
			case "backup_start":
				handlers.BackupStart = func(BackupRequest) { mu.Lock(); called = true; mu.Unlock() }
			case "sync_keys":
				handlers.SyncKeys = func(SyncKeysRequest) { mu.Lock(); called = true; mu.Unlock() }
			case "agent_update":
				handlers.UpdateAgent = func(UpdateAgentRequest) { mu.Lock(); called = true; mu.Unlock() }
			case "switch_variant":
				handlers.SwitchVariant = func(SwitchVariantRequest) { mu.Lock(); called = true; mu.Unlock() }
			case "check_updates":
				handlers.CheckUpdates = func(CheckUpdatesRequest) { mu.Lock(); called = true; mu.Unlock() }
			case "dir_list_request":
				handlers.DirList = func(DirListRequest) { mu.Lock(); called = true; mu.Unlock() }
			case "exec_request":
				handlers.Exec = func(ExecRequest) { mu.Lock(); called = true; mu.Unlock() }
			case "exec_allowlist":
				handlers.ExecAllowlist = func(ExecAllowlist) { mu.Lock(); called = true; mu.Unlock() }
			case "file_get_request":
				handlers.FileGet = func(FileGetRequest) { mu.Lock(); called = true; mu.Unlock() }
			case "file_put_start":
				handlers.FilePutStart = func(FilePutStartRequest) { mu.Lock(); called = true; mu.Unlock() }
			case "file_put_chunk":
				handlers.FilePutChunk = func(FilePutChunk) { mu.Lock(); called = true; mu.Unlock() }
			case "file_put_finish":
				handlers.FilePutFinish = func(FilePutFinishRequest) { mu.Lock(); called = true; mu.Unlock() }
			case "file_delete_request":
				handlers.FileDelete = func(FileDeleteRequest) { mu.Lock(); called = true; mu.Unlock() }
			case "file_chmod_request":
				handlers.FileChmod = func(FileChmodRequest) { mu.Lock(); called = true; mu.Unlock() }
			case "file_mkdir_request":
				handlers.FileMkdir = func(FileMkdirRequest) { mu.Lock(); called = true; mu.Unlock() }
			case "file_rename_request":
				handlers.FileRename = func(FileRenameRequest) { mu.Lock(); called = true; mu.Unlock() }
			case "kiosk_set":
				handlers.KioskSet = func(KioskSetRequest) { mu.Lock(); called = true; mu.Unlock() }
			}

			client := &Client{
				cfg: Config{
					ServerURL: "https://example.com",
					ClientID:  "test",
					AuthToken: "token",
				},
				handlers: handlers,
			}

			// Build a minimal valid payload for each event
			payload, _ := json.Marshal(map[string]any{})
			client.dispatchSignedCommand(event, payload)

			mu.Lock()
			defer mu.Unlock()
			if !called {
				t.Errorf("handler for %q was not called", event)
			}
		})
	}
}

func TestHandshakeURL_UsesSocketPath(t *testing.T) {
	tests := []struct {
		name       string
		serverURL  string
		socketPath string
		wantPath   string
	}{
		{
			name:       "default path",
			serverURL:  "https://example.com",
			socketPath: "/ws/agent",
			wantPath:   "/ws/agent",
		},
		{
			name:       "custom path",
			serverURL:  "https://example.com",
			socketPath: "/custom/ws",
			wantPath:   "/custom/ws",
		},
		{
			name:       "with port",
			serverURL:  "https://example.com:8443",
			socketPath: "/ws/agent",
			wantPath:   "/ws/agent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &Client{cfg: Config{
				ServerURL:  tt.serverURL,
				ClientID:   "test",
				AuthToken:  "token",
				SocketPath: tt.socketPath,
			}}

			urlStr, err := client.handshakeURL()
			if err != nil {
				t.Fatalf("handshakeURL error: %v", err)
			}

			u, _ := url.Parse(urlStr)
			if u.Path != tt.wantPath {
				t.Errorf("path = %q, want %q", u.Path, tt.wantPath)
			}
		})
	}
}

func TestMessage_JSONRoundTrip(t *testing.T) {
	original := Message{
		Event: "test_event",
		Data:  json.RawMessage(`{"key":"value"}`),
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Message
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Event != original.Event {
		t.Errorf("event = %q, want %q", decoded.Event, original.Event)
	}
	if string(decoded.Data) != string(original.Data) {
		t.Errorf("data = %s, want %s", decoded.Data, original.Data)
	}
}

func TestNew_InvalidServerURL(t *testing.T) {
	cfg := Config{
		ServerURL: "://invalid",
		ClientID:  "test",
		AuthToken: "token",
	}

	_, err := New(cfg, nil, Handlers{})
	if err == nil {
		t.Error("expected error for invalid server URL")
	}
	if !strings.Contains(err.Error(), "parse server URL") {
		t.Errorf("expected parse error, got: %v", err)
	}
}
