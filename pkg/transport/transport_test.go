package transport

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"testing"
	"time"
)

func TestHandshakeURL(t *testing.T) {
	cfg := Config{
		ServerURL:  "https://example.com",
		ClientID:   "test-client",
		AuthToken:  "secret-token",
		SocketPath: "/socket.io",
	}

	baseURL, err := buildBaseURL(cfg.ServerURL, cfg.SocketPath)
	if err != nil {
		t.Fatalf("buildBaseURL: %v", err)
	}

	client := &Client{
		cfg:     cfg,
		baseURL: baseURL,
	}

	urlStr, err := client.handshakeURL()
	if err != nil {
		t.Fatalf("handshakeURL: %v", err)
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
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

func TestBuildBaseURL(t *testing.T) {
	tests := []struct {
		name       string
		serverURL  string
		socketPath string
		wantPath   string
		wantErr    bool
	}{
		{
			name:       "simple URL",
			serverURL:  "https://example.com",
			socketPath: "/socket.io",
			wantPath:   "/socket.io/",
		},
		{
			name:       "URL with trailing slash",
			serverURL:  "https://example.com/",
			socketPath: "/socket.io",
			wantPath:   "/socket.io/",
		},
		{
			name:       "URL with path",
			serverURL:  "https://example.com/api",
			socketPath: "/socket.io",
			wantPath:   "/api/socket.io/",
		},
		{
			name:       "socket path without leading slash",
			serverURL:  "https://example.com",
			socketPath: "socket.io",
			wantPath:   "/socket.io/",
		},
		{
			name:       "invalid URL",
			serverURL:  "://invalid",
			socketPath: "/socket.io",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := buildBaseURL(tt.serverURL, tt.socketPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("buildBaseURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if u.Path != tt.wantPath {
				t.Errorf("buildBaseURL() path = %q, want %q", u.Path, tt.wantPath)
			}
			if u.RawQuery != "" {
				t.Errorf("buildBaseURL() RawQuery = %q, want empty", u.RawQuery)
			}
			if u.Fragment != "" {
				t.Errorf("buildBaseURL() Fragment = %q, want empty", u.Fragment)
			}
		})
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
				Namespace:  "/agents",
				SocketPath: "/socket.io",
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
				SocketPath: "/socket.io",
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
		ServerURL:  "https://example.com",
		ClientID:   "test",
		AuthToken:  "token",
		SocketPath: "",
	}

	client, err := New(cfg, nil, Handlers{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if client.cfg.Namespace != "/agents" {
		t.Errorf("expected default namespace '/agents', got %q", client.cfg.Namespace)
	}
	if client.cfg.SocketPath != "/socket.io" {
		t.Errorf("expected default socket path '/socket.io', got %q", client.cfg.SocketPath)
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
		SocketPath: "/socket.io",
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

func TestEnsureTypeCompat_AddsTWithoutMutatingOriginal(t *testing.T) {
	in := map[string]any{"type": "foo", "x": 1}
	outAny := ensureTypeCompat(in)
	out, ok := outAny.(map[string]any)
	if !ok {
		t.Fatalf("expected map payload, got %T", outAny)
	}
	if out["t"] != "foo" {
		t.Fatalf("expected t to be populated from type, got %v", out["t"])
	}
	if _, ok := in["t"]; ok {
		t.Fatalf("expected input map to not be mutated")
	}
	// Preserve other fields.
	if out["x"] != 1 {
		t.Fatalf("expected x to be preserved, got %v", out["x"])
	}
}

func TestHTTPTransport_SkipTLSVerify(t *testing.T) {
	cfg := Config{
		ServerURL:     "https://example.com",
		ClientID:      "test",
		AuthToken:     "token",
		SkipTLSVerify: true,
	}

	baseURL, _ := buildBaseURL(cfg.ServerURL, "/socket.io")
	client := &Client{
		cfg:     cfg,
		baseURL: baseURL,
	}

	transport := client.httpTransport()
	if transport == nil {
		t.Fatal("httpTransport() returned nil")
	}

	// We can't easily test the TLS config without making actual requests,
	// but we can verify the transport is created
}

func TestRegisterEventHandlers(t *testing.T) {
	cfg := Config{
		ServerURL:  "https://example.com",
		ClientID:   "test",
		AuthToken:  "token",
		SocketPath: "/socket.io",
	}

	handlersCalled := make(map[string]bool)
	handlers := Handlers{
		Hello: func() {
			handlersCalled["hello"] = true
		},
		AdminRun: func(AdminCommand) {
			handlersCalled["admin_run"] = true
		},
		ShellStart: func(ShellStart) {
			handlersCalled["shell_start"] = true
		},
		ShellInput: func(ShellInput) {
			handlersCalled["shell_input"] = true
		},
		ShellResize: func(ShellResize) {
			handlersCalled["shell_resize"] = true
		},
		ShellClose: func(ShellClose) {
			handlersCalled["shell_close"] = true
		},
		BackupPlan: func(BackupRequest) {
			handlersCalled["backup_plan"] = true
		},
		BackupStart: func(BackupRequest) {
			handlersCalled["backup_start"] = true
		},
		SyncKeys: func(SyncKeysRequest) {
			handlersCalled["sync_keys"] = true
		},
		UpdateAgent: func(UpdateAgentRequest) {
			handlersCalled["agent_update"] = true
		},
	}

	client, err := New(cfg, nil, handlers)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Verify handlers are set
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
		SocketPath: "/socket.io",
	}

	// Test that nil handlers don't cause panics
	handlers := Handlers{}

	client, err := New(cfg, nil, handlers)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Should not panic with nil handlers
	if client.handlers.Hello != nil {
		t.Error("expected nil Hello handler")
	}
}

func TestRun_ContextCancellation(t *testing.T) {
	// Skip this test as it requires a real logger and would try to connect
	// The context cancellation is tested implicitly in other integration tests
	t.Skip("requires real logger and network connection")
}

func TestHandshakeURL_SignatureFormat(t *testing.T) {
	cfg := Config{
		ServerURL:  "https://example.com",
		ClientID:   "test-client",
		AuthToken:  "secret",
		SocketPath: "/socket.io",
	}

	baseURL, _ := buildBaseURL(cfg.ServerURL, cfg.SocketPath)
	client := &Client{
		cfg:     cfg,
		baseURL: baseURL,
	}

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

	// Verify they're valid hex
	if _, err := hex.DecodeString(sig1); err != nil {
		t.Errorf("sig1 is not valid hex: %v", err)
	}
	if _, err := hex.DecodeString(sig2); err != nil {
		t.Errorf("sig2 is not valid hex: %v", err)
	}
}
