package kiosk

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/austinkregel/compute-agent/pkg/logging"
	"nhooyr.io/websocket"
)

//go:embed kiosk_page.html
var kioskPageFS embed.FS

// manager implements Manager using webview and a local HTTP/WS server.
type manager struct {
	cfg      Config
	log      *logging.Logger
	onStatus StatusFunc

	mu        sync.RWMutex
	content   Content
	connected bool
	lastError string
	running   bool

	// WS connection to the kiosk page
	wsMu   sync.Mutex
	wsConn *websocket.Conn

	// Session token for WS auth
	token string

	// HTTP server
	listener net.Listener
	server   *http.Server
}

// New creates a kiosk manager.
// Returns an error if WebView support is not available (CGO disabled).
func New(cfg Config, log *logging.Logger, onStatus StatusFunc) (Manager, error) {
	if !webviewAvailable {
		return nil, ErrWebViewUnavailable
	}

	// Generate random session token
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("generate kiosk token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	return &manager{
		cfg:      cfg,
		log:      log,
		onStatus: onStatus,
		content:  Content{Kind: "dashboard"},
		token:    token,
	}, nil
}

func (m *manager) Run(ctx context.Context) error {
	// Start HTTP server
	listener, err := net.Listen("tcp", m.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen for kiosk: %w", err)
	}
	m.listener = listener

	addr := listener.Addr().String()
	m.log.Info("kiosk server listening", "addr", addr)

	mux := http.NewServeMux()
	mux.HandleFunc("/", m.handleIndex)
	mux.HandleFunc("/ws", m.handleWS)

	m.server = &http.Server{Handler: mux}

	// Start HTTP server in goroutine
	serverErr := make(chan error, 1)
	go func() {
		if err := m.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
		close(serverErr)
	}()

	m.setRunning(true)
	defer m.setRunning(false)

	// Launch WebView
	kioskURL := fmt.Sprintf("http://%s/?token=%s", addr, m.token)
	m.log.Info("launching kiosk webview", "url", kioskURL)

	// WebView blocks until closed, run in goroutine
	webviewDone := make(chan error, 1)
	go func() {
		webviewDone <- launchWebView(kioskURL, m.cfg.Fullscreen)
	}()

	// Wait for context cancellation, WebView close, or HTTP server error
	select {
	case <-ctx.Done():
		m.log.Info("kiosk shutting down")
	case err := <-webviewDone:
		if err != nil {
			m.log.Error("webview error", "error", err)
			m.setError(err.Error())
		} else {
			m.log.Info("kiosk webview closed")
		}
	case err := <-serverErr:
		if err != nil {
			m.log.Error("kiosk server error", "error", err)
			return err
		}
	}

	// Shutdown HTTP server
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = m.server.Shutdown(shutdownCtx)

	return ctx.Err()
}

func (m *manager) handleIndex(w http.ResponseWriter, r *http.Request) {
	tmplData, err := kioskPageFS.ReadFile("kiosk_page.html")
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}

	tmpl, err := template.New("kiosk").Parse(string(tmplData))
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tmpl.Execute(w, map[string]string{
		"Token": m.token,
	})
}

func (m *manager) handleWS(w http.ResponseWriter, r *http.Request) {
	// Validate token
	token := r.URL.Query().Get("token")
	if token != m.token {
		http.Error(w, "unauthorized", 401)
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // localhost only
	})
	if err != nil {
		m.log.Error("kiosk ws accept failed", "error", err)
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "closed")

	m.log.Info("kiosk page connected")
	m.setWSConn(conn)
	defer m.setWSConn(nil)

	// Send current content immediately
	m.pushContent()

	// Read loop (mostly for keepalive/status)
	ctx := r.Context()
	for {
		_, msg, err := conn.Read(ctx)
		if err != nil {
			m.log.Debug("kiosk ws read error", "error", err)
			break
		}

		// Parse message for potential status updates
		var wsMsg struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(msg, &wsMsg) == nil {
			if wsMsg.Type == "ping" {
				_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"pong"}`))
			}
		}
	}
}

func (m *manager) SetContent(c Content) error {
	if err := ValidateContent(c); err != nil {
		return err
	}

	m.mu.Lock()
	m.content = c
	m.mu.Unlock()

	m.pushContent()
	m.emitStatus()
	return nil
}

func (m *manager) pushContent() {
	m.wsMu.Lock()
	conn := m.wsConn
	m.wsMu.Unlock()

	if conn == nil {
		return
	}

	m.mu.RLock()
	content := m.content
	m.mu.RUnlock()

	msg := map[string]any{
		"type":    "content",
		"content": content,
	}
	data, _ := json.Marshal(msg)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
		m.log.Debug("kiosk push content failed", "error", err)
	}
}

func (m *manager) PushStats(data json.RawMessage) {
	m.mu.RLock()
	kind := m.content.Kind
	m.mu.RUnlock()

	if kind != "dashboard" {
		return
	}

	m.wsMu.Lock()
	conn := m.wsConn
	m.wsMu.Unlock()

	if conn == nil {
		return
	}

	msg := map[string]any{
		"type": "stats",
		"data": json.RawMessage(data),
	}
	out, err := json.Marshal(msg)
	if err != nil {
		m.log.Debug("kiosk stats marshal failed", "error", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := conn.Write(ctx, websocket.MessageText, out); err != nil {
		m.log.Debug("kiosk push stats failed", "error", err)
	}
}

func (m *manager) Status() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.wsMu.Lock()
	connected := m.wsConn != nil
	m.wsMu.Unlock()

	return NewStatus(m.running, connected, m.content, m.lastError)
}

func (m *manager) setRunning(running bool) {
	m.mu.Lock()
	m.running = running
	m.mu.Unlock()
	m.emitStatus()
}

func (m *manager) setWSConn(conn *websocket.Conn) {
	m.wsMu.Lock()
	m.wsConn = conn
	m.wsMu.Unlock()

	m.mu.Lock()
	m.connected = conn != nil
	m.mu.Unlock()

	m.emitStatus()
}

func (m *manager) setError(err string) {
	m.mu.Lock()
	m.lastError = err
	m.mu.Unlock()
	m.emitStatus()
}

func (m *manager) emitStatus() {
	if m.onStatus != nil {
		m.onStatus(m.Status())
	}
}
