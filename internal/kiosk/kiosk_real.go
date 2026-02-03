//go:build kiosk && cgo

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
	"github.com/webview/webview"
	"nhooyr.io/websocket"
)

//go:embed kiosk_page.html
var kioskPageFS embed.FS

// realManager implements Manager using webview and a local HTTP/WS server.
type realManager struct {
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

// New creates a kiosk manager with WebView support.
func New(cfg Config, log *logging.Logger, onStatus StatusFunc) (Manager, error) {
	// Generate random session token
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("generate kiosk token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	return &realManager{
		cfg:      cfg,
		log:      log,
		onStatus: onStatus,
		content:  Content{Kind: "blank"},
		token:    token,
	}, nil
}

func (m *realManager) Run(ctx context.Context) error {
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

	// Start WebView
	kioskURL := fmt.Sprintf("http://%s/?token=%s", addr, m.token)
	m.log.Info("starting kiosk webview", "url", kioskURL)

	// WebView runs on main thread, so we need to run it in a separate goroutine
	// and coordinate shutdown
	wvDone := make(chan struct{})
	go func() {
		defer close(wvDone)
		m.runWebView(kioskURL)
	}()

	// Wait for context cancellation or errors
	select {
	case <-ctx.Done():
		m.log.Info("kiosk shutting down")
	case err := <-serverErr:
		if err != nil {
			m.log.Error("kiosk server error", "error", err)
			return err
		}
	case <-wvDone:
		m.log.Info("kiosk webview closed")
	}

	// Shutdown HTTP server
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = m.server.Shutdown(shutdownCtx)

	return ctx.Err()
}

func (m *realManager) runWebView(url string) {
	w := webview.New(false)
	if w == nil {
		m.setError("failed to create webview")
		return
	}
	defer w.Destroy()

	w.SetTitle("Kiosk")
	w.SetSize(1920, 1080, webview.HintNone)

	// Navigate to our local kiosk page
	w.Navigate(url)

	// Run the webview event loop
	w.Run()
}

func (m *realManager) handleIndex(w http.ResponseWriter, r *http.Request) {
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

func (m *realManager) handleWS(w http.ResponseWriter, r *http.Request) {
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

func (m *realManager) SetContent(c Content) error {
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

func (m *realManager) pushContent() {
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

func (m *realManager) Status() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.wsMu.Lock()
	connected := m.wsConn != nil
	m.wsMu.Unlock()

	return NewStatus(m.running, connected, m.content, m.lastError)
}

func (m *realManager) setRunning(running bool) {
	m.mu.Lock()
	m.running = running
	m.mu.Unlock()
	m.emitStatus()
}

func (m *realManager) setWSConn(conn *websocket.Conn) {
	m.wsMu.Lock()
	m.wsConn = conn
	m.wsMu.Unlock()

	m.mu.Lock()
	m.connected = conn != nil
	m.mu.Unlock()

	m.emitStatus()
}

func (m *realManager) setError(err string) {
	m.mu.Lock()
	m.lastError = err
	m.mu.Unlock()
	m.emitStatus()
}

func (m *realManager) emitStatus() {
	if m.onStatus != nil {
		m.onStatus(m.Status())
	}
}
