package kiosk

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"strings"
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

	// localURL is the kiosk page address (set during Run), used to
	// navigate the WebView back after displaying an external URL.
	localURL string

	// HTTP server
	listener net.Listener
	server   *http.Server

	layoutStore *LayoutStore
}

// New creates a kiosk manager.
// Returns an error if WebView support is not available (CGO disabled).
// dataDir is the directory where kiosk-layouts.json will be persisted.
func New(cfg Config, log *logging.Logger, onStatus StatusFunc, dataDir string) (Manager, error) {
	if !webviewAvailable {
		return nil, ErrWebViewUnavailable
	}

	// Generate random session token
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("generate kiosk token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	store := NewLayoutStore(dataDir)
	if err := store.Load(); err != nil {
		log.Warn("failed to load kiosk layouts, using defaults", "error", err)
	}

	return &manager{
		cfg:         cfg,
		log:         log,
		onStatus:    onStatus,
		content:     Content{Kind: "dashboard"},
		token:       token,
		layoutStore: store,
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
	mux.HandleFunc("/api/layouts", m.handleListLayouts)
	mux.HandleFunc("/api/layout/", m.handleLayout)

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
	m.localURL = kioskURL
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
		// Shutdown HTTP server before returning
		shutdownCtx, shutCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer shutCancel()
		_ = m.server.Shutdown(shutdownCtx)

		if err != nil {
			m.log.Error("FATAL: kiosk webview failed — the agent will exit so the service manager can restart it",
				"error", err)
			m.setError(err.Error())
			return fmt.Errorf("kiosk webview: %w", err)
		}
		m.log.Info("kiosk webview closed")
		return nil
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

	// For page kind, resolve widget placements and units from store if not provided.
	if c.Kind == "page" && m.layoutStore != nil {
		if layout, ok := m.layoutStore.Get(c.Layout); ok {
			if len(c.Widgets) == 0 {
				c.Widgets = layout.Widgets
			}
			if c.Units == "" && layout.Units != "" {
				c.Units = layout.Units
			}
		}
	}

	m.mu.Lock()
	wasURL := m.content.Kind == "url"
	m.content = c
	m.mu.Unlock()

	switch {
	case c.Kind == "url":
		navigateWebView(c.URL)
	case wasURL && m.localURL != "":
		navigateWebView(m.localURL)
	default:
		m.pushContent()
	}

	m.emitStatus()
	return nil
}

func (m *manager) pushContent() {
	m.mu.RLock()
	content := m.content
	m.mu.RUnlock()

	// URL content is rendered by the WebView itself, not the kiosk page.
	if content.Kind == "url" {
		navigateWebView(content.URL)
		return
	}

	m.wsMu.Lock()
	conn := m.wsConn
	m.wsMu.Unlock()

	if conn == nil {
		return
	}

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

	if kind != "dashboard" && kind != "page" {
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

func (m *manager) SaveLayout(name string, layout PageLayout) error {
	if m.layoutStore == nil {
		return errors.New("layout store not initialized")
	}
	if err := m.layoutStore.Save(name, layout); err != nil {
		return err
	}
	// If this is the currently active layout, re-push to kiosk
	m.mu.RLock()
	active := m.content.Kind == "page" && m.content.Layout == name
	m.mu.RUnlock()

	if active {
		m.mu.Lock()
		m.content.Widgets = layout.Widgets
		m.mu.Unlock()
		m.pushContent()
	}
	return nil
}

func (m *manager) GetLayouts() map[string]PageLayout {
	if m.layoutStore == nil {
		return nil
	}
	return m.layoutStore.List()
}

func (m *manager) handleListLayouts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := r.URL.Query().Get("token")
	if token != m.token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(m.GetLayouts())
}

func (m *manager) handleLayout(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token != m.token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/api/layout/")
	if name == "" {
		http.Error(w, "layout name required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		layout, ok := m.layoutStore.Get(name)
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(layout)

	case http.MethodPut:
		body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		var layout PageLayout
		if err := json.Unmarshal(body, &layout); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := m.SaveLayout(name, layout); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
