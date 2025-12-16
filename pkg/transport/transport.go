package transport

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sio "github.com/karagenc/socket.io-go"
	eio "github.com/karagenc/socket.io-go/engine.io"
	"nhooyr.io/websocket"

	"github.com/austinkregel/compute-agent/pkg/logging"
)

// ErrNotConnected is returned when emitting before the socket is ready.
var ErrNotConnected = errors.New("transport: not connected")

// Emitter exposes the minimal functionality needed by subsystems that emit events.
type Emitter interface {
	Emit(event string, payload any) error
}

// Config configures the socket transport.
type Config struct {
	ServerURL         string
	ClientID          string
	AuthToken         string
	Namespace         string
	SocketPath        string
	SkipTLSVerify     bool
	ReconnectMin      time.Duration
	ReconnectMax      time.Duration
	HeartbeatInterval time.Duration
	PongTimeout       time.Duration
}

// Handlers capture callbacks for server-originated events.
type Handlers struct {
	Hello        func()
	AdminRun     func(AdminCommand)
	ShellStart   func(ShellStart)
	ShellInput   func(ShellInput)
	ShellResize  func(ShellResize)
	ShellClose   func(ShellClose)
	LogTailStart func(LogTailStart)
	LogTailStop  func(LogTailStop)
	BackupPlan   func(BackupRequest)
	BackupStart  func(BackupRequest)
	SyncKeys     func(SyncKeysRequest)
	UpdateAgent  func(UpdateAgentRequest)
	CheckUpdates func(CheckUpdatesRequest)
	DirList      func(DirListRequest)
}

// AdminCommand mirrors the payload emitted by the control plane.
type AdminCommand struct {
	Token string      `json:"token"`
	Cmd   CommandSpec `json:"cmd"`
}

// CommandSpec represents the server-provided command details.
type CommandSpec struct {
	Command    string `json:"command"`
	TimeoutSec int    `json:"timeoutSec"`
	Cwd        string `json:"cwd"`
}

// ShellStart represents an interactive shell start request.
type ShellStart struct {
	Session string `json:"session"`
}

// ShellInput bytes destined for the PTY stdIn.
type ShellInput struct {
	Session string `json:"session"`
	Data    string `json:"data"`
}

// ShellResize request.
type ShellResize struct {
	Session string `json:"session"`
	Cols    int    `json:"cols"`
	Rows    int    `json:"rows"`
}

// ShellClose signals an operator-initiated close.
type ShellClose struct {
	Session string `json:"session"`
}

// LogTailStart begins streaming the agent log file.
type LogTailStart struct {
	Session string `json:"session"`
	Lines   int    `json:"lines"`
}

// LogTailStop stops a streaming log tail session.
type LogTailStop struct {
	Session string `json:"session"`
}

// BackupRequest describes plan/run payloads.
type BackupRequest struct {
	PlanID      string   `json:"planId"`
	Host        string   `json:"host"`
	User        string   `json:"user"`
	Port        int      `json:"port"`
	SourceDirs  []string `json:"sourceDirs"`
	DestRoot    string   `json:"destRoot"`
	IgnoreGlobs []string `json:"ignoreGlobs"`
}

// DirListRequest asks the agent to list a single directory (local or remote).
// See working_plan.md (RFC-0002).
type DirListRequest struct {
	ClientID  string `json:"clientId"`
	RequestID string `json:"requestId"`
	Mode      string `json:"mode"` // "local" or "remote"
	Path      string `json:"path"`

	// Remote fields (SSH / SMB). Host is required for remote mode.
	Host string `json:"host,omitempty"`
	User string `json:"user,omitempty"`
	Port int    `json:"port,omitempty"`

	// Optional extension: remote protocol selector.
	// If empty, agent treats remote mode as SSH.
	Protocol string `json:"protocol,omitempty"` // "ssh" or "smb"

	// SMB-only fields.
	Share   string `json:"share,omitempty"`
	Profile string `json:"profile,omitempty"`
}

// DirListEntry describes a single child entry of a directory.
type DirListEntry struct {
	Name string `json:"name"`
	Type string `json:"type"`           // "dir" or "file"
	Size int64  `json:"size,omitempty"` // optional
}

// DirListResponse returns entries for a single directory request.
type DirListResponse struct {
	ClientID  string         `json:"clientId"`
	RequestID string         `json:"requestId"`
	Mode      string         `json:"mode"`
	Path      string         `json:"path"`
	Entries   []DirListEntry `json:"entries"`
	Error     string         `json:"error,omitempty"`
}

// SyncKeysRequest contains GitHub username for authorized_keys sync.
type SyncKeysRequest struct {
	User string `json:"user"`
}

// UpdateAgentRequest instructs the agent to self-update from GitHub releases.
// Server will typically send { repo: "austinkregel/compute-agent", tag?: "vX.Y.Z" }.
type UpdateAgentRequest struct {
	Repo string `json:"repo"`
	Tag  string `json:"tag"`
	At   string `json:"at"`
}

// CheckUpdatesRequest requests that the agent refresh OS update availability immediately.
// Payload is optional; server may send an empty object.
type CheckUpdatesRequest struct {
	At string `json:"at,omitempty"`
}

// Client maintains the socket.io/WebSocket session to the control plane.
type Client struct {
	cfg      Config
	log      *logging.Logger
	handlers Handlers

	baseURL *url.URL

	socketMu sync.RWMutex
	socket   sio.ClientSocket

	// lastTraffic stores the unix nano timestamp of the last inbound/outbound
	// control-plane traffic. A value of 0 means "not connected / unknown".
	lastTraffic atomic.Int64
	helloAcked  atomic.Bool
}

// New builds a transport client with default backoff settings.
func New(cfg Config, log *logging.Logger, handlers Handlers) (*Client, error) {
	if strings.TrimSpace(cfg.ServerURL) == "" {
		return nil, errors.New("server URL is required")
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, errors.New("client ID is required")
	}
	if strings.TrimSpace(cfg.AuthToken) == "" {
		return nil, errors.New("auth token is required")
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "/agents"
	}
	if cfg.SocketPath == "" {
		cfg.SocketPath = "/socket.io"
	}
	if cfg.ReconnectMin == 0 {
		cfg.ReconnectMin = time.Second
	}
	if cfg.ReconnectMax == 0 {
		cfg.ReconnectMax = 30 * time.Second
	}
	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = 20 * time.Second
	}
	if cfg.PongTimeout == 0 {
		cfg.PongTimeout = 90 * time.Second
	}
	baseURL, err := buildBaseURL(cfg.ServerURL, cfg.SocketPath)
	if err != nil {
		return nil, err
	}

	return &Client{
		cfg:      cfg,
		log:      log,
		handlers: handlers,
		baseURL:  baseURL,
	}, nil
}

// Run establishes the control plane session and reconnects with backoff until ctx is cancelled.
func (c *Client) Run(ctx context.Context) error {
	c.log.Info("transport loop starting",
		"serverUrl", c.cfg.ServerURL,
		"namespace", c.cfg.Namespace)

	delay := c.cfg.ReconnectMin
	for {
		if ctx.Err() != nil {
			c.log.Info("transport loop exiting", "reason", ctx.Err())
			return ctx.Err()
		}

		err := c.connectOnce(ctx)
		if errors.Is(err, context.Canceled) {
			return err
		}
		if err != nil {
			c.log.Error("transport connection closed", "error", err)
		}

		// Reconnect backoff must reset after a successful hello_ack.
		waitDelay := delay
		if c.helloAcked.Load() {
			waitDelay = c.cfg.ReconnectMin
			delay = c.cfg.ReconnectMin
		} else {
			delay = nextDelay(delay, c.cfg.ReconnectMax)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitDelay):
		}
	}
}

// Emit sends an event to the control plane.
func (c *Client) Emit(event string, payload any) error {
	sock := c.currentSocket()
	if sock == nil {
		return ErrNotConnected
	}
	payload = ensureTypeCompat(payload)
	c.log.Debug("emit event", "event", event)
	sock.Emit(event, payload)
	c.touchTraffic()
	return nil
}

func (c *Client) connectOnce(ctx context.Context) error {
	c.helloAcked.Store(false)
	c.lastTraffic.Store(0)

	connectURL, err := c.handshakeURL()
	if err != nil {
		return err
	}

	httpTransport := c.httpTransport()
	httpClient := &http.Client{Transport: httpTransport}

	manager := sio.NewManager(connectURL, &sio.ManagerConfig{
		NoReconnection: true,
		EIO: eio.ClientConfig{
			Transports:           []string{"polling", "websocket"},
			HTTPTransport:        httpTransport,
			WebSocketDialOptions: &websocket.DialOptions{HTTPClient: httpClient},
		},
	})
	socket := manager.Socket(c.cfg.Namespace, nil)

	done := make(chan error, 1)

	manager.OnError(func(err error) {
		select {
		case done <- err:
		default:
		}
	})
	manager.OnClose(func(reason sio.Reason, err error) {
		select {
		case done <- fmt.Errorf("close: %s (%v)", reason, err):
		default:
		}
	})

	socket.OnConnect(func() {
		c.log.Info("agent socket connected")
		c.setSocket(socket)
		c.touchTraffic()
	})
	socket.OnDisconnect(func(reason sio.Reason) {
		c.log.Error("agent socket disconnected", "reason", reason)
		c.setSocket(nil)
		c.lastTraffic.Store(0)
		select {
		case done <- fmt.Errorf("disconnect: %s", reason):
		default:
		}
	})

	c.registerEventHandlers(socket)
	socket.Connect()

	stop := make(chan struct{})
	defer close(stop)
	go c.proactivePingLoop(ctx, stop)

	select {
	case <-ctx.Done():
		socket.Disconnect()
		return ctx.Err()
	case err := <-done:
		return err
	}
}

func (c *Client) registerEventHandlers(socket sio.ClientSocket) {
	socket.OnEvent("hello_ack", func(_ struct{}) {
		c.helloAcked.Store(true)
		c.touchTraffic()
		c.log.Debug("recv event", "event", "hello_ack")
		if c.handlers.Hello != nil {
			c.handlers.Hello()
		}
	})

	socket.OnEvent("ping", func(msg struct {
		TS int64 `json:"ts"`
	}) {
		c.touchTraffic()
		c.log.Debug("recv event", "event", "ping", "ts", msg.TS)
		_ = c.Emit("pong", map[string]int64{"ts": msg.TS})
	})

	socket.OnEvent("admin_run", func(msg AdminCommand) {
		c.touchTraffic()
		c.log.Debug("recv event", "event", "admin_run")
		if c.handlers.AdminRun != nil {
			c.handlers.AdminRun(msg)
		}
	})

	socket.OnEvent("shell_start", func(msg ShellStart) {
		c.touchTraffic()
		c.log.Debug("recv event", "event", "shell_start", "session", msg.Session)
		if c.handlers.ShellStart != nil {
			c.handlers.ShellStart(msg)
		}
	})
	socket.OnEvent("shell_input", func(msg ShellInput) {
		c.touchTraffic()
		c.log.Debug("recv event", "event", "shell_input", "session", msg.Session, "bytes", len(msg.Data))
		if c.handlers.ShellInput != nil {
			c.handlers.ShellInput(msg)
		}
	})
	socket.OnEvent("shell_resize", func(msg ShellResize) {
		c.touchTraffic()
		c.log.Debug("recv event", "event", "shell_resize", "session", msg.Session, "cols", msg.Cols, "rows", msg.Rows)
		if c.handlers.ShellResize != nil {
			c.handlers.ShellResize(msg)
		}
	})
	socket.OnEvent("shell_close", func(msg ShellClose) {
		c.touchTraffic()
		c.log.Debug("recv event", "event", "shell_close", "session", msg.Session)
		if c.handlers.ShellClose != nil {
			c.handlers.ShellClose(msg)
		}
	})

	socket.OnEvent("log_tail_start", func(msg LogTailStart) {
		c.touchTraffic()
		c.log.Debug("recv event", "event", "log_tail_start", "session", msg.Session, "lines", msg.Lines)
		if c.handlers.LogTailStart != nil {
			c.handlers.LogTailStart(msg)
		}
	})

	socket.OnEvent("log_tail_stop", func(msg LogTailStop) {
		c.touchTraffic()
		c.log.Debug("recv event", "event", "log_tail_stop", "session", msg.Session)
		if c.handlers.LogTailStop != nil {
			c.handlers.LogTailStop(msg)
		}
	})

	socket.OnEvent("backup_plan", func(msg BackupRequest) {
		c.touchTraffic()
		c.log.Debug("recv event", "event", "backup_plan", "planId", msg.PlanID)
		if c.handlers.BackupPlan != nil {
			c.handlers.BackupPlan(msg)
		}
	})
	socket.OnEvent("backup_start", func(msg BackupRequest) {
		c.touchTraffic()
		c.log.Debug("recv event", "event", "backup_start", "planId", msg.PlanID)
		if c.handlers.BackupStart != nil {
			c.handlers.BackupStart(msg)
		}
	})
	socket.OnEvent("sync_keys", func(msg SyncKeysRequest) {
		c.touchTraffic()
		c.log.Debug("recv event", "event", "sync_keys", "user", msg.User)
		if c.handlers.SyncKeys != nil {
			c.handlers.SyncKeys(msg)
		}
	})

	socket.OnEvent("agent_update", func(msg UpdateAgentRequest) {
		c.touchTraffic()
		c.log.Info("recv event", "event", "agent_update", "repo", msg.Repo, "tag", msg.Tag)
		if c.handlers.UpdateAgent != nil {
			c.handlers.UpdateAgent(msg)
		}
	})

	socket.OnEvent("check_updates", func(msg CheckUpdatesRequest) {
		c.touchTraffic()
		c.log.Info("recv event", "event", "check_updates")
		if c.handlers.CheckUpdates != nil {
			c.handlers.CheckUpdates(msg)
		}
	})

	socket.OnEvent("dir_list_request", func(msg DirListRequest) {
		c.touchTraffic()
		c.log.Debug("recv event", "event", "dir_list_request")
		if c.handlers.DirList != nil {
			c.handlers.DirList(msg)
		}
	})
}

func (c *Client) handshakeURL() (string, error) {
	ts := time.Now().UnixMilli()
	payload := fmt.Sprintf("{\"clientId\":\"%s\",\"ts\":%d}", c.cfg.ClientID, ts)
	sum := hmac.New(sha256.New, []byte(c.cfg.AuthToken))
	sum.Write([]byte(payload))
	sig := hex.EncodeToString(sum.Sum(nil))

	clone := *c.baseURL
	q := clone.Query()
	q.Set("clientId", c.cfg.ClientID)
	q.Set("ts", strconv.FormatInt(ts, 10))
	q.Set("sig", sig)
	clone.RawQuery = q.Encode()
	return clone.String(), nil
}

func (c *Client) httpTransport() http.RoundTripper {
	base := http.DefaultTransport.(*http.Transport).Clone()
	if c.cfg.SkipTLSVerify {
		if base.TLSClientConfig == nil {
			base.TLSClientConfig = &tls.Config{}
		}
		base.TLSClientConfig.InsecureSkipVerify = true // #nosec G402
	}
	return base
}

func (c *Client) currentSocket() sio.ClientSocket {
	c.socketMu.RLock()
	defer c.socketMu.RUnlock()
	return c.socket
}

func (c *Client) setSocket(socket sio.ClientSocket) {
	c.socketMu.Lock()
	defer c.socketMu.Unlock()
	c.socket = socket
}

func (c *Client) touchTraffic() {
	c.lastTraffic.Store(time.Now().UnixNano())
}

func (c *Client) proactivePingLoop(ctx context.Context, stop <-chan struct{}) {
	interval := c.cfg.HeartbeatInterval
	if interval <= 0 {
		interval = 20 * time.Second
	}
	timeout := c.cfg.PongTimeout
	if timeout <= 0 {
		timeout = 90 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-ticker.C:
			last := c.lastTraffic.Load()
			if last == 0 {
				continue
			}
			if time.Since(time.Unix(0, last)) < timeout/2 {
				continue
			}
			// Best-effort proactive ping to avoid idle disconnects.
			_ = c.Emit("ping", map[string]int64{"ts": time.Now().UnixMilli()})
		}
	}
}

func buildBaseURL(raw, socketPath string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse server URL: %w", err)
	}
	basePath := path.Clean("/" + strings.TrimPrefix(u.Path, "/"))
	if basePath == "." {
		basePath = ""
	}
	socketPath = "/" + strings.TrimPrefix(socketPath, "/")
	finalPath := path.Join(basePath, strings.TrimPrefix(socketPath, "/"))
	if !strings.HasSuffix(finalPath, "/") {
		finalPath += "/"
	}
	u.Path = finalPath
	u.RawQuery = ""
	u.Fragment = ""
	return u, nil
}

func nextDelay(current, max time.Duration) time.Duration {
	next := current * 2
	if next > max {
		return max
	}
	return next
}

// ensureTypeCompat ensures payloads that include `type` also include legacy `t`,
// since the server dispatch may check `t || type` during a compatibility window.
func ensureTypeCompat(payload any) any {
	m, ok := payload.(map[string]any)
	if !ok {
		return payload
	}
	if _, hasT := m["t"]; hasT {
		return payload
	}
	v, hasType := m["type"]
	if !hasType {
		return payload
	}
	cp := make(map[string]any, len(m)+1)
	for k, vv := range m {
		cp[k] = vv
	}
	cp["t"] = v
	return cp
}
