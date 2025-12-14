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
	ServerURL     string
	ClientID      string
	AuthToken     string
	Namespace     string
	SocketPath    string
	SkipTLSVerify bool
	ReconnectMin  time.Duration
	ReconnectMax  time.Duration
}

// Handlers capture callbacks for server-originated events.
type Handlers struct {
	Hello       func()
	AdminRun    func(AdminCommand)
	ShellStart  func(ShellStart)
	ShellInput  func(ShellInput)
	ShellResize func(ShellResize)
	ShellClose  func(ShellClose)
	BackupPlan  func(BackupRequest)
	BackupStart func(BackupRequest)
	SyncKeys    func(SyncKeysRequest)
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

// SyncKeysRequest contains GitHub username for authorized_keys sync.
type SyncKeysRequest struct {
	User string `json:"user"`
}

// Client maintains the socket.io/WebSocket session to the control plane.
type Client struct {
	cfg      Config
	log      *logging.Logger
	handlers Handlers

	baseURL *url.URL

	socketMu sync.RWMutex
	socket   sio.ClientSocket
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

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
			delay = nextDelay(delay, c.cfg.ReconnectMax)
		}
	}
}

// Emit sends an event to the control plane.
func (c *Client) Emit(event string, payload any) error {
	sock := c.currentSocket()
	if sock == nil {
		return ErrNotConnected
	}
	sock.Emit(event, payload)
	return nil
}

func (c *Client) connectOnce(ctx context.Context) error {
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
	})
	socket.OnDisconnect(func(reason sio.Reason) {
		c.log.Error("agent socket disconnected", "reason", reason)
		c.setSocket(nil)
		select {
		case done <- fmt.Errorf("disconnect: %s", reason):
		default:
		}
	})

	c.registerEventHandlers(socket)
	socket.Connect()

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
		if c.handlers.Hello != nil {
			c.handlers.Hello()
		}
	})

	socket.OnEvent("ping", func(msg struct {
		TS int64 `json:"ts"`
	}) {
		_ = c.Emit("pong", map[string]int64{"ts": msg.TS})
	})

	socket.OnEvent("admin_run", func(msg AdminCommand) {
		if c.handlers.AdminRun != nil {
			c.handlers.AdminRun(msg)
		}
	})

	socket.OnEvent("shell_start", func(msg ShellStart) {
		if c.handlers.ShellStart != nil {
			c.handlers.ShellStart(msg)
		}
	})
	socket.OnEvent("shell_input", func(msg ShellInput) {
		if c.handlers.ShellInput != nil {
			c.handlers.ShellInput(msg)
		}
	})
	socket.OnEvent("shell_resize", func(msg ShellResize) {
		if c.handlers.ShellResize != nil {
			c.handlers.ShellResize(msg)
		}
	})
	socket.OnEvent("shell_close", func(msg ShellClose) {
		if c.handlers.ShellClose != nil {
			c.handlers.ShellClose(msg)
		}
	})

	socket.OnEvent("backup_plan", func(msg BackupRequest) {
		if c.handlers.BackupPlan != nil {
			c.handlers.BackupPlan(msg)
		}
	})
	socket.OnEvent("backup_start", func(msg BackupRequest) {
		if c.handlers.BackupStart != nil {
			c.handlers.BackupStart(msg)
		}
	})
	socket.OnEvent("sync_keys", func(msg SyncKeysRequest) {
		if c.handlers.SyncKeys != nil {
			c.handlers.SyncKeys(msg)
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
