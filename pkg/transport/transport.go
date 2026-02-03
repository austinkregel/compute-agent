package transport

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
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

	"github.com/austinkregel/compute-agent/pkg/cmdsig"
	"github.com/austinkregel/compute-agent/pkg/logging"
)

// ErrNotConnected is returned when emitting before the socket is ready.
var ErrNotConnected = errors.New("transport: not connected")

// ErrCommandVerificationFailed is returned when a signed command fails verification.
var ErrCommandVerificationFailed = errors.New("transport: command verification failed")

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

	// MaxClockSkew is the maximum allowed difference between server and agent
	// clocks for signed command verification. Default: 5 minutes.
	MaxClockSkew time.Duration
}

// Handlers capture callbacks for server-originated events.
type Handlers struct {
	Hello         func()
	AdminRun      func(AdminCommand)
	ShellStart    func(ShellStart)
	ShellInput    func(ShellInput)
	ShellResize   func(ShellResize)
	ShellClose    func(ShellClose)
	LogTailStart  func(LogTailStart)
	LogTailStop   func(LogTailStop)
	BackupPlan    func(BackupRequest)
	BackupStart   func(BackupRequest)
	SyncKeys      func(SyncKeysRequest)
	UpdateAgent   func(UpdateAgentRequest)
	CheckUpdates  func(CheckUpdatesRequest)
	DirList       func(DirListRequest)
	FilePutStart  func(FilePutStartRequest)
	FilePutChunk  func(FilePutChunk)
	FilePutFinish func(FilePutFinishRequest)
	FileDelete    func(FileDeleteRequest)
	FileChmod     func(FileChmodRequest)
	KioskSet      func(KioskSetRequest)
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
	Name       string `json:"name"`
	Type       string `json:"type"`                  // "dir" or "file"
	Size       int64  `json:"size,omitempty"`        // optional
	Mode       string `json:"mode,omitempty"`        // Unix permission string, e.g., "drwxr-xr-x"
	ModTime    string `json:"modTime,omitempty"`     // RFC3339 formatted modification time
	IsSymlink  bool   `json:"isSymlink,omitempty"`   // true if entry is a symbolic link
	LinkTarget string `json:"linkTarget,omitempty"` // target path if IsSymlink is true
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

// --- File Operations ---

// FilePutStartRequest initiates a file upload to the agent.
type FilePutStartRequest struct {
	ClientID  string `json:"clientId"`
	RequestID string `json:"requestId"`
	Path      string `json:"path"`       // Absolute path where file should be written
	Size      int64  `json:"size"`       // Expected total file size in bytes
	Mode      string `json:"mode"`       // Optional permission mode, e.g., "0644"
	Force     bool   `json:"force"`      // If true, allow writing to dangerous paths
	Overwrite bool   `json:"overwrite"`  // If true, overwrite existing files
}

// FilePutChunk contains a chunk of file data.
type FilePutChunk struct {
	RequestID string `json:"requestId"`
	Offset    int64  `json:"offset"` // Byte offset within the file
	Data      []byte `json:"data"`   // Chunk data (base64 encoded in JSON)
}

// FilePutFinishRequest signals the end of a file upload.
type FilePutFinishRequest struct {
	RequestID string `json:"requestId"`
	Checksum  string `json:"checksum,omitempty"` // Optional SHA256 checksum for verification
}

// FilePutResult is the agent's response to a file upload.
type FilePutResult struct {
	ClientID  string `json:"clientId"`
	RequestID string `json:"requestId"`
	OK        bool   `json:"ok"`
	Path      string `json:"path,omitempty"`
	Size      int64  `json:"size,omitempty"`
	Error     string `json:"error,omitempty"`
}

// FileDeleteRequest asks the agent to delete a file or empty directory.
type FileDeleteRequest struct {
	ClientID  string `json:"clientId"`
	RequestID string `json:"requestId"`
	Path      string `json:"path"`
	Force     bool   `json:"force"`     // If true, allow deleting in dangerous paths
	Recursive bool   `json:"recursive"` // If true, allow deleting non-empty directories (requires force)
}

// FileDeleteResult is the agent's response to a delete request.
type FileDeleteResult struct {
	ClientID  string `json:"clientId"`
	RequestID string `json:"requestId"`
	OK        bool   `json:"ok"`
	Path      string `json:"path,omitempty"`
	Error     string `json:"error,omitempty"`
}

// FileChmodRequest asks the agent to change file permissions.
type FileChmodRequest struct {
	ClientID  string `json:"clientId"`
	RequestID string `json:"requestId"`
	Path      string `json:"path"`
	Mode      string `json:"mode"`  // Permission mode, e.g., "0755" or "rwxr-xr-x"
	Force     bool   `json:"force"` // If true, allow chmod in dangerous paths
}

// FileChmodResult is the agent's response to a chmod request.
type FileChmodResult struct {
	ClientID  string `json:"clientId"`
	RequestID string `json:"requestId"`
	OK        bool   `json:"ok"`
	Path      string `json:"path,omitempty"`
	Mode      string `json:"mode,omitempty"`
	Error     string `json:"error,omitempty"`
}

// --- Kiosk Operations ---

// KioskContent describes what the kiosk should display.
// Kind determines which fields are used:
//   - "blank": no additional fields
//   - "message": Title (optional) and Text are used
//   - "url": URL is used (must be http: or https:)
type KioskContent struct {
	Kind  string `json:"kind"`            // "blank", "message", or "url"
	Title string `json:"title,omitempty"` // for "message" kind
	Text  string `json:"text,omitempty"`  // for "message" kind
	URL   string `json:"url,omitempty"`   // for "url" kind
}

// KioskSetRequest is the signed command payload for setting kiosk content.
type KioskSetRequest struct {
	RequestID string       `json:"requestId,omitempty"`
	Content   KioskContent `json:"content"`
	TS        string       `json:"ts,omitempty"`
}

// KioskStatus reports the current state of the kiosk subsystem.
type KioskStatus struct {
	Running     bool         `json:"running"`
	Connected   bool         `json:"connected"`
	Content     KioskContent `json:"content,omitempty"`
	LastError   string       `json:"lastError,omitempty"`
	TS          string       `json:"ts"`
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

	// Command signature verification (per-session)
	verifierMu sync.RWMutex
	verifier   *cmdsig.Verifier
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
	c.clearVerifier() // Reset signature verifier for new session

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
	// HelloAckPayload contains optional session nonce for command signing.
	type HelloAckPayload struct {
		SessionNonce string `json:"sessionNonce,omitempty"`
	}

	socket.OnEvent("hello_ack", func(msg HelloAckPayload) {
		c.helloAcked.Store(true)
		c.touchTraffic()

		// Command signing is mandatory - server MUST provide session nonce
		if msg.SessionNonce == "" {
			c.log.Error("server did not provide session nonce - command signing required")
			// Continue but commands will be rejected until we get a valid nonce
		} else {
			sessionKey := cmdsig.DeriveSessionKey(c.cfg.AuthToken, msg.SessionNonce)
			verifier := cmdsig.NewVerifier(sessionKey)
			if c.cfg.MaxClockSkew > 0 {
				verifier.SetMaxClockSkew(c.cfg.MaxClockSkew)
			}
			c.setVerifier(verifier)
			c.log.Info("command signing initialized",
				"noncePrefix", msg.SessionNonce[:8]+"...")
		}

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

	// Handler for signed commands from the server.
	// This is the secure path for all security-sensitive operations.
	socket.OnEvent("signed_command", func(rawEnvelope json.RawMessage) {
		c.touchTraffic()

		var envelope cmdsig.SignedEnvelope
		if err := json.Unmarshal(rawEnvelope, &envelope); err != nil {
			c.log.Error("failed to unmarshal signed_command envelope", "error", err)
			return
		}

		// Verify the signature
		if err := c.verifyCommand(&envelope); err != nil {
			c.log.Warn("rejecting signed_command", "event", envelope.Event, "error", err)
			// Optionally emit rejection back to server
			_ = c.Emit("command_rejected", map[string]any{
				"event": envelope.Event,
				"seq":   envelope.Seq,
				"error": err.Error(),
			})
			return
		}

		c.log.Debug("verified signed_command", "event", envelope.Event, "seq", envelope.Seq)

		// Dispatch to the appropriate handler based on event type
		c.dispatchSignedCommand(envelope.Event, envelope.Payload)
	})

	// Legacy unsigned event handlers - ALL commands must be signed, so these
	// handlers reject unsigned commands and log a warning.
	socket.OnEvent("admin_run", func(msg AdminCommand) {
		c.touchTraffic()
		c.log.Warn("rejecting unsigned admin_run - use signed_command")
		// Unsigned commands are not allowed
	})

	// All commands MUST be signed. These legacy event handlers reject unsigned
	// commands unconditionally. The server must use signed_command event.

	socket.OnEvent("shell_start", func(msg ShellStart) {
		c.touchTraffic()
		c.log.Warn("rejecting unsigned shell_start - use signed_command")
	})
	socket.OnEvent("shell_input", func(msg ShellInput) {
		c.touchTraffic()
		c.log.Warn("rejecting unsigned shell_input - use signed_command")
	})
	socket.OnEvent("shell_resize", func(msg ShellResize) {
		c.touchTraffic()
		c.log.Warn("rejecting unsigned shell_resize - use signed_command")
	})
	socket.OnEvent("shell_close", func(msg ShellClose) {
		c.touchTraffic()
		c.log.Warn("rejecting unsigned shell_close - use signed_command")
	})

	socket.OnEvent("log_tail_start", func(msg LogTailStart) {
		c.touchTraffic()
		c.log.Warn("rejecting unsigned log_tail_start - use signed_command")
	})

	socket.OnEvent("log_tail_stop", func(msg LogTailStop) {
		c.touchTraffic()
		c.log.Warn("rejecting unsigned log_tail_stop - use signed_command")
	})

	socket.OnEvent("backup_plan", func(msg BackupRequest) {
		c.touchTraffic()
		c.log.Warn("rejecting unsigned backup_plan - use signed_command")
	})
	socket.OnEvent("backup_start", func(msg BackupRequest) {
		c.touchTraffic()
		c.log.Warn("rejecting unsigned backup_start - use signed_command")
	})
	socket.OnEvent("sync_keys", func(msg SyncKeysRequest) {
		c.touchTraffic()
		c.log.Warn("rejecting unsigned sync_keys - use signed_command")
	})

	socket.OnEvent("agent_update", func(msg UpdateAgentRequest) {
		c.touchTraffic()
		c.log.Warn("rejecting unsigned agent_update - use signed_command")
	})

	socket.OnEvent("check_updates", func(msg CheckUpdatesRequest) {
		c.touchTraffic()
		c.log.Warn("rejecting unsigned check_updates - use signed_command")
	})

	socket.OnEvent("dir_list_request", func(msg DirListRequest) {
		c.touchTraffic()
		c.log.Warn("rejecting unsigned dir_list_request - use signed_command")
	})

	socket.OnEvent("file_put_start", func(msg FilePutStartRequest) {
		c.touchTraffic()
		c.log.Warn("rejecting unsigned file_put_start - use signed_command")
	})

	socket.OnEvent("file_put_chunk", func(msg FilePutChunk) {
		c.touchTraffic()
		c.log.Warn("rejecting unsigned file_put_chunk - use signed_command")
	})

	socket.OnEvent("file_put_finish", func(msg FilePutFinishRequest) {
		c.touchTraffic()
		c.log.Warn("rejecting unsigned file_put_finish - use signed_command")
	})

	socket.OnEvent("file_delete_request", func(msg FileDeleteRequest) {
		c.touchTraffic()
		c.log.Warn("rejecting unsigned file_delete_request - use signed_command")
	})

	socket.OnEvent("file_chmod_request", func(msg FileChmodRequest) {
		c.touchTraffic()
		c.log.Warn("rejecting unsigned file_chmod_request - use signed_command")
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

// setVerifier sets the command signature verifier for this session.
func (c *Client) setVerifier(v *cmdsig.Verifier) {
	c.verifierMu.Lock()
	defer c.verifierMu.Unlock()
	c.verifier = v
}

// clearVerifier removes the current verifier (e.g., on disconnect).
func (c *Client) clearVerifier() {
	c.verifierMu.Lock()
	defer c.verifierMu.Unlock()
	c.verifier = nil
}

// getVerifier returns the current verifier, if any.
func (c *Client) getVerifier() *cmdsig.Verifier {
	c.verifierMu.RLock()
	defer c.verifierMu.RUnlock()
	return c.verifier
}

// verifyCommand checks if a signed command envelope is valid.
// Returns nil if valid, error otherwise. All commands MUST be signed.
func (c *Client) verifyCommand(envelope *cmdsig.SignedEnvelope) error {
	verifier := c.getVerifier()

	// Command signing is mandatory - if we don't have a verifier, reject
	if verifier == nil {
		c.log.Error("rejecting command: no session verifier (server may be outdated)")
		return ErrCommandVerificationFailed
	}

	if err := verifier.Verify(envelope); err != nil {
		c.log.Warn("command signature verification failed",
			"event", envelope.Event,
			"seq", envelope.Seq,
			"error", err)
		return err
	}
	return nil
}

// dispatchSignedCommand routes a verified command payload to the appropriate handler.
func (c *Client) dispatchSignedCommand(event string, payload json.RawMessage) {
	switch event {
	case "admin_run":
		var msg AdminCommand
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal admin_run payload", "error", err)
			return
		}
		if c.handlers.AdminRun != nil {
			c.handlers.AdminRun(msg)
		}

	case "shell_start":
		var msg ShellStart
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal shell_start payload", "error", err)
			return
		}
		if c.handlers.ShellStart != nil {
			c.handlers.ShellStart(msg)
		}

	case "shell_input":
		var msg ShellInput
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal shell_input payload", "error", err)
			return
		}
		if c.handlers.ShellInput != nil {
			c.handlers.ShellInput(msg)
		}

	case "shell_resize":
		var msg ShellResize
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal shell_resize payload", "error", err)
			return
		}
		if c.handlers.ShellResize != nil {
			c.handlers.ShellResize(msg)
		}

	case "shell_close":
		var msg ShellClose
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal shell_close payload", "error", err)
			return
		}
		if c.handlers.ShellClose != nil {
			c.handlers.ShellClose(msg)
		}

	case "log_tail_start":
		var msg LogTailStart
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal log_tail_start payload", "error", err)
			return
		}
		if c.handlers.LogTailStart != nil {
			c.handlers.LogTailStart(msg)
		}

	case "log_tail_stop":
		var msg LogTailStop
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal log_tail_stop payload", "error", err)
			return
		}
		if c.handlers.LogTailStop != nil {
			c.handlers.LogTailStop(msg)
		}

	case "backup_plan":
		var msg BackupRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal backup_plan payload", "error", err)
			return
		}
		if c.handlers.BackupPlan != nil {
			c.handlers.BackupPlan(msg)
		}

	case "backup_start":
		var msg BackupRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal backup_start payload", "error", err)
			return
		}
		if c.handlers.BackupStart != nil {
			c.handlers.BackupStart(msg)
		}

	case "sync_keys":
		var msg SyncKeysRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal sync_keys payload", "error", err)
			return
		}
		if c.handlers.SyncKeys != nil {
			c.handlers.SyncKeys(msg)
		}

	case "agent_update":
		var msg UpdateAgentRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal agent_update payload", "error", err)
			return
		}
		if c.handlers.UpdateAgent != nil {
			c.handlers.UpdateAgent(msg)
		}

	case "check_updates":
		var msg CheckUpdatesRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal check_updates payload", "error", err)
			return
		}
		if c.handlers.CheckUpdates != nil {
			c.handlers.CheckUpdates(msg)
		}

	case "dir_list_request":
		var msg DirListRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal dir_list_request payload", "error", err)
			return
		}
		if c.handlers.DirList != nil {
			c.handlers.DirList(msg)
		}

	case "file_put_start":
		var msg FilePutStartRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal file_put_start payload", "error", err)
			return
		}
		if c.handlers.FilePutStart != nil {
			c.handlers.FilePutStart(msg)
		}

	case "file_put_chunk":
		var msg FilePutChunk
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal file_put_chunk payload", "error", err)
			return
		}
		if c.handlers.FilePutChunk != nil {
			c.handlers.FilePutChunk(msg)
		}

	case "file_put_finish":
		var msg FilePutFinishRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal file_put_finish payload", "error", err)
			return
		}
		if c.handlers.FilePutFinish != nil {
			c.handlers.FilePutFinish(msg)
		}

	case "file_delete_request":
		var msg FileDeleteRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal file_delete_request payload", "error", err)
			return
		}
		if c.handlers.FileDelete != nil {
			c.handlers.FileDelete(msg)
		}

	case "file_chmod_request":
		var msg FileChmodRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal file_chmod_request payload", "error", err)
			return
		}
		if c.handlers.FileChmod != nil {
			c.handlers.FileChmod(msg)
		}

	case "kiosk_set":
		var msg KioskSetRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal kiosk_set payload", "error", err)
			return
		}
		if c.handlers.KioskSet != nil {
			c.handlers.KioskSet(msg)
		}

	default:
		c.log.Warn("unknown signed command event", "event", event)
	}
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
