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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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
	Namespace         string // Deprecated: ignored for plain WebSocket; kept for backward compat.
	SocketPath        string // WebSocket endpoint path (default: "/ws/agent").
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
	Hello           func()
	AdminRun        func(AdminCommand)
	ShellStart      func(ShellStart)
	ShellInput      func(ShellInput)
	ShellResize     func(ShellResize)
	ShellClose      func(ShellClose)
	LogTailStart    func(LogTailStart)
	LogTailStop     func(LogTailStop)
	BackupPlan      func(BackupRequest)
	BackupStart     func(BackupRequest)
	SyncKeys        func(SyncKeysRequest)
	UpdateAgent     func(UpdateAgentRequest)
	SwitchVariant   func(SwitchVariantRequest)
	CheckUpdates    func(CheckUpdatesRequest)
	DirList         func(DirListRequest)
	Exec            func(ExecRequest)
	ExecCancel      func(ExecCancelRequest)
	ExecAllowlist   func(ExecAllowlist)
	FileGet         func(FileGetRequest)
	FilePutStart    func(FilePutStartRequest)
	FilePutChunk    func(FilePutChunk)
	FilePutFinish   func(FilePutFinishRequest)
	FileDelete      func(FileDeleteRequest)
	FileChmod       func(FileChmodRequest)
	FileMkdir       func(FileMkdirRequest)
	FileRename      func(FileRenameRequest)
	KioskSet        func(KioskSetRequest)
	KioskSaveLayout func(KioskSaveLayoutRequest)
	KioskGetLayouts func(KioskGetLayoutsRequest)

	// Docker/Swarm handlers. Read-only reporting plus cluster join/leave;
	// stack/service/network mutation lives in a separate management tool.
	SwarmInfo        func(SwarmInfoRequest)
	SwarmInit        func(SwarmInitRequest)
	SwarmJoin        func(SwarmJoinRequest)
	SwarmLeave       func(SwarmLeaveRequest)
	SwarmNodeList    func(SwarmNodeListRequest)
	SwarmServiceList func(SwarmServiceListRequest)
	SwarmServiceLogs func(SwarmServiceLogsRequest)
	SwarmNetworkList func(SwarmNetworkListRequest)
	SwarmStackList   func(SwarmStackListRequest)

	ContainerInventory func(ContainerInventoryRequest)
	StackStatus        func(StackStatusRequest)
	ComposeScan        func(ComposeScanRequest)
	ComposeParse       func(ComposeParseRequest)
	ContainerLogs      func(ContainerLogsRequest)

	// NotifySubscribers reports how many dashboards are currently connected, so
	// the agent can gate desktop-notification forwarding.
	NotifySubscribers func(NotifySubscribers)

	// Telephony handlers (phone-class agents only, gated by the "telephony"
	// capability — see commandCapability). Bridge to the Android companion app.
	SMSSend            func(SMSSendRequest)
	SMSThreadRequest   func(SMSThreadRequest)
	SMSMessagesRequest func(SMSMessagesRequest)
}

// NotifySubscribers carries the count of dashboards currently subscribed to an
// agent, so it can gate desktop-notification forwarding (skip work when nobody's
// listening).
type NotifySubscribers struct {
	Count int `json:"count"`
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
// See docs/RFC-0002-directory-browsing.md.
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
	Type       string `json:"type"`                 // "dir" or "file"
	Size       int64  `json:"size,omitempty"`       // optional
	Mode       string `json:"mode,omitempty"`       // Unix permission string, e.g., "drwxr-xr-x"
	ModTime    string `json:"modTime,omitempty"`    // RFC3339 formatted modification time
	IsSymlink  bool   `json:"isSymlink,omitempty"`  // true if entry is a symbolic link
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
	// Variant optionally specifies which variant to download ("headless" or "kiosk").
	// If empty, the agent keeps its current variant.
	Variant string `json:"variant,omitempty"`
}

// SwitchVariantRequest instructs the agent to switch to a different binary variant.
type SwitchVariantRequest struct {
	// Variant is the desired variant: "headless" or "kiosk".
	Variant string `json:"variant"`
	// Repo is the GitHub repository to download from.
	Repo string `json:"repo"`
	// Tag is the version tag to download. If empty, uses current version.
	Tag string `json:"tag,omitempty"`
}

// VariantStatus reports the agent's current variant state.
type VariantStatus struct {
	// Current is the variant of the running binary.
	Current string `json:"current"`
	// Desired is the configured preferred variant.
	Desired string `json:"desired"`
	// KioskAvailable indicates if the current binary has kiosk capability.
	KioskAvailable bool `json:"kioskAvailable"`
	// LastSwitchError is the error from the last failed switch attempt.
	LastSwitchError string `json:"lastSwitchError,omitempty"`
	// LastSwitchAttempt is the RFC3339 timestamp of the last switch attempt.
	LastSwitchAttempt string `json:"lastSwitchAttempt,omitempty"`
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
	Path      string `json:"path"`      // Absolute path where file should be written
	Size      int64  `json:"size"`      // Expected total file size in bytes
	Mode      string `json:"mode"`      // Optional permission mode, e.g., "0644"
	Force     bool   `json:"force"`     // If true, allow writing to dangerous paths
	Overwrite bool   `json:"overwrite"` // If true, overwrite existing files
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

// ExecRequest asks the agent to run an allowlisted command and return its
// output. Generic IDE primitive (git status, build, test, lint, … are all
// client-side helpers over this). cwd, when set, is confined to the IDE's
// allowed roots by the agent.
type ExecRequest struct {
	ClientID   string `json:"clientId"`
	RequestID  string `json:"requestId"`
	Command    string `json:"command"`
	Cwd        string `json:"cwd,omitempty"`
	TimeoutSec int    `json:"timeoutSec,omitempty"`
}

// ExecResult is the agent's response to an ExecRequest.
type ExecResult struct {
	ClientID  string `json:"clientId"`
	RequestID string `json:"requestId"`
	OK        bool   `json:"ok"`
	Code      int    `json:"code"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	Error     string `json:"error,omitempty"`
}

// ExecCancelRequest cancels an in-flight exec_request by id (kills the running
// process). Used by the IDE's agent loop to stop a running command without
// dropping the control-plane connection.
type ExecCancelRequest struct {
	ClientID  string `json:"clientId"`
	RequestID string `json:"requestId"`
}

// ExecAllowlist is pushed by the control plane to set the agent's command
// allowlist (governs both exec and admin_run). Central policy, not per-agent.
type ExecAllowlist struct {
	Commands []string `json:"commands"`
}

// FileGetRequest asks the agent to read a file and stream it back as chunks.
// This is the read half of the file API; the response is one or more
// file_get_chunk frames followed by a terminal file_get_result.
type FileGetRequest struct {
	ClientID  string `json:"clientId"`
	RequestID string `json:"requestId"`
	Path      string `json:"path"`
	MaxSize   int64  `json:"maxSize,omitempty"` // Optional cap; 0 = agent default limit
	Offset    int64  `json:"offset,omitempty"`  // Windowed read: start byte (0 = whole file)
	Length    int64  `json:"length,omitempty"`  // Windowed read: bytes from offset (0 = to EOF)
}

// FileGetResult is the terminal frame of a file read (after all chunks).
type FileGetResult struct {
	ClientID  string `json:"clientId"`
	RequestID string `json:"requestId"`
	OK        bool   `json:"ok"`
	Path      string `json:"path,omitempty"`
	Size      int64  `json:"size,omitempty"` // Total file size
	Error     string `json:"error,omitempty"`
	// Ranged-read metadata (populated for windowed reads).
	Offset    int64  `json:"offset,omitempty"`    // Served window start
	Returned  int64  `json:"returned,omitempty"`  // Bytes streamed
	EOF       bool   `json:"eof,omitempty"`       // Window reached end of file
	Truncated bool   `json:"truncated,omitempty"` // Window cut short by a cap
	ErrorCode string `json:"errorCode,omitempty"`
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

// FileMkdirRequest asks the agent to create a directory (and parents).
type FileMkdirRequest struct {
	ClientID  string `json:"clientId"`
	RequestID string `json:"requestId"`
	Path      string `json:"path"`
	Force     bool   `json:"force"`
}

// FileMkdirResult is the agent's response to a mkdir request.
type FileMkdirResult struct {
	ClientID  string `json:"clientId"`
	RequestID string `json:"requestId"`
	OK        bool   `json:"ok"`
	Path      string `json:"path,omitempty"`
	Error     string `json:"error,omitempty"`
}

// FileRenameRequest asks the agent to rename/move a file or directory.
type FileRenameRequest struct {
	ClientID  string `json:"clientId"`
	RequestID string `json:"requestId"`
	Path      string `json:"path"`    // source
	NewPath   string `json:"newPath"` // destination
	Force     bool   `json:"force"`
}

// FileRenameResult is the agent's response to a rename request.
type FileRenameResult struct {
	ClientID  string `json:"clientId"`
	RequestID string `json:"requestId"`
	OK        bool   `json:"ok"`
	Path      string `json:"path,omitempty"` // destination on success
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

// KioskWidgetPlacement describes a widget's grid position.
type KioskWidgetPlacement struct {
	Type   string         `json:"type"`
	Col    int            `json:"col"`
	Row    int            `json:"row"`
	W      int            `json:"w"`
	H      int            `json:"h"`
	Config map[string]any `json:"config,omitempty"`
}

// KioskContent describes what the kiosk should display.
// Kind determines which fields are used:
//   - "blank": no additional fields
//   - "dashboard": self-reporting system dashboard (no additional fields)
//   - "message": Title (optional) and Text are used
//   - "url": URL is used (must be http: or https:)
//   - "page": Layout and optionally Widgets are used
type KioskContent struct {
	Kind    string                 `json:"kind"`              // "blank", "dashboard", "message", "url", or "page"
	Title   string                 `json:"title,omitempty"`   // for "message" kind
	Text    string                 `json:"text,omitempty"`    // for "message" kind
	URL     string                 `json:"url,omitempty"`     // for "url" kind
	Layout  string                 `json:"layout,omitempty"`  // for "page" kind
	Widgets []KioskWidgetPlacement `json:"widgets,omitempty"` // for "page" kind
	Units   string                 `json:"units,omitempty"`   // "imperial" or "metric"
}

// KioskSetRequest is the signed command payload for setting kiosk content.
type KioskSetRequest struct {
	RequestID string       `json:"requestId,omitempty"`
	Content   KioskContent `json:"content"`
	TS        string       `json:"ts,omitempty"`
}

// KioskSaveLayoutRequest is the signed command payload for saving a kiosk layout.
type KioskSaveLayoutRequest struct {
	Layout  string                 `json:"layout"`
	Cols    int                    `json:"cols"`
	Rows    int                    `json:"rows"`
	Widgets []KioskWidgetPlacement `json:"widgets"`
	Units   string                 `json:"units,omitempty"` // "imperial" or "metric"
	TS      string                 `json:"ts,omitempty"`
}

// KioskGetLayoutsRequest requests the list of saved layouts.
type KioskGetLayoutsRequest struct {
	TS string `json:"ts,omitempty"`
}

// KioskStatus reports the current state of the kiosk subsystem.
type KioskStatus struct {
	Running   bool         `json:"running"`
	Connected bool         `json:"connected"`
	Content   KioskContent `json:"content,omitempty"`
	LastError string       `json:"lastError,omitempty"`
	TS        string       `json:"ts"`
}

// --- WebSocket Protocol ---

// Message is the JSON envelope for all WebSocket communication.
// Agent→Server and Server→Agent messages use this format.
type Message struct {
	Event string          `json:"event"`
	Data  json.RawMessage `json:"data"`
}

// HelloAckPayload contains the session nonce for command signing.
type HelloAckPayload struct {
	SessionNonce string `json:"sessionNonce,omitempty"`
}

// Client maintains the WebSocket session to the control plane.
type Client struct {
	cfg      Config
	log      *logging.Logger
	handlers Handlers

	connMu sync.RWMutex
	conn   *websocket.Conn

	// writeMu serializes WebSocket writes. Emit is called from the read-loop
	// dispatch, the telemetry ticker, shell-output callbacks, and async command
	// handlers; the underlying conn permits only one writer at a time.
	writeMu sync.Mutex

	// fileGetSem bounds concurrent file_get handlers (each can buffer a sizable
	// file), so a flood of requests can't exhaust agent memory/FDs.
	fileGetSem chan struct{}

	// lastTraffic stores the unix nano timestamp of the last inbound/outbound
	// control-plane traffic. A value of 0 means "not connected / unknown".
	lastTraffic atomic.Int64
	helloAcked  atomic.Bool

	// Command signature verification (per-session)
	verifierMu sync.RWMutex
	verifier   *cmdsig.Verifier

	// CapabilityGate, when set, reports whether the agent currently has the
	// named capability enabled (see pkg/capability.Registry.Has). Wired by
	// agent.New. dispatchSignedCommand consults commandCapability to find
	// capability-scoped events and refuses them when this returns false (or
	// is nil) — a fail-closed gate so a compromised/buggy control plane can
	// never make an agent execute a command class it never declared support
	// for (e.g. sms_send on a desktop agent with no telephony companion).
	CapabilityGate func(name string) bool
}

// commandCapability maps capability-scoped signed-command event names to the
// capability name (see pkg/capability) required to execute them. Events not
// listed here are unscoped and dispatch unconditionally (once signature
// verification passes), matching today's behavior. Telephony entries are
// reserved ahead of the feature landing — inert until dispatchSignedCommand
// grows the matching cases, and safe to ship now since an unrecognized event
// name is a no-op regardless of this table.
var commandCapability = map[string]string{
	"sms_send":             "telephony",
	"sms_thread_request":   "telephony",
	"sms_messages_request": "telephony",
	"call_control":         "telephony",
	"call_dial":            "telephony",
	"call_bridge_offer":    "telephony",
	"call_bridge_ice":      "telephony",
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
	if cfg.SocketPath == "" {
		cfg.SocketPath = "/ws/agent"
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

	// Validate server URL
	if _, err := url.Parse(cfg.ServerURL); err != nil {
		return nil, fmt.Errorf("parse server URL: %w", err)
	}

	return &Client{
		cfg:        cfg,
		log:        log,
		handlers:   handlers,
		fileGetSem: make(chan struct{}, 8),
	}, nil
}

// Run establishes the control plane session and reconnects with backoff until ctx is cancelled.
func (c *Client) Run(ctx context.Context) error {
	c.log.Info("transport loop starting",
		"serverUrl", c.cfg.ServerURL,
		"path", c.cfg.SocketPath)

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
	conn := c.currentConn()
	if conn == nil {
		return ErrNotConnected
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	msg := Message{Event: event, Data: data}
	out, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	c.log.Debug("emit event", "event", event)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c.writeMu.Lock()
	err = conn.Write(ctx, websocket.MessageText, out)
	c.writeMu.Unlock()
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}
	c.touchTraffic()
	return nil
}

func (c *Client) connectOnce(ctx context.Context) error {
	c.helloAcked.Store(false)
	c.lastTraffic.Store(0)
	c.clearVerifier()

	wsURL, err := c.handshakeURL()
	if err != nil {
		return err
	}

	httpClient := &http.Client{Transport: c.httpTransport()}

	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPClient: httpClient,
	})
	if err != nil {
		return fmt.Errorf("websocket dial: %w", err)
	}

	// Set read limit to 1 MB (for file chunk messages)
	conn.SetReadLimit(1 << 20)

	c.setConn(conn)
	c.touchTraffic()
	c.log.Info("agent websocket connected")

	stop := make(chan struct{})
	defer close(stop)
	go c.proactivePingLoop(ctx, stop)

	err = c.readLoop(ctx, conn)

	c.setConn(nil)
	c.lastTraffic.Store(0)
	conn.Close(websocket.StatusNormalClosure, "closing")

	return err
}

// readLoop reads JSON messages from the WebSocket and dispatches them.
func (c *Client) readLoop(ctx context.Context, conn *websocket.Conn) error {
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		c.touchTraffic()

		var msg Message
		if err := json.Unmarshal(data, &msg); err != nil {
			c.log.Error("failed to unmarshal message", "error", err)
			continue
		}

		c.dispatchMessage(msg)
	}
}

// dispatchMessage routes an incoming WebSocket message to the appropriate handler.
func (c *Client) dispatchMessage(msg Message) {
	switch msg.Event {
	case "hello_ack":
		var payload HelloAckPayload
		if err := json.Unmarshal(msg.Data, &payload); err != nil {
			c.log.Error("failed to unmarshal hello_ack", "error", err)
			return
		}
		c.helloAcked.Store(true)

		// Command signing is mandatory - server MUST provide session nonce
		if payload.SessionNonce == "" {
			c.log.Error("server did not provide session nonce - command signing required")
		} else {
			sessionKey := cmdsig.DeriveSessionKey(c.cfg.AuthToken, payload.SessionNonce)
			verifier := cmdsig.NewVerifier(sessionKey)
			if c.cfg.MaxClockSkew > 0 {
				verifier.SetMaxClockSkew(c.cfg.MaxClockSkew)
			}
			c.setVerifier(verifier)
			c.log.Info("command signing initialized",
				"noncePrefix", payload.SessionNonce[:8]+"...")
		}

		c.log.Debug("recv event", "event", "hello_ack")
		if c.handlers.Hello != nil {
			c.handlers.Hello()
		}

	case "ping":
		var ping struct {
			TS int64 `json:"ts"`
		}
		if err := json.Unmarshal(msg.Data, &ping); err != nil {
			c.log.Error("failed to unmarshal ping", "error", err)
			return
		}
		c.log.Debug("recv event", "event", "ping", "ts", ping.TS)
		_ = c.Emit("pong", map[string]int64{"ts": ping.TS})

	case "signed_command":
		var envelope cmdsig.SignedEnvelope
		if err := json.Unmarshal(msg.Data, &envelope); err != nil {
			c.log.Error("failed to unmarshal signed_command envelope", "error", err)
			return
		}

		// Verify the signature
		if err := c.verifyCommand(&envelope); err != nil {
			c.log.Warn("rejecting signed_command", "event", envelope.Event, "error", err)
			_ = c.Emit("command_rejected", map[string]any{
				"event": envelope.Event,
				"seq":   envelope.Seq,
				"error": err.Error(),
			})
			return
		}

		c.log.Debug("verified signed_command", "event", envelope.Event, "seq", envelope.Seq)
		c.dispatchSignedCommand(envelope.Event, envelope.Payload)

	default:
		// Unsigned events are rejected — all commands must come via signed_command.
		c.log.Warn("ignoring unsigned event", "event", msg.Event)
	}
}

func (c *Client) handshakeURL() (string, error) {
	ts := time.Now().UnixMilli()
	payload := fmt.Sprintf("{\"clientId\":\"%s\",\"ts\":%d}", c.cfg.ClientID, ts)
	sum := hmac.New(sha256.New, []byte(c.cfg.AuthToken))
	sum.Write([]byte(payload))
	sig := hex.EncodeToString(sum.Sum(nil))

	u, err := url.Parse(c.cfg.ServerURL)
	if err != nil {
		return "", fmt.Errorf("parse server URL: %w", err)
	}

	u.Path = c.cfg.SocketPath
	q := u.Query()
	q.Set("clientId", c.cfg.ClientID)
	q.Set("ts", strconv.FormatInt(ts, 10))
	q.Set("sig", sig)
	u.RawQuery = q.Encode()

	return u.String(), nil
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

func (c *Client) currentConn() *websocket.Conn {
	c.connMu.RLock()
	defer c.connMu.RUnlock()
	return c.conn
}

func (c *Client) setConn(conn *websocket.Conn) {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	c.conn = conn
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
// actorPayloadKey carries the principal that caused a command, folded into the
// signed payload by the control plane. Riding inside the payload puts it under
// the command signature, so rewriting it invalidates the command. Absent on
// commands from servers predating the field.
const actorPayloadKey = "_actor"

// actorOf extracts the acting principal from a signed payload.
func actorOf(payload json.RawMessage) string {
	if len(payload) == 0 {
		return ""
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return ""
	}
	raw, ok := envelope[actorPayloadKey]
	if !ok {
		return ""
	}
	var actor string
	if err := json.Unmarshal(raw, &actor); err != nil {
		return ""
	}
	return actor
}

// highVolumeCommands arrive per keystroke (shell_input) or per chunk of a file
// transfer, so they are attributed at Debug. The session-scoped command that
// opened the stream is recorded at Info, which is what ties the stream to a
// person; logging every frame would bury it.
var highVolumeCommands = map[string]bool{
	"shell_input":     true,
	"shell_resize":    true,
	"file_put_chunk":  true,
	"log_tail_output": true,
}

func (c *Client) dispatchSignedCommand(event string, payload json.RawMessage) {
	// Record who caused this before running it. The agent's log persists on the
	// managed machine independently of the control plane's audit trail.
	actor := actorOf(payload)
	if actor == "" {
		actor = "unattributed"
	}
	if highVolumeCommands[event] {
		c.log.Debug("executing signed command", "event", event, "actor", actor)
	} else {
		c.log.Info("executing signed command", "event", event, "actor", actor)
	}

	if reqCap, scoped := commandCapability[event]; scoped {
		if c.CapabilityGate == nil || !c.CapabilityGate(reqCap) {
			c.log.Warn("refusing capability-scoped command", "event", event, "capability", reqCap)
			_ = c.Emit("command_rejected", map[string]any{
				"event": event,
				"error": "capability_unavailable",
			})
			return
		}
	}

	switch event {
	case "admin_run":
		var msg AdminCommand
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal admin_run payload", "error", err)
			return
		}
		if c.handlers.AdminRun != nil {
			// Off the read loop (same rationale as exec_request).
			go c.handlers.AdminRun(msg)
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

	case "switch_variant":
		var msg SwitchVariantRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal switch_variant payload", "error", err)
			return
		}
		if c.handlers.SwitchVariant != nil {
			c.handlers.SwitchVariant(msg)
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

	case "exec_request":
		var msg ExecRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal exec_request payload", "error", err)
			return
		}
		if c.handlers.Exec != nil {
			// Off the read loop: an exec (e.g. a multi-minute `rebase-indexer
			// index`) must not block ping/pong or other messages. The admin
			// runner's own concurrency limit serializes the work.
			go c.handlers.Exec(msg)
		}

	case "exec_cancel":
		var msg ExecCancelRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal exec_cancel payload", "error", err)
			return
		}
		if c.handlers.ExecCancel != nil {
			// Instant (just cancels a context) — run inline.
			c.handlers.ExecCancel(msg)
		}

	case "exec_allowlist":
		var msg ExecAllowlist
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal exec_allowlist payload", "error", err)
			return
		}
		if c.handlers.ExecAllowlist != nil {
			c.handlers.ExecAllowlist(msg)
		}

	case "file_get_request":
		var msg FileGetRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal file_get_request payload", "error", err)
			return
		}
		if c.handlers.FileGet != nil {
			// Off the read loop: streaming a large file (e.g. a packed index
			// archive) chunk-by-chunk must not block ping/pong, or the control
			// plane drops the agent mid-transfer. Chunks carry requestId, so
			// concurrent downloads stay correlated. Bounded by fileGetSem so a
			// flood can't exhaust memory/FDs.
			go func() {
				// fileGetSem is nil when a Client is built without New() (tests);
				// only gate when it's configured.
				if c.fileGetSem != nil {
					c.fileGetSem <- struct{}{}
					defer func() { <-c.fileGetSem }()
				}
				c.handlers.FileGet(msg)
			}()
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

	case "file_mkdir_request":
		var msg FileMkdirRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal file_mkdir_request payload", "error", err)
			return
		}
		if c.handlers.FileMkdir != nil {
			c.handlers.FileMkdir(msg)
		}

	case "file_rename_request":
		var msg FileRenameRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal file_rename_request payload", "error", err)
			return
		}
		if c.handlers.FileRename != nil {
			c.handlers.FileRename(msg)
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

	case "kiosk_save_layout":
		var msg KioskSaveLayoutRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal kiosk_save_layout payload", "error", err)
			return
		}
		if c.handlers.KioskSaveLayout != nil {
			c.handlers.KioskSaveLayout(msg)
		}

	case "kiosk_get_layouts":
		var msg KioskGetLayoutsRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("failed to unmarshal kiosk_get_layouts payload", "error", err)
			return
		}
		if c.handlers.KioskGetLayouts != nil {
			c.handlers.KioskGetLayouts(msg)
		}

	case "swarm_info":
		var msg SwarmInfoRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("unmarshal swarm_info", "error", err)
			return
		}
		if c.handlers.SwarmInfo != nil {
			c.handlers.SwarmInfo(msg)
		}

	case "swarm_init":
		var msg SwarmInitRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("unmarshal swarm_init", "error", err)
			return
		}
		if c.handlers.SwarmInit != nil {
			c.handlers.SwarmInit(msg)
		}

	case "swarm_join":
		var msg SwarmJoinRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("unmarshal swarm_join", "error", err)
			return
		}
		if c.handlers.SwarmJoin != nil {
			c.handlers.SwarmJoin(msg)
		}

	case "swarm_leave":
		var msg SwarmLeaveRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("unmarshal swarm_leave", "error", err)
			return
		}
		if c.handlers.SwarmLeave != nil {
			c.handlers.SwarmLeave(msg)
		}

	case "swarm_node_list":
		var msg SwarmNodeListRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("unmarshal swarm_node_list", "error", err)
			return
		}
		if c.handlers.SwarmNodeList != nil {
			c.handlers.SwarmNodeList(msg)
		}

	case "swarm_service_list":
		var msg SwarmServiceListRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("unmarshal swarm_service_list", "error", err)
			return
		}
		if c.handlers.SwarmServiceList != nil {
			c.handlers.SwarmServiceList(msg)
		}

	case "swarm_service_logs":
		var msg SwarmServiceLogsRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("unmarshal swarm_service_logs", "error", err)
			return
		}
		if c.handlers.SwarmServiceLogs != nil {
			c.handlers.SwarmServiceLogs(msg)
		}

	case "swarm_network_list":
		var msg SwarmNetworkListRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("unmarshal swarm_network_list", "error", err)
			return
		}
		if c.handlers.SwarmNetworkList != nil {
			c.handlers.SwarmNetworkList(msg)
		}

	case "swarm_stack_list":
		var msg SwarmStackListRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("unmarshal swarm_stack_list", "error", err)
			return
		}
		if c.handlers.SwarmStackList != nil {
			c.handlers.SwarmStackList(msg)
		}

	case "container_inventory":
		var msg ContainerInventoryRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("unmarshal container_inventory", "error", err)
			return
		}
		if c.handlers.ContainerInventory != nil {
			c.handlers.ContainerInventory(msg)
		}

	case "stack_status":
		var msg StackStatusRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("unmarshal stack_status", "error", err)
			return
		}
		if c.handlers.StackStatus != nil {
			c.handlers.StackStatus(msg)
		}

	case "compose_scan":
		var msg ComposeScanRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("unmarshal compose_scan", "error", err)
			return
		}
		if c.handlers.ComposeScan != nil {
			c.handlers.ComposeScan(msg)
		}

	case "compose_parse":
		var msg ComposeParseRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("unmarshal compose_parse", "error", err)
			return
		}
		if c.handlers.ComposeParse != nil {
			c.handlers.ComposeParse(msg)
		}

	case "container_logs":
		var msg ContainerLogsRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("unmarshal container_logs", "error", err)
			return
		}
		if c.handlers.ContainerLogs != nil {
			c.handlers.ContainerLogs(msg)
		}

	case "sms_send":
		var msg SMSSendRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("unmarshal sms_send", "error", err)
			return
		}
		if c.handlers.SMSSend != nil {
			c.handlers.SMSSend(msg)
		}

	case "sms_thread_request":
		var msg SMSThreadRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("unmarshal sms_thread_request", "error", err)
			return
		}
		if c.handlers.SMSThreadRequest != nil {
			c.handlers.SMSThreadRequest(msg)
		}

	case "sms_messages_request":
		var msg SMSMessagesRequest
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.log.Error("unmarshal sms_messages_request", "error", err)
			return
		}
		if c.handlers.SMSMessagesRequest != nil {
			c.handlers.SMSMessagesRequest(msg)
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

func nextDelay(current, max time.Duration) time.Duration {
	next := current * 2
	if next > max {
		return max
	}
	return next
}
