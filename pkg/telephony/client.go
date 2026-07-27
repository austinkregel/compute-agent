// Package telephony bridges the Go agent to the Android companion app (see
// app/README.md) over a loopback TCP connection, exposing SMS send/receive
// today (M1) and reserved for a VoLTE call-audio bridge later (M3).
//
// Protocol: one JSON object per line over a persistent TCP connection the
// agent initiates. See CompanionService's doc comment (app/companion/src/main/
// java/dev/kregel/homelab/companion/telephony/CompanionService.kt) for the
// authoritative wire format; this client is the Go-side mirror of it.
package telephony

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/austinkregel/compute-agent/pkg/logging"
)

// ErrNotConnected is returned by Request when there's no live companion connection.
var ErrNotConnected = errors.New("telephony: companion app not connected")

const requestTimeout = 15 * time.Second

// Config configures the companion connection.
type Config struct {
	// CompanionAddr is the companion app's loopback address, e.g. "127.0.0.1:47800".
	CompanionAddr string
	// CompanionToken is the shared pairing secret shown in the companion app's UI.
	CompanionToken string
}

// Client maintains a reconnecting TCP connection to the companion app.
type Client struct {
	cfg Config
	log *logging.Logger

	// OnEvent is called for each unsolicited `event` message from the
	// companion app (e.g. "sms.received"). May be called concurrently with
	// Request; must not block.
	OnEvent func(event string, payload map[string]any)

	connMu sync.Mutex
	conn   net.Conn

	pendingMu sync.Mutex
	pending   map[string]chan map[string]any

	connected atomic.Bool
	writeMu   sync.Mutex
}

// NewClient creates a companion client. Call Run to start connecting.
func NewClient(cfg Config, log *logging.Logger) *Client {
	return &Client{
		cfg:     cfg,
		log:     log,
		pending: make(map[string]chan map[string]any),
	}
}

// Connected reports whether a companion connection is currently established
// and past the handshake. Used by the "telephony" capability probe.
func (c *Client) Connected() bool {
	return c.connected.Load()
}

// Run connects to the companion app, reconnecting with backoff until ctx is
// canceled. It never returns until ctx is done (or a non-recoverable setup
// error, which shouldn't occur given Config is validated before Run).
func (c *Client) Run(ctx context.Context) error {
	backoff := time.Second
	const maxBackoff = 30 * time.Second

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		connectedAt := time.Now()
		err := c.connectOnce(ctx)
		c.connected.Store(false)
		c.setConn(nil)

		if err != nil && !errors.Is(err, context.Canceled) {
			c.log.Debug("companion connection lost", "error", err)
		}

		// A connection that stayed up a while was healthy; don't let a later
		// transient drop pay the full accumulated backoff from earlier retries.
		if time.Since(connectedAt) > maxBackoff {
			backoff = time.Second
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (c *Client) connectOnce(ctx context.Context) error {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", c.cfg.CompanionAddr)
	if err != nil {
		return fmt.Errorf("dial companion: %w", err)
	}
	defer conn.Close()

	if err := writeLine(conn, map[string]any{"type": "hello", "token": c.cfg.CompanionToken}); err != nil {
		return fmt.Errorf("companion handshake write: %w", err)
	}

	reader := bufio.NewReader(conn)
	ackLine, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("companion handshake read: %w", err)
	}
	var ack struct {
		Type string `json:"type"`
		OK   bool   `json:"ok"`
	}
	if err := json.Unmarshal([]byte(ackLine), &ack); err != nil || ack.Type != "hello_ack" {
		return fmt.Errorf("companion handshake: unexpected response %q", ackLine)
	}
	if !ack.OK {
		return errors.New("companion handshake rejected (token mismatch)")
	}

	c.setConn(conn)
	c.connected.Store(true)
	c.log.Info("companion app connected", "addr", c.cfg.CompanionAddr)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("companion read: %w", err)
		}
		if len(line) == 0 {
			continue
		}

		var msg map[string]any
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			c.log.Debug("companion sent invalid JSON line", "error", err)
			continue
		}

		switch msg["type"] {
		case "response":
			id, _ := msg["id"].(string)
			c.resolvePending(id, msg)
		case "event":
			event, _ := msg["event"].(string)
			payload, _ := msg["payload"].(map[string]any)
			if c.OnEvent != nil {
				c.OnEvent(event, payload)
			}
		}
	}
}

// Request sends {"type":"request","op":op,"payload":payload} and waits for
// the matching response, returning its "payload" (may be a map or a slice,
// depending on the op — callers type-assert as needed).
func (c *Client) Request(ctx context.Context, op string, payload map[string]any) (any, error) {
	conn := c.getConn()
	if conn == nil {
		return nil, ErrNotConnected
	}

	id := newRequestID()
	ch := make(chan map[string]any, 1)
	c.registerPending(id, ch)
	defer c.unregisterPending(id)

	req := map[string]any{"type": "request", "id": id, "op": op, "payload": payload}
	if err := writeLineLocked(&c.writeMu, conn, req); err != nil {
		return nil, fmt.Errorf("companion write: %w", err)
	}

	select {
	case resp := <-ch:
		if ok, _ := resp["ok"].(bool); !ok {
			errMsg, _ := resp["error"].(string)
			if errMsg == "" {
				errMsg = "companion request failed"
			}
			return nil, errors.New(errMsg)
		}
		return resp["payload"], nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(requestTimeout):
		return nil, errors.New("companion request timed out")
	}
}

func (c *Client) setConn(conn net.Conn) {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	c.conn = conn
}

func (c *Client) getConn() net.Conn {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	return c.conn
}

func (c *Client) registerPending(id string, ch chan map[string]any) {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	c.pending[id] = ch
}

func (c *Client) unregisterPending(id string) {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	delete(c.pending, id)
}

func (c *Client) resolvePending(id string, msg map[string]any) {
	c.pendingMu.Lock()
	ch, ok := c.pending[id]
	c.pendingMu.Unlock()
	if !ok {
		return
	}
	select {
	case ch <- msg:
	default:
	}
}

func writeLine(conn net.Conn, v map[string]any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = conn.Write(data)
	return err
}

func writeLineLocked(mu *sync.Mutex, conn net.Conn, v map[string]any) error {
	mu.Lock()
	defer mu.Unlock()
	return writeLine(conn, v)
}

func newRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
