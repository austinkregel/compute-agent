// Package cmdsig implements cryptographic signing and verification for
// server-to-agent commands. This prevents unauthorized command execution
// by requiring agents to verify that each command originated from the
// legitimate server.
//
// # Security Model
//
// 1. At connection time, server and agent derive a session key from the
//    shared authToken + a server-generated session nonce.
// 2. Every command the server sends includes:
//    - seq: monotonically increasing sequence number (prevents replay)
//    - ts: Unix timestamp in milliseconds (freshness check)
//    - sig: HMAC-SHA256(sessionKey, canonicalPayload)
// 3. Agent verifies signature and rejects commands that:
//    - Have invalid/missing signatures
//    - Have out-of-order or duplicate sequence numbers
//    - Have timestamps too far from agent's clock
//
// # Canonical Payload Format
//
// The signature covers: event + seq + ts + sorted JSON of command fields.
// This ensures both parties compute the same signature regardless of
// JSON field ordering.
package cmdsig

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrInvalidSignature is returned when HMAC verification fails.
var ErrInvalidSignature = errors.New("cmdsig: invalid signature")

// ErrReplayDetected is returned when a sequence number is reused or out of order.
var ErrReplayDetected = errors.New("cmdsig: replay detected (seq out of order)")

// ErrStaleCommand is returned when command timestamp is too old.
var ErrStaleCommand = errors.New("cmdsig: stale command (ts too old)")

// ErrFutureCommand is returned when command timestamp is too far in the future.
var ErrFutureCommand = errors.New("cmdsig: future command (ts too far ahead)")

// ErrMissingSignature is returned when a command lacks required signature fields.
var ErrMissingSignature = errors.New("cmdsig: missing signature fields")

// DefaultMaxClockSkew is the maximum allowed difference between server and agent clocks.
const DefaultMaxClockSkew = 5 * time.Minute

// DefaultMaxSeqGap is the maximum gap allowed in sequence numbers to handle
// occasional packet reordering while still detecting replays.
const DefaultMaxSeqGap = 100

// SignedEnvelope wraps a command payload with signature fields.
// Every server-originated command must include these fields.
type SignedEnvelope struct {
	// Event is the socket.io event name (e.g., "shell_start", "admin_run").
	Event string `json:"event"`

	// Seq is a monotonically increasing sequence number for this session.
	Seq int64 `json:"seq"`

	// Ts is the Unix timestamp in milliseconds when the command was signed.
	Ts int64 `json:"ts"`

	// Sig is the hex-encoded HMAC-SHA256 signature.
	Sig string `json:"sig"`

	// Payload contains the actual command data as a raw JSON object.
	// The signature covers this data.
	Payload json.RawMessage `json:"payload"`
}

// Signer creates signed command envelopes. Used by the server.
type Signer struct {
	sessionKey []byte
	seq        int64
	mu         sync.Mutex
}

// NewSigner creates a signer with the given session key.
func NewSigner(sessionKey []byte) *Signer {
	return &Signer{
		sessionKey: sessionKey,
		seq:        0,
	}
}

// Sign wraps a command payload in a signed envelope.
func (s *Signer) Sign(event string, payload any) (*SignedEnvelope, error) {
	s.mu.Lock()
	s.seq++
	seq := s.seq
	s.mu.Unlock()

	ts := time.Now().UnixMilli()

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	env := &SignedEnvelope{
		Event:   event,
		Seq:     seq,
		Ts:      ts,
		Payload: payloadBytes,
	}

	sig, err := s.computeSignature(env)
	if err != nil {
		return nil, err
	}
	env.Sig = sig

	return env, nil
}

func (s *Signer) computeSignature(env *SignedEnvelope) (string, error) {
	canonical, err := canonicalPayload(env.Event, env.Seq, env.Ts, env.Payload)
	if err != nil {
		return "", err
	}

	mac := hmac.New(sha256.New, s.sessionKey)
	mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// Verifier validates signed command envelopes. Used by the agent.
type Verifier struct {
	sessionKey   []byte
	lastSeq      int64
	seenSeqs     map[int64]struct{} // Track recent seqs for reorder tolerance
	maxClockSkew time.Duration
	maxSeqGap    int64
	mu           sync.Mutex
}

// NewVerifier creates a verifier with the given session key.
func NewVerifier(sessionKey []byte) *Verifier {
	return &Verifier{
		sessionKey:   sessionKey,
		lastSeq:      0,
		seenSeqs:     make(map[int64]struct{}),
		maxClockSkew: DefaultMaxClockSkew,
		maxSeqGap:    DefaultMaxSeqGap,
	}
}

// SetMaxClockSkew configures the maximum allowed clock difference.
func (v *Verifier) SetMaxClockSkew(d time.Duration) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.maxClockSkew = d
}

// Verify checks the signature and replay protection for a command envelope.
// Returns nil if valid, otherwise returns a descriptive error.
func (v *Verifier) Verify(env *SignedEnvelope) error {
	if env == nil {
		return ErrMissingSignature
	}
	if env.Event == "" || env.Sig == "" || env.Seq <= 0 || env.Ts <= 0 {
		return ErrMissingSignature
	}

	// 1. Verify timestamp freshness
	now := time.Now().UnixMilli()
	skewMs := v.maxClockSkew.Milliseconds()

	if env.Ts < now-skewMs {
		return ErrStaleCommand
	}
	if env.Ts > now+skewMs {
		return ErrFutureCommand
	}

	// 2. Verify signature
	canonical, err := canonicalPayload(env.Event, env.Seq, env.Ts, env.Payload)
	if err != nil {
		return fmt.Errorf("canonical payload: %w", err)
	}

	mac := hmac.New(sha256.New, v.sessionKey)
	mac.Write(canonical)
	expected := mac.Sum(nil)

	sigBytes, err := hex.DecodeString(env.Sig)
	if err != nil {
		return ErrInvalidSignature
	}
	if subtle.ConstantTimeCompare(expected, sigBytes) != 1 {
		return ErrInvalidSignature
	}

	// 3. Verify sequence number (replay protection)
	v.mu.Lock()
	defer v.mu.Unlock()

	// Check if we've seen this exact sequence before
	if _, seen := v.seenSeqs[env.Seq]; seen {
		return ErrReplayDetected
	}

	// Allow some out-of-order delivery, but reject if too far behind
	if env.Seq <= v.lastSeq-v.maxSeqGap {
		return ErrReplayDetected
	}

	// Track this sequence
	v.seenSeqs[env.Seq] = struct{}{}

	// Update high-water mark
	if env.Seq > v.lastSeq {
		v.lastSeq = env.Seq
	}

	// Prune old sequence numbers to prevent memory growth
	// Keep only sequences within the gap window of current high-water mark
	for seq := range v.seenSeqs {
		if seq < v.lastSeq-v.maxSeqGap {
			delete(v.seenSeqs, seq)
		}
	}

	return nil
}

// canonicalPayload creates a deterministic byte representation for signing.
// Format: "event|seq|ts|sortedPayloadJSON"
func canonicalPayload(event string, seq, ts int64, payloadRaw json.RawMessage) ([]byte, error) {
	// Decode payload to ensure consistent JSON representation
	var payload map[string]any
	if len(payloadRaw) > 0 {
		if err := json.Unmarshal(payloadRaw, &payload); err != nil {
			// If it's not an object, use as-is
			payload = nil
		}
	}

	var payloadStr string
	if payload != nil {
		// Sort keys and re-encode for determinism
		sortedBytes, err := sortedJSONMarshal(payload)
		if err != nil {
			return nil, err
		}
		payloadStr = string(sortedBytes)
	} else if len(payloadRaw) > 0 {
		payloadStr = string(payloadRaw)
	}

	canonical := fmt.Sprintf("%s|%d|%d|%s", event, seq, ts, payloadStr)
	return []byte(canonical), nil
}

// sortedJSONMarshal marshals a map with sorted keys for deterministic output.
func sortedJSONMarshal(m map[string]any) ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf strings.Builder
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		keyBytes, _ := json.Marshal(k)
		buf.Write(keyBytes)
		buf.WriteByte(':')

		// Recursively handle nested maps
		switch v := m[k].(type) {
		case map[string]any:
			nested, err := sortedJSONMarshal(v)
			if err != nil {
				return nil, err
			}
			buf.Write(nested)
		default:
			valBytes, err := json.Marshal(v)
			if err != nil {
				return nil, err
			}
			buf.Write(valBytes)
		}
	}
	buf.WriteByte('}')
	return []byte(buf.String()), nil
}

// DeriveSessionKey derives a unique session key from the shared authToken
// and a server-provided session nonce. This ensures each connection has
// a unique key, preventing cross-session replay attacks.
//
// sessionKey = HMAC-SHA256(authToken, "cmdsig-session-v1|" + sessionNonce)
func DeriveSessionKey(authToken string, sessionNonce string) []byte {
	data := []byte("cmdsig-session-v1|" + sessionNonce)
	mac := hmac.New(sha256.New, []byte(authToken))
	mac.Write(data)
	return mac.Sum(nil)
}

// GenerateSessionNonce creates a cryptographically random session nonce.
// Called by the server when an agent connects.
func GenerateSessionNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ParseSeq extracts seq from a string (for environments that serialize as string).
func ParseSeq(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}

// ParseTs extracts ts from a string (for environments that serialize as string).
func ParseTs(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}
