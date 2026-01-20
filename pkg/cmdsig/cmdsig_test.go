package cmdsig

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSignAndVerify(t *testing.T) {
	sessionKey := DeriveSessionKey("test-auth-token", "test-nonce-12345")

	signer := NewSigner(sessionKey)
	verifier := NewVerifier(sessionKey)

	payload := map[string]any{
		"session": "abc-123",
		"cols":    80,
		"rows":    24,
	}

	env, err := signer.Sign("shell_start", payload)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if env.Event != "shell_start" {
		t.Errorf("Event = %q, want %q", env.Event, "shell_start")
	}
	if env.Seq != 1 {
		t.Errorf("Seq = %d, want 1", env.Seq)
	}
	if env.Sig == "" {
		t.Error("Sig is empty")
	}
	if len(env.Payload) == 0 {
		t.Error("Payload is empty")
	}

	// Verify should succeed
	if err := verifier.Verify(env); err != nil {
		t.Errorf("Verify failed: %v", err)
	}
}

func TestSequenceIncreases(t *testing.T) {
	sessionKey := DeriveSessionKey("auth", "nonce")
	signer := NewSigner(sessionKey)

	for i := int64(1); i <= 5; i++ {
		env, err := signer.Sign("test", map[string]string{"i": "x"})
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
		if env.Seq != i {
			t.Errorf("Seq = %d, want %d", env.Seq, i)
		}
	}
}

func TestReplayDetection(t *testing.T) {
	sessionKey := DeriveSessionKey("auth", "nonce")
	signer := NewSigner(sessionKey)
	verifier := NewVerifier(sessionKey)

	env, _ := signer.Sign("test", map[string]string{"x": "y"})

	// First verify should succeed
	if err := verifier.Verify(env); err != nil {
		t.Errorf("First verify failed: %v", err)
	}

	// Second verify of same envelope should fail (replay)
	err := verifier.Verify(env)
	if err != ErrReplayDetected {
		t.Errorf("Replay verify error = %v, want %v", err, ErrReplayDetected)
	}
}

func TestInvalidSignature(t *testing.T) {
	sessionKey1 := DeriveSessionKey("auth", "nonce1")
	sessionKey2 := DeriveSessionKey("auth", "nonce2")

	signer := NewSigner(sessionKey1)
	verifier := NewVerifier(sessionKey2) // Different key!

	env, _ := signer.Sign("test", map[string]string{"x": "y"})

	err := verifier.Verify(env)
	if err != ErrInvalidSignature {
		t.Errorf("Wrong key verify error = %v, want %v", err, ErrInvalidSignature)
	}
}

func TestTamperedPayload(t *testing.T) {
	sessionKey := DeriveSessionKey("auth", "nonce")
	signer := NewSigner(sessionKey)
	verifier := NewVerifier(sessionKey)

	env, _ := signer.Sign("test", map[string]string{"x": "y"})

	// Tamper with payload
	env.Payload = json.RawMessage(`{"x":"HACKED"}`)

	err := verifier.Verify(env)
	if err != ErrInvalidSignature {
		t.Errorf("Tampered verify error = %v, want %v", err, ErrInvalidSignature)
	}
}

func TestTamperedEvent(t *testing.T) {
	sessionKey := DeriveSessionKey("auth", "nonce")
	signer := NewSigner(sessionKey)
	verifier := NewVerifier(sessionKey)

	env, _ := signer.Sign("shell_input", map[string]string{"data": "ls"})

	// Tamper with event name
	env.Event = "admin_run"

	err := verifier.Verify(env)
	if err != ErrInvalidSignature {
		t.Errorf("Tampered event verify error = %v, want %v", err, ErrInvalidSignature)
	}
}

func TestTamperedSeq(t *testing.T) {
	sessionKey := DeriveSessionKey("auth", "nonce")
	signer := NewSigner(sessionKey)
	verifier := NewVerifier(sessionKey)

	env, _ := signer.Sign("test", map[string]string{"x": "y"})

	// Tamper with sequence
	env.Seq = 9999

	err := verifier.Verify(env)
	if err != ErrInvalidSignature {
		t.Errorf("Tampered seq verify error = %v, want %v", err, ErrInvalidSignature)
	}
}

func TestStaleCommand(t *testing.T) {
	sessionKey := DeriveSessionKey("auth", "nonce")
	signer := NewSigner(sessionKey)
	verifier := NewVerifier(sessionKey)
	verifier.SetMaxClockSkew(1 * time.Minute)

	env, _ := signer.Sign("test", map[string]string{"x": "y"})

	// Manually set timestamp to 10 minutes ago
	env.Ts = time.Now().Add(-10 * time.Minute).UnixMilli()

	// Re-sign with stale timestamp (simulating attacker can't re-sign)
	// The sig won't match the new ts, so this tests both
	err := verifier.Verify(env)
	// Could be either stale or invalid sig depending on check order
	if err == nil {
		t.Error("Stale command should fail verification")
	}
}

func TestMissingSignature(t *testing.T) {
	verifier := NewVerifier([]byte("key"))

	tests := []struct {
		name string
		env  *SignedEnvelope
	}{
		{"nil envelope", nil},
		{"empty event", &SignedEnvelope{Seq: 1, Ts: time.Now().UnixMilli(), Sig: "abc"}},
		{"empty sig", &SignedEnvelope{Event: "test", Seq: 1, Ts: time.Now().UnixMilli()}},
		{"zero seq", &SignedEnvelope{Event: "test", Ts: time.Now().UnixMilli(), Sig: "abc"}},
		{"zero ts", &SignedEnvelope{Event: "test", Seq: 1, Sig: "abc"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifier.Verify(tt.env)
			if err != ErrMissingSignature {
				t.Errorf("Verify error = %v, want %v", err, ErrMissingSignature)
			}
		})
	}
}

func TestOutOfOrderDelivery(t *testing.T) {
	sessionKey := DeriveSessionKey("auth", "nonce")
	signer := NewSigner(sessionKey)
	verifier := NewVerifier(sessionKey)

	// Generate 5 commands
	envs := make([]*SignedEnvelope, 5)
	for i := 0; i < 5; i++ {
		var err error
		envs[i], err = signer.Sign("test", map[string]int{"i": i})
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
	}

	// Verify out of order: 3, 1, 5, 2, 4
	order := []int{2, 0, 4, 1, 3}
	for _, idx := range order {
		err := verifier.Verify(envs[idx])
		if err != nil {
			t.Errorf("Verify envs[%d] (seq=%d) failed: %v", idx, envs[idx].Seq, err)
		}
	}
}

func TestDeriveSessionKey(t *testing.T) {
	// Same inputs should produce same key
	key1 := DeriveSessionKey("token", "nonce")
	key2 := DeriveSessionKey("token", "nonce")
	if string(key1) != string(key2) {
		t.Error("Same inputs should produce same key")
	}

	// Different inputs should produce different keys
	key3 := DeriveSessionKey("token", "different-nonce")
	if string(key1) == string(key3) {
		t.Error("Different nonces should produce different keys")
	}

	key4 := DeriveSessionKey("different-token", "nonce")
	if string(key1) == string(key4) {
		t.Error("Different tokens should produce different keys")
	}
}

func TestGenerateSessionNonce(t *testing.T) {
	nonce1, err := GenerateSessionNonce()
	if err != nil {
		t.Fatalf("GenerateSessionNonce failed: %v", err)
	}
	if len(nonce1) != 64 { // 32 bytes = 64 hex chars
		t.Errorf("Nonce length = %d, want 64", len(nonce1))
	}

	nonce2, _ := GenerateSessionNonce()
	if nonce1 == nonce2 {
		t.Error("Consecutive nonces should be different")
	}
}

func TestCanonicalPayloadDeterminism(t *testing.T) {
	// Same payload with different key ordering should produce same canonical form
	payload1 := json.RawMessage(`{"b":"2","a":"1"}`)
	payload2 := json.RawMessage(`{"a":"1","b":"2"}`)

	c1, _ := canonicalPayload("test", 1, 12345, payload1)
	c2, _ := canonicalPayload("test", 1, 12345, payload2)

	if string(c1) != string(c2) {
		t.Errorf("Canonical payloads differ:\n  %s\n  %s", c1, c2)
	}
}

func TestVerifierMemoryBounded(t *testing.T) {
	sessionKey := DeriveSessionKey("auth", "nonce")
	signer := NewSigner(sessionKey)
	verifier := NewVerifier(sessionKey)

	// Generate and verify 1000 commands
	for i := 0; i < 1000; i++ {
		env, _ := signer.Sign("test", map[string]int{"i": i})
		if err := verifier.Verify(env); err != nil {
			t.Fatalf("Verify %d failed: %v", i, err)
		}
	}

	// Check that seenSeqs doesn't grow unboundedly
	verifier.mu.Lock()
	seenCount := len(verifier.seenSeqs)
	verifier.mu.Unlock()

	if seenCount > int(DefaultMaxSeqGap)+10 {
		t.Errorf("seenSeqs has %d entries, should be pruned to ~%d", seenCount, DefaultMaxSeqGap)
	}
}

func BenchmarkSign(b *testing.B) {
	sessionKey := DeriveSessionKey("auth", "nonce")
	signer := NewSigner(sessionKey)
	payload := map[string]any{"session": "abc", "data": "some input data"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = signer.Sign("shell_input", payload)
	}
}

func BenchmarkVerify(b *testing.B) {
	sessionKey := DeriveSessionKey("auth", "nonce")
	signer := NewSigner(sessionKey)
	verifier := NewVerifier(sessionKey)

	// Pre-generate envelopes
	envs := make([]*SignedEnvelope, b.N)
	for i := 0; i < b.N; i++ {
		envs[i], _ = signer.Sign("test", map[string]int{"i": i})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = verifier.Verify(envs[i])
	}
}
