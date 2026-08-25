package admin

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"aead.dev/minisign"

	"github.com/austinkregel/compute-agent/pkg/config"
	"github.com/austinkregel/compute-agent/pkg/logging"
)

// A non-empty allowlist that does NOT match our test binary, so the only way a
// command is permitted is via a valid signature (an empty allowlist means
// allow-all, which would mask what we're testing).
var unrelatedAllowlist = []string{"git status"}

func testRunner(t *testing.T, signers []string, strict bool) *Runner {
	t.Helper()
	log, err := logging.New(logging.Options{Level: "error"})
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	cfg := &config.Config{
		Admin: config.AdminConfig{
			Allowed:              unrelatedAllowlist,
			TrustedSigners:       signers,
			SignatureTrustStrict: strict,
			MaxConcurrent:        1,
		},
	}
	return NewRunner(cfg, log, ShellCallbacks{})
}

// writeSignedBinary drops a fake binary + its `<path>.minisig` in a temp dir,
// signed by priv, and returns the binary path.
func writeSignedBinary(t *testing.T, priv minisign.PrivateKey, contents []byte) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "rebase-indexer")
	if err := os.WriteFile(bin, contents, 0o755); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	sig := minisign.Sign(priv, contents)
	if err := os.WriteFile(bin+".minisig", sig, 0o644); err != nil {
		t.Fatalf("write sig: %v", err)
	}
	return bin
}

func pubText(t *testing.T, pub minisign.PublicKey) string {
	t.Helper()
	b, err := pub.MarshalText()
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}
	return string(b)
}

func TestSignedBinary_Permitted(t *testing.T) {
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	bin := writeSignedBinary(t, priv, []byte("indexer bytes"))
	r := testRunner(t, []string{pubText(t, pub)}, false)

	if r.isAllowed([]string{bin}) {
		t.Fatal("precondition: binary should NOT be allowlisted")
	}
	if !r.permitted([]string{bin, "index", "/srv/app"}) {
		t.Error("a validly-signed binary should be permitted despite the allowlist")
	}
}

func TestSignedBinary_TamperedIsBlocked(t *testing.T) {
	pub, priv, _ := minisign.GenerateKey(rand.Reader)
	bin := writeSignedBinary(t, priv, []byte("original"))
	r := testRunner(t, []string{pubText(t, pub)}, false)

	if !r.permitted([]string{bin}) {
		t.Fatal("baseline: signed binary should be permitted")
	}
	// Overwrite the binary after signing — the size/mtime change must bust the
	// memo and the stale signature must fail.
	if err := os.WriteFile(bin, []byte("evil-payload-different-length"), 0o755); err != nil {
		t.Fatal(err)
	}
	if r.permitted([]string{bin}) {
		t.Error("a tampered binary must be blocked (and the cache must re-verify)")
	}
}

func TestSignedBinary_UntrustedKeyIsBlocked(t *testing.T) {
	// Signed by one key, but the runner trusts a different key.
	_, priv, _ := minisign.GenerateKey(rand.Reader)
	otherPub, _, _ := minisign.GenerateKey(rand.Reader)
	bin := writeSignedBinary(t, priv, []byte("indexer"))
	r := testRunner(t, []string{pubText(t, otherPub)}, false)

	if r.permitted([]string{bin}) {
		t.Error("a signature from a non-pinned key must not be trusted")
	}
}

func TestSignedBinary_MissingSignatureIsBlocked(t *testing.T) {
	pub, _, _ := minisign.GenerateKey(rand.Reader)
	dir := t.TempDir()
	bin := filepath.Join(dir, "rebase-indexer")
	if err := os.WriteFile(bin, []byte("unsigned"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := testRunner(t, []string{pubText(t, pub)}, false)

	if r.permitted([]string{bin}) {
		t.Error("an unsigned binary must be blocked")
	}
}

func TestSignedBinary_StrictModeIgnoresSignature(t *testing.T) {
	pub, priv, _ := minisign.GenerateKey(rand.Reader)
	bin := writeSignedBinary(t, priv, []byte("indexer"))
	r := testRunner(t, []string{pubText(t, pub)}, true) // strict = true

	if r.permitted([]string{bin}) {
		t.Error("strict mode must ignore signatures and fall back to the allowlist")
	}
}

func TestSignedBinary_NoSignersConfigured(t *testing.T) {
	_, priv, _ := minisign.GenerateKey(rand.Reader)
	bin := writeSignedBinary(t, priv, []byte("indexer"))
	r := testRunner(t, nil, false) // no trusted signers

	if r.permitted([]string{bin}) {
		t.Error("with no trusted signers, a signed binary is not auto-trusted")
	}
}

func TestPermitted_AllowlistStillWorks(t *testing.T) {
	// A relative, allowlisted command never touches signature I/O and is permitted.
	r := testRunner(t, nil, false)
	if !r.permitted([]string{"git", "status"}) {
		t.Error("allowlisted commands must still be permitted")
	}
	if r.permitted([]string{"rm", "-rf", "/"}) {
		t.Error("non-allowlisted, unsigned commands must stay blocked")
	}
}

func TestParseTrustedSigners_AcceptsThePinnedReleaseKey(t *testing.T) {
	// The Crucible release signing key baked into pkg/config defaultConfig().
	// If this stops parsing, agents silently trust nothing — so guard it.
	const releaseKey = "RWQ8+JuRPTjMJNiOAp15pQ5QoMbm5UNuK4ynl05hvL1ePrTLsWsPlinx"
	log, _ := logging.New(logging.Options{Level: "error"})
	if keys := parseTrustedSigners([]string{releaseKey}, log); len(keys) != 1 {
		t.Fatalf("the pinned release public key must parse; got %d keys", len(keys))
	}
}

func TestParseTrustedSigners_SkipsJunkAndPrefix(t *testing.T) {
	pub, _, _ := minisign.GenerateKey(rand.Reader)
	log, _ := logging.New(logging.Options{Level: "error"})
	keys := parseTrustedSigners([]string{
		"minisign:" + pubText(t, pub), // prefixed — accepted
		"   ",                         // blank — skipped
		"not-a-key",                   // junk — skipped
	}, log)
	if len(keys) != 1 {
		t.Fatalf("expected 1 valid key, got %d", len(keys))
	}
}
