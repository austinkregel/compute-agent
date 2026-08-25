package admin

import (
	"os"
	"path/filepath"
	"strings"

	"aead.dev/minisign"

	"github.com/austinkregel/compute-agent/pkg/logging"
)

// Signature-based command trust.
//
// A first-party tool we ship (e.g. the Crucible indexer) is trusted by its
// *signature*, not by the operator's command allowlist: if the binary at argv[0]
// carries a valid detached minisign signature (`<path>.minisig`) from one of the
// configured trusted keys, it runs even when the allowlist wouldn't permit it.
// The trust root is the pinned public key in config — nothing on the network can
// change it. This is deliberately additive: it only ever *widens* what runs, and
// a strict fleet can disable it (SignatureTrustStrict).

// sigCacheEntry memoizes a verification result for a file identity so a large
// binary isn't re-read and re-verified on every exec.
type sigCacheEntry struct {
	size  int64
	mtime int64
	ok    bool
}

// parseTrustedSigners decodes config public-key strings (base64, with an optional
// "minisign:" prefix) into keys, skipping — and logging — malformed entries.
func parseTrustedSigners(entries []string, log *logging.Logger) []minisign.PublicKey {
	var keys []minisign.PublicKey
	for _, entry := range entries {
		s := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(entry), "minisign:"))
		if s == "" {
			continue
		}
		var pk minisign.PublicKey
		if err := pk.UnmarshalText([]byte(s)); err != nil {
			log.Debug("invalid trusted signer public key; ignoring", "error", err)
			continue
		}
		keys = append(keys, pk)
	}
	return keys
}

// permitted reports whether a command may run: either the operator allowlist
// permits it, or it is a trusted, signed first-party binary.
func (r *Runner) permitted(tokens []string) bool {
	return r.isAllowed(tokens) || r.isSignedTrusted(tokens)
}

// isSignedTrusted reports whether argv[0] is an absolute path to an existing file
// carrying a valid `<path>.minisig` signature from one of the trusted keys.
// Results are memoized by (path, size, mtime); a changed file re-verifies.
func (r *Runner) isSignedTrusted(tokens []string) bool {
	if r.signatureStrict || len(r.trustedKeys) == 0 || len(tokens) == 0 {
		return false
	}
	path := tokens[0]
	// Only absolute paths to real files can be signed binaries — a bare command
	// name ("git") never triggers signature I/O, so normal commands stay cheap.
	if !filepath.IsAbs(path) {
		return false
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	size, mtime := info.Size(), info.ModTime().UnixNano()

	r.sigCacheMu.Lock()
	if e, ok := r.sigCache[path]; ok && e.size == size && e.mtime == mtime {
		r.sigCacheMu.Unlock()
		return e.ok
	}
	r.sigCacheMu.Unlock()

	ok := verifyMinisign(path, r.trustedKeys)

	r.sigCacheMu.Lock()
	if r.sigCache == nil {
		r.sigCache = make(map[string]sigCacheEntry)
	}
	r.sigCache[path] = sigCacheEntry{size: size, mtime: mtime, ok: ok}
	r.sigCacheMu.Unlock()
	return ok
}

// verifyMinisign returns true iff `<path>.minisig` is a valid signature over the
// bytes of `path` under any of the given keys.
func verifyMinisign(path string, keys []minisign.PublicKey) bool {
	sig, err := os.ReadFile(path + ".minisig")
	if err != nil {
		return false
	}
	bin, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, key := range keys {
		if minisign.Verify(key, bin, sig) {
			return true
		}
	}
	return false
}
