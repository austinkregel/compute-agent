package version

import (
	"strconv"
	"strings"
)

// These vars are intended to be set at build time via:
//
//	go build -ldflags "-X 'github.com/austinkregel/compute-agent/pkg/version.Version=...'"
//
// Keep defaults useful for local builds.
var (
	Version   = "0.1.0-dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// Short returns a human-friendly version string.
func Short() string {
	if Commit == "" || Commit == "unknown" {
		return Version
	}
	return Version + " (" + Commit + ")"
}

// IsNewer reports whether latest is a strictly newer semver than current.
// Both may optionally carry a "v" prefix (e.g. "v0.0.30").
// Returns false if either string is unparseable.
func IsNewer(latest, current string) bool {
	lParts, lok := parseSemver(latest)
	cParts, cok := parseSemver(current)
	if !lok || !cok {
		return false
	}
	for i := 0; i < 3; i++ {
		if lParts[i] > cParts[i] {
			return true
		}
		if lParts[i] < cParts[i] {
			return false
		}
	}
	return false
}

func parseSemver(s string) ([3]int, bool) {
	s = strings.TrimPrefix(s, "v")
	// Strip pre-release suffix (e.g. "1.0.0-dev")
	if idx := strings.IndexByte(s, '-'); idx != -1 {
		s = s[:idx]
	}
	parts := strings.SplitN(s, ".", 3)
	if len(parts) != 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}
