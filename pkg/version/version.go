package version

// These vars are intended to be set at build time via:
//   go build -ldflags "-X 'github.com/austinkregel/compute-agent/pkg/version.Version=...'"
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



