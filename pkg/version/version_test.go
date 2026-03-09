package version

import "testing"

func TestIsNewer(t *testing.T) {
	tests := []struct {
		name    string
		latest  string
		current string
		want    bool
	}{
		{name: "newer_patch", latest: "v0.0.30", current: "v0.0.29", want: true},
		{name: "older_patch", latest: "v0.0.29", current: "v0.0.30", want: false},
		{name: "same_version", latest: "v0.0.30", current: "v0.0.30", want: false},
		{name: "newer_minor", latest: "v0.1.0", current: "v0.0.99", want: true},
		{name: "newer_major", latest: "v1.0.0", current: "v0.99.99", want: true},
		{name: "mixed_v_prefix", latest: "v0.0.31", current: "0.0.30", want: true},
		{name: "no_v_prefix", latest: "0.0.31", current: "0.0.30", want: true},
		{name: "prerelease_stripped", latest: "0.0.31", current: "0.0.31-dev", want: false},
		{name: "garbage_latest", latest: "abc", current: "0.0.1", want: false},
		{name: "garbage_current", latest: "0.0.1", current: "abc", want: false},
		{name: "two_part_version", latest: "0.1", current: "0.0.1", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNewer(tt.latest, tt.current); got != tt.want {
				t.Fatalf("IsNewer(%q, %q) = %v, want %v", tt.latest, tt.current, got, tt.want)
			}
		})
	}
}

func TestShort(t *testing.T) {
	origVersion := Version
	origCommit := Commit
	origBuildDate := BuildDate
	t.Cleanup(func() {
		Version = origVersion
		Commit = origCommit
		BuildDate = origBuildDate
	})

	tests := []struct {
		name    string
		version string
		commit  string
		want    string
	}{
		{name: "unknown_commit_returns_version", version: "1.2.3", commit: "unknown", want: "1.2.3"},
		{name: "empty_commit_returns_version", version: "1.2.3", commit: "", want: "1.2.3"},
		{name: "commit_included", version: "1.2.3", commit: "abc123", want: "1.2.3 (abc123)"},
		{name: "commit_whitespace_still_included", version: "1.2.3", commit: "   ", want: "1.2.3 (   )"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Version = tt.version
			Commit = tt.commit
			if got := Short(); got != tt.want {
				t.Fatalf("Short() = %q, want %q", got, tt.want)
			}
		})
	}
}
