package version

import "testing"

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
