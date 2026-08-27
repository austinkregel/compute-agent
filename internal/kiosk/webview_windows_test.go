//go:build cgo && windows

package kiosk

import (
	"strings"
	"testing"
)

func TestWinBrowserArgs_FullscreenPinsPrimaryDisplay(t *testing.T) {
	cases := []struct {
		name        string
		browser     string
		fullscreen  bool
		wantContain []string
		wantAbsent  []string
	}{
		{
			name:        "edge fullscreen",
			browser:     `C:\Edge\msedge.exe`,
			fullscreen:  true,
			wantContain: []string{"--user-data-dir=C:\\profile", "--no-first-run", "--window-position=0,0", "--kiosk", "--edge-kiosk-type=fullscreen", "https://x/"},
		},
		{
			name:        "chrome fullscreen",
			browser:     `C:\Chrome\chrome.exe`,
			fullscreen:  true,
			wantContain: []string{"--window-position=0,0", "--kiosk", "https://x/"},
			wantAbsent:  []string{"--edge-kiosk-type=fullscreen"},
		},
		{
			name:        "windowed app mode",
			browser:     `C:\Chrome\chrome.exe`,
			fullscreen:  false,
			wantContain: []string{"--app=https://x/"},
			wantAbsent:  []string{"--window-position=0,0", "--kiosk"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := winBrowserArgs(tc.browser, "https://x/", `C:\profile`, tc.fullscreen)
			joined := strings.Join(args, " ")
			for _, want := range tc.wantContain {
				if !contains(args, want) {
					t.Errorf("args %v missing %q", args, want)
				}
			}
			for _, absent := range tc.wantAbsent {
				if contains(args, absent) {
					t.Errorf("args %v should not contain %q", args, absent)
				}
			}
			// The URL must be the final positional argument in fullscreen mode.
			if tc.fullscreen && args[len(args)-1] != "https://x/" {
				t.Errorf("expected url last, got %q (all: %s)", args[len(args)-1], joined)
			}
		})
	}
}

func contains(ss []string, target string) bool {
	for _, s := range ss {
		if s == target {
			return true
		}
	}
	return false
}
