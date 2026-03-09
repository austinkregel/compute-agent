//go:build cgo && windows

package kiosk

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// webviewAvailable indicates whether WebView support is compiled in.
// On Windows, we use Edge or Chrome in kiosk mode since WebView2 CGO bindings
// are complex.
const webviewAvailable = true

// findEdgePath locates Microsoft Edge executable on Windows.
func findEdgePath() string {
	// Standard Edge installation paths
	paths := []string{
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(os.Getenv("ProgramFiles"), "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Microsoft", "Edge", "Application", "msedge.exe"),
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// findChromePath locates Google Chrome executable on Windows.
func findChromePath() string {
	paths := []string{
		filepath.Join(os.Getenv("ProgramFiles"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "Application", "chrome.exe"),
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// launchWebView opens a browser in kiosk mode pointing to the given URL.
// This provides a chromeless fullscreen experience on Windows.
func launchWebView(url string, fullscreen bool) error {
	var browserPath string
	var args []string

	// Try Edge first
	if edgePath := findEdgePath(); edgePath != "" {
		browserPath = edgePath
		if fullscreen {
			args = []string{"--kiosk", "--edge-kiosk-type=fullscreen", url}
		} else {
			args = []string{"--app=" + url}
		}
	} else if chromePath := findChromePath(); chromePath != "" {
		// Fall back to Chrome
		browserPath = chromePath
		if fullscreen {
			args = []string{"--kiosk", url}
		} else {
			args = []string{"--app=" + url}
		}
	} else {
		return errors.New("kiosk mode requires Microsoft Edge or Google Chrome; neither was found")
	}

	cmd := exec.Command(browserPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	if err := cmd.Start(); err != nil {
		return err
	}

	return cmd.Wait()
}
