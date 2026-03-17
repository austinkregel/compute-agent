//go:build cgo && windows

package kiosk

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
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

func winBrowserArgs(browserPath, url string, fullscreen bool) []string {
	isEdge := filepath.Base(browserPath) == "msedge.exe"
	if fullscreen {
		if isEdge {
			return []string{"--kiosk", "--edge-kiosk-type=fullscreen", url}
		}
		return []string{"--kiosk", url}
	}
	return []string{"--app=" + url}
}

// launchWebView opens a browser in kiosk mode pointing to the given URL.
// It re-launches the browser when navigateWebView signals a new URL.
func launchWebView(url string, fullscreen bool) error {
	var browserPath string

	if edgePath := findEdgePath(); edgePath != "" {
		browserPath = edgePath
	} else if chromePath := findChromePath(); chromePath != "" {
		browserPath = chromePath
	} else {
		return errors.New("kiosk mode requires Microsoft Edge or Google Chrome; neither was found")
	}

	var (
		procMu sync.Mutex
		proc   *os.Process
		navCh  = make(chan string, 1)
	)

	registerNavigate(func(newURL string) {
		// Replace any pending URL, then kill the current browser.
		select {
		case <-navCh:
		default:
		}
		navCh <- newURL

		procMu.Lock()
		if proc != nil {
			_ = proc.Kill()
		}
		procMu.Unlock()
	})
	defer registerNavigate(nil)

	currentURL := url
	for {
		args := winBrowserArgs(browserPath, currentURL, fullscreen)
		cmd := exec.Command(browserPath, args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

		if err := cmd.Start(); err != nil {
			return err
		}

		procMu.Lock()
		proc = cmd.Process
		procMu.Unlock()

		_ = cmd.Wait()

		select {
		case newURL := <-navCh:
			currentURL = newURL
			continue
		default:
			return nil
		}
	}
}
