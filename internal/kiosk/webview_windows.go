//go:build cgo && windows

package kiosk

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"

	"golang.org/x/sys/windows"
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

// kioskUserDataDir returns a dedicated browser profile dir so the kiosk launch
// is independent of any browser the user already has open.
func kioskUserDataDir(browserPath string) string {
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		base = os.TempDir()
	}
	name := "chrome"
	if filepath.Base(browserPath) == "msedge.exe" {
		name = "edge"
	}
	return filepath.Join(base, "backup-agent", "kiosk-"+name)
}

func winBrowserArgs(browserPath, url, userDataDir string, fullscreen bool) []string {
	isEdge := filepath.Base(browserPath) == "msedge.exe"

	args := []string{
		"--user-data-dir=" + userDataDir,
		"--no-first-run",
		"--no-default-browser-check",
	}
	if fullscreen {
		// Position 0,0 is the primary display's origin, so --kiosk fullscreens there.
		args = append(args, "--window-position=0,0")
		if isEdge {
			args = append(args, "--kiosk", "--edge-kiosk-type=fullscreen")
		} else {
			args = append(args, "--kiosk")
		}
		return append(args, url)
	}
	return append(args, "--app="+url)
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

	userDataDir := kioskUserDataDir(browserPath)
	_ = os.MkdirAll(userDataDir, 0o755)

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
		args := winBrowserArgs(browserPath, currentURL, userDataDir, fullscreen)
		cmd := exec.Command(browserPath, args...)
		// CREATE_NO_WINDOW suppresses a console without hiding the browser window.
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}

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
