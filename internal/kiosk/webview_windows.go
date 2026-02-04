//go:build cgo && windows

package kiosk

import (
	"os/exec"
	"syscall"
)

// webviewAvailable indicates whether WebView support is compiled in.
// On Windows, we use a simpler approach with the default browser in kiosk mode
// since WebView2 CGO bindings are complex. For full WebView2 support,
// consider using a pure-Go wrapper like go-webview2.
const webviewAvailable = true

// launchWebView opens Microsoft Edge in kiosk mode pointing to the given URL.
// This provides a chromeless fullscreen experience on Windows.
func launchWebView(url string, fullscreen bool) error {
	// Try Microsoft Edge first (has built-in kiosk mode)
	args := []string{"--kiosk", "--edge-kiosk-type=fullscreen"}
	if !fullscreen {
		args = []string{"--app=" + url}
	} else {
		args = append(args, url)
	}
	
	cmd := exec.Command("msedge", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	
	if err := cmd.Start(); err != nil {
		// Fall back to Chrome
		args[0] = "--kiosk"
		cmd = exec.Command("chrome", append(args, url)...)
		if err := cmd.Start(); err != nil {
			// Fall back to default browser
			cmd = exec.Command("cmd", "/c", "start", url)
			return cmd.Start()
		}
	}
	
	// Wait for the browser to close
	return cmd.Wait()
}
