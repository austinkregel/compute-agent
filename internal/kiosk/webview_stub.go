//go:build !cgo

package kiosk

// webviewAvailable indicates whether WebView support is compiled in.
// When CGO is disabled, WebView is not available.
const webviewAvailable = false

// launchWebView is a stub that returns an error when CGO is disabled.
func launchWebView(url string, fullscreen bool) error {
	return ErrWebViewUnavailable
}
