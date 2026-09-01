//go:build !cgo || android

package kiosk

// This file also covers android: GOOS=android satisfies Go's "linux" build
// tag, so without the !android guards on the GTK implementations an Android
// build (which needs CGO for bionic's DNS resolver) would try to compile
// webview.go against the host's gtk/webkit headers. Phone-class agents have
// no use for the kiosk WebView anyway.

// webviewAvailable indicates whether WebView support is compiled in.
// When CGO is disabled — or on Android — WebView is not available.
const webviewAvailable = false

// launchWebView is a stub that returns an error when CGO is disabled.
func launchWebView(url string, fullscreen bool) error {
	return ErrWebViewUnavailable
}
