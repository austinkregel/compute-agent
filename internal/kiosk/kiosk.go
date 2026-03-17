// Package kiosk provides the optional kiosk mode subsystem for the agent.
// The kiosk displays content in a fullscreen WebView, controlled remotely via
// the dashboard through signed commands.
package kiosk

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrKioskNotRunning is returned when trying to set content on a stopped kiosk.
var ErrKioskNotRunning = errors.New("kiosk is not running")

// ErrInvalidContent is returned when the content fails validation.
var ErrInvalidContent = errors.New("invalid kiosk content")

// ErrWebViewUnavailable is returned when kiosk mode is enabled but WebView
// support is not available (binary compiled without CGO).
var ErrWebViewUnavailable = errors.New("kiosk mode requires CGO; rebuild with CGO_ENABLED=1")

// ErrWebViewFailed is returned when the WebView fails to initialize.
var ErrWebViewFailed = errors.New("failed to create webview")

// navigateMu guards navigateFn, which is set by platform-specific webview code
// once the window is initialized and cleared when the webview exits.
var (
	navigateMu sync.Mutex
	navigateFn func(string)
)

// registerNavigate stores (or clears) the function used to navigate the
// WebView to an arbitrary URL at runtime. Platform init code calls this
// after creating the window and before entering the event loop.
func registerNavigate(fn func(string)) {
	navigateMu.Lock()
	navigateFn = fn
	navigateMu.Unlock()
}

// navigateWebView navigates the running WebView to the given URL.
// Safe to call from any goroutine. No-op if the WebView is not yet ready.
func navigateWebView(url string) {
	navigateMu.Lock()
	fn := navigateFn
	navigateMu.Unlock()
	if fn != nil {
		fn(url)
	}
}

// ValidWidgetTypes lists all recognised widget type IDs.
var ValidWidgetTypes = map[string]bool{
	"stats-primary":    true,
	"stats-secondary":  true,
	"weather-current":  true,
	"weather-forecast": true,
	"clock-calendar":   true,
	"news":             true,
	"crypto":           true,
	"iss-tracker":      true,
	"astronomy":        true,
	"world-clocks":     true,
	"ambient-photo":    true,
}

var layoutNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

// WidgetPlacement defines a widget's position and span within a grid layout.
type WidgetPlacement struct {
	Type   string         `json:"type"`
	Col    int            `json:"col"`
	Row    int            `json:"row"`
	W      int            `json:"w"`
	H      int            `json:"h"`
	Config map[string]any `json:"config,omitempty"`
}

// Content describes what the kiosk should display.
type Content struct {
	Kind    string            `json:"kind"`              // "blank", "message", "url", "dashboard", or "page"
	Title   string            `json:"title,omitempty"`   // for "message" kind
	Text    string            `json:"text,omitempty"`    // for "message" kind
	URL     string            `json:"url,omitempty"`     // for "url" kind
	Layout  string            `json:"layout,omitempty"`  // for "page" kind
	Widgets []WidgetPlacement `json:"widgets,omitempty"` // for "page" kind
	Units   string            `json:"units,omitempty"`   // "imperial" or "metric" (default "imperial")
}

// ValidateContent checks that the content is well-formed and safe.
func ValidateContent(c Content) error {
	switch c.Kind {
	case "blank":
		return nil
	case "dashboard":
		return nil
	case "message":
		if len(c.Text) > 10000 {
			return errors.New("message text too long (max 10000 chars)")
		}
		if len(c.Title) > 500 {
			return errors.New("message title too long (max 500 chars)")
		}
		return nil
	case "url":
		if c.URL == "" {
			return errors.New("url kind requires a url field")
		}
		if len(c.URL) > 2048 {
			return errors.New("url too long (max 2048 chars)")
		}
		u, err := url.Parse(c.URL)
		if err != nil {
			return errors.New("invalid url")
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme != "http" && scheme != "https" {
			return errors.New("url must use http or https scheme")
		}
		return nil
	case "page":
		if c.Layout == "" {
			return errors.New("page kind requires a layout field")
		}
		if !layoutNameRe.MatchString(c.Layout) {
			return errors.New("layout name must be alphanumeric/hyphens/underscores, 1-64 chars")
		}
		if len(c.Widgets) > 20 {
			return errors.New("too many widgets (max 20)")
		}
		for i, w := range c.Widgets {
			if !ValidWidgetTypes[w.Type] {
				return errors.New("widget " + strconv.Itoa(i) + ": unknown type " + w.Type)
			}
			if w.Col < 1 || w.Row < 1 || w.W < 1 || w.H < 1 {
				return errors.New("widget " + strconv.Itoa(i) + ": col/row/w/h must be >= 1")
			}
		}
		return nil
	default:
		return errors.New("unknown content kind: " + c.Kind)
	}
}

// Status represents the current state of the kiosk subsystem.
type Status struct {
	Running   bool    `json:"running"`
	Connected bool    `json:"connected"`
	Content   Content `json:"content,omitempty"`
	LastError string  `json:"lastError,omitempty"`
	TS        string  `json:"ts"`
}

// StatusFunc is called whenever kiosk status changes.
type StatusFunc func(Status)

// Config holds kiosk configuration.
type Config struct {
	ListenAddr string
	Fullscreen bool
}

// PageLayout holds the grid dimensions and widget placements for a kiosk page layout.
type PageLayout struct {
	Cols    int               `json:"cols"`
	Rows    int               `json:"rows"`
	Widgets []WidgetPlacement `json:"widgets"`
	Units   string            `json:"units,omitempty"` // "imperial" or "metric"
}

// Manager controls the kiosk subsystem lifecycle.
type Manager interface {
	// Run starts the kiosk subsystem. It blocks until ctx is cancelled.
	Run(ctx context.Context) error

	// SetContent updates what the kiosk displays.
	SetContent(c Content) error

	// PushStats sends a telemetry stats snapshot to the kiosk page.
	// When the kiosk is in "dashboard" or "page" mode, the page renders this data.
	PushStats(data json.RawMessage)

	// Status returns the current kiosk status.
	Status() Status

	// SaveLayout persists a named layout and optionally pushes to kiosk if active.
	SaveLayout(name string, layout PageLayout) error

	// GetLayouts returns all saved layouts.
	GetLayouts() map[string]PageLayout
}

// NewStatus creates a status snapshot with current timestamp.
func NewStatus(running, connected bool, content Content, lastError string) Status {
	return Status{
		Running:   running,
		Connected: connected,
		Content:   content,
		LastError: lastError,
		TS:        time.Now().UTC().Format(time.RFC3339Nano),
	}
}

// IsAvailable returns true if this binary was compiled with kiosk support.
// Kiosk support requires CGO and platform-specific GUI libraries.
func IsAvailable() bool {
	return webviewAvailable
}
