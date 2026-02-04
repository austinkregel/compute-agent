// Package kiosk provides the optional kiosk mode subsystem for the agent.
// The kiosk displays content in a fullscreen WebView, controlled remotely via
// the dashboard through signed commands.
package kiosk

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"
)

// ErrKioskNotRunning is returned when trying to set content on a stopped kiosk.
var ErrKioskNotRunning = errors.New("kiosk is not running")

// ErrInvalidContent is returned when the content fails validation.
var ErrInvalidContent = errors.New("invalid kiosk content")

// Content describes what the kiosk should display.
type Content struct {
	Kind  string `json:"kind"`            // "blank", "message", or "url"
	Title string `json:"title,omitempty"` // for "message" kind
	Text  string `json:"text,omitempty"`  // for "message" kind
	URL   string `json:"url,omitempty"`   // for "url" kind
}

// ValidateContent checks that the content is well-formed and safe.
func ValidateContent(c Content) error {
	switch c.Kind {
	case "blank":
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

// Manager controls the kiosk subsystem lifecycle.
type Manager interface {
	// Run starts the kiosk subsystem. It blocks until ctx is cancelled.
	Run(ctx context.Context) error

	// SetContent updates what the kiosk displays.
	SetContent(c Content) error

	// Status returns the current kiosk status.
	Status() Status
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
