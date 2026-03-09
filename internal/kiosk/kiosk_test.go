package kiosk

import (
	"strings"
	"testing"
)

func TestValidateContent_Blank(t *testing.T) {
	c := Content{Kind: "blank"}
	if err := ValidateContent(c); err != nil {
		t.Errorf("blank content should be valid, got error: %v", err)
	}
}

func TestValidateContent_Dashboard(t *testing.T) {
	c := Content{Kind: "dashboard"}
	if err := ValidateContent(c); err != nil {
		t.Errorf("dashboard content should be valid, got error: %v", err)
	}
}

func TestValidateContent_Message(t *testing.T) {
	tests := []struct {
		name    string
		content Content
		wantErr bool
		errText string
	}{
		{
			name:    "valid message",
			content: Content{Kind: "message", Title: "Hello", Text: "World"},
			wantErr: false,
		},
		{
			name:    "message without title",
			content: Content{Kind: "message", Text: "World"},
			wantErr: false,
		},
		{
			name:    "message without text (empty)",
			content: Content{Kind: "message", Title: "Hello", Text: ""},
			wantErr: false,
		},
		{
			name:    "message with text too long",
			content: Content{Kind: "message", Text: strings.Repeat("a", 10001)},
			wantErr: true,
			errText: "text too long",
		},
		{
			name:    "message with title too long",
			content: Content{Kind: "message", Title: strings.Repeat("a", 501), Text: "ok"},
			wantErr: true,
			errText: "title too long",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateContent(tt.content)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errText != "" && !strings.Contains(err.Error(), tt.errText) {
					t.Errorf("expected error containing %q, got %q", tt.errText, err.Error())
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateContent_URL(t *testing.T) {
	tests := []struct {
		name    string
		content Content
		wantErr bool
		errText string
	}{
		{
			name:    "valid https url",
			content: Content{Kind: "url", URL: "https://example.com"},
			wantErr: false,
		},
		{
			name:    "valid http url",
			content: Content{Kind: "url", URL: "http://localhost:8080/page"},
			wantErr: false,
		},
		{
			name:    "missing url",
			content: Content{Kind: "url", URL: ""},
			wantErr: true,
			errText: "requires a url",
		},
		{
			name:    "file scheme rejected",
			content: Content{Kind: "url", URL: "file:///etc/passwd"},
			wantErr: true,
			errText: "http or https",
		},
		{
			name:    "javascript scheme rejected",
			content: Content{Kind: "url", URL: "javascript:alert(1)"},
			wantErr: true,
			errText: "http or https",
		},
		{
			name:    "url too long",
			content: Content{Kind: "url", URL: "https://example.com/" + strings.Repeat("a", 2048)},
			wantErr: true,
			errText: "too long",
		},
		{
			name:    "invalid url (no scheme)",
			content: Content{Kind: "url", URL: "not a url"},
			wantErr: true,
			errText: "http or https", // url.Parse succeeds but scheme check fails
		},
		{
			name:    "actually invalid url",
			content: Content{Kind: "url", URL: "://invalid"},
			wantErr: true,
			errText: "invalid url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateContent(tt.content)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errText != "" && !strings.Contains(err.Error(), tt.errText) {
					t.Errorf("expected error containing %q, got %q", tt.errText, err.Error())
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateContent_UnknownKind(t *testing.T) {
	c := Content{Kind: "unknown"}
	err := ValidateContent(c)
	if err == nil {
		t.Error("expected error for unknown kind")
	}
	if !strings.Contains(err.Error(), "unknown") {
		t.Errorf("expected error mentioning 'unknown', got %q", err.Error())
	}
}

func TestNewStatus(t *testing.T) {
	status := NewStatus(true, true, Content{Kind: "blank"}, "")

	if !status.Running {
		t.Error("expected Running to be true")
	}
	if !status.Connected {
		t.Error("expected Connected to be true")
	}
	if status.Content.Kind != "blank" {
		t.Errorf("expected Content.Kind to be 'blank', got %q", status.Content.Kind)
	}
	if status.TS == "" {
		t.Error("expected TS to be set")
	}
}

func TestNewStatus_WithError(t *testing.T) {
	status := NewStatus(false, false, Content{Kind: "blank"}, "test error")

	if status.Running {
		t.Error("expected Running to be false")
	}
	if status.LastError != "test error" {
		t.Errorf("expected LastError to be 'test error', got %q", status.LastError)
	}
}
