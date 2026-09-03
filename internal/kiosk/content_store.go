package kiosk

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// ContentStore persists the kiosk's active content so that a restart of the
// agent resumes whatever the operator last set, rather than reverting to the
// built-in default.
type ContentStore struct {
	mu   sync.Mutex
	path string
}

// NewContentStore creates a store backed by kiosk-content.json in dir.
func NewContentStore(dir string) *ContentStore {
	return &ContentStore{path: filepath.Join(dir, "kiosk-content.json")}
}

// Load returns the persisted content. A missing, unreadable, malformed or
// no-longer-valid file yields ok=false so the caller falls back to its
// configured default instead of failing to start.
func (s *ContentStore) Load() (Content, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		return Content{}, false
	}
	var c Content
	if err := json.Unmarshal(data, &c); err != nil {
		return Content{}, false
	}
	// Re-validate: the file is agent-local state, but it survives upgrades that
	// may have retired a content kind or widget type.
	if err := ValidateContent(c); err != nil {
		return Content{}, false
	}
	return c, true
}

// Save atomically writes the content to disk with restrictive permissions.
func (s *ContentStore) Save(c Content) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal kiosk content: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write kiosk content: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename kiosk content: %w", err)
	}
	return nil
}
