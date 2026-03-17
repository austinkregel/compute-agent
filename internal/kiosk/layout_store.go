package kiosk

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var builtinPresets = map[string]bool{
	"ultrawide": true,
	"wide":      true,
	"classic":   true,
}

// LayoutStore persists named kiosk page layouts to a JSON file.
type LayoutStore struct {
	mu      sync.RWMutex
	path    string
	layouts map[string]PageLayout
}

// NewLayoutStore creates a store backed by kiosk-layouts.json in dir.
func NewLayoutStore(dir string) *LayoutStore {
	return &LayoutStore{
		path:    filepath.Join(dir, "kiosk-layouts.json"),
		layouts: make(map[string]PageLayout),
	}
}

// Load reads layouts from disk, or initialises with defaults if the file is missing.
func (s *LayoutStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.layouts = defaultLayouts()
			return s.writeLocked()
		}
		return fmt.Errorf("read layout store: %w", err)
	}
	var loaded map[string]PageLayout
	if err := json.Unmarshal(data, &loaded); err != nil {
		return fmt.Errorf("parse layout store: %w", err)
	}
	s.layouts = loaded

	// Ensure built-in presets exist
	defs := defaultLayouts()
	for name, layout := range defs {
		if _, ok := s.layouts[name]; !ok {
			s.layouts[name] = layout
		}
	}
	return nil
}

// Get returns a named layout and whether it exists.
func (s *LayoutStore) Get(name string) (PageLayout, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	l, ok := s.layouts[name]
	return l, ok
}

// List returns a copy of all stored layouts.
func (s *LayoutStore) List() map[string]PageLayout {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]PageLayout, len(s.layouts))
	for k, v := range s.layouts {
		out[k] = v
	}
	return out
}

// Save validates and persists a layout under the given name.
func (s *LayoutStore) Save(name string, layout PageLayout) error {
	if !layoutNameRe.MatchString(name) {
		return errors.New("invalid layout name")
	}
	if layout.Cols < 1 || layout.Cols > 10 {
		return errors.New("cols must be 1-10")
	}
	if layout.Rows < 1 || layout.Rows > 10 {
		return errors.New("rows must be 1-10")
	}
	if len(layout.Widgets) > 20 {
		return errors.New("too many widgets (max 20)")
	}
	for i, w := range layout.Widgets {
		if !ValidWidgetTypes[w.Type] {
			return fmt.Errorf("widget %d: unknown type %s", i, w.Type)
		}
		if w.Col < 1 || w.Row < 1 || w.W < 1 || w.H < 1 {
			return fmt.Errorf("widget %d: col/row/w/h must be >= 1", i)
		}
		if w.Col+w.W-1 > layout.Cols {
			return fmt.Errorf("widget %d: extends beyond grid columns", i)
		}
		if w.Row+w.H-1 > layout.Rows {
			return fmt.Errorf("widget %d: extends beyond grid rows", i)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.layouts[name] = layout
	return s.writeLocked()
}

// Delete removes a layout. Built-in presets cannot be deleted.
func (s *LayoutStore) Delete(name string) error {
	if builtinPresets[name] {
		return errors.New("cannot delete built-in layout preset")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.layouts[name]; !ok {
		return errors.New("layout not found: " + name)
	}
	delete(s.layouts, name)
	return s.writeLocked()
}

// writeLocked atomically writes layouts to disk. Caller must hold s.mu.
func (s *LayoutStore) writeLocked() error {
	data, err := json.MarshalIndent(s.layouts, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal layouts: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write layout store: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename layout store: %w", err)
	}
	return nil
}

func defaultLayouts() map[string]PageLayout {
	return map[string]PageLayout{
		"ultrawide": {
			Cols: 5, Rows: 3,
			Widgets: []WidgetPlacement{
				{Type: "stats-primary", Col: 1, Row: 1, W: 1, H: 1},
				{Type: "weather-current", Col: 2, Row: 1, W: 1, H: 1},
				{Type: "clock-calendar", Col: 3, Row: 1, W: 1, H: 1},
				{Type: "iss-tracker", Col: 4, Row: 1, W: 1, H: 1},
				{Type: "crypto", Col: 5, Row: 1, W: 1, H: 1},
				{Type: "stats-secondary", Col: 1, Row: 2, W: 1, H: 1},
				{Type: "weather-forecast", Col: 2, Row: 2, W: 1, H: 1},
				{Type: "news", Col: 3, Row: 2, W: 1, H: 1},
				{Type: "astronomy", Col: 4, Row: 2, W: 1, H: 1},
				{Type: "world-clocks", Col: 5, Row: 2, W: 1, H: 1},
				{Type: "ambient-photo", Col: 1, Row: 3, W: 5, H: 1},
			},
		},
		"wide": {
			Cols: 3, Rows: 3,
			Widgets: []WidgetPlacement{
				{Type: "stats-primary", Col: 1, Row: 1, W: 1, H: 1},
				{Type: "clock-calendar", Col: 2, Row: 1, W: 1, H: 1},
				{Type: "weather-current", Col: 3, Row: 1, W: 1, H: 1},
				{Type: "news", Col: 1, Row: 2, W: 1, H: 1},
				{Type: "crypto", Col: 2, Row: 2, W: 1, H: 1},
				{Type: "world-clocks", Col: 3, Row: 2, W: 1, H: 1},
				{Type: "stats-secondary", Col: 1, Row: 3, W: 1, H: 1},
				{Type: "iss-tracker", Col: 2, Row: 3, W: 1, H: 1},
				{Type: "astronomy", Col: 3, Row: 3, W: 1, H: 1},
			},
		},
		"classic": {
			Cols: 2, Rows: 3,
			Widgets: []WidgetPlacement{
				{Type: "weather-current", Col: 1, Row: 1, W: 1, H: 1},
				{Type: "stats-primary", Col: 2, Row: 1, W: 1, H: 1},
				{Type: "news", Col: 1, Row: 2, W: 1, H: 1},
				{Type: "crypto", Col: 2, Row: 2, W: 1, H: 1},
				{Type: "world-clocks", Col: 1, Row: 3, W: 1, H: 1},
				{Type: "iss-tracker", Col: 2, Row: 3, W: 1, H: 1},
			},
		},
	}
}
