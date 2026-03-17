package kiosk

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLayoutStore_LoadDefaults(t *testing.T) {
	dir := t.TempDir()
	store := NewLayoutStore(dir)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	// Should have 3 built-in presets
	all := store.List()
	for _, name := range []string{"ultrawide", "wide", "classic"} {
		if _, ok := all[name]; !ok {
			t.Errorf("expected default layout %q", name)
		}
	}

	// File should be created
	if _, err := os.Stat(filepath.Join(dir, "kiosk-layouts.json")); err != nil {
		t.Errorf("expected kiosk-layouts.json to be created: %v", err)
	}
}

func TestLayoutStore_SaveAndGet(t *testing.T) {
	dir := t.TempDir()
	store := NewLayoutStore(dir)
	if err := store.Load(); err != nil {
		t.Fatal(err)
	}

	layout := PageLayout{
		Cols: 4, Rows: 2,
		Widgets: []WidgetPlacement{
			{Type: "stats-primary", Col: 1, Row: 1, W: 2, H: 1},
			{Type: "news", Col: 3, Row: 1, W: 2, H: 1},
		},
	}

	if err := store.Save("my-layout", layout); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	got, ok := store.Get("my-layout")
	if !ok {
		t.Fatal("Get() returned false")
	}
	if got.Cols != 4 || got.Rows != 2 {
		t.Errorf("got cols=%d rows=%d, want 4×2", got.Cols, got.Rows)
	}
	if len(got.Widgets) != 2 {
		t.Errorf("got %d widgets, want 2", len(got.Widgets))
	}
}

func TestLayoutStore_SavePersists(t *testing.T) {
	dir := t.TempDir()
	store := NewLayoutStore(dir)
	if err := store.Load(); err != nil {
		t.Fatal(err)
	}

	layout := PageLayout{
		Cols: 2, Rows: 2,
		Widgets: []WidgetPlacement{
			{Type: "crypto", Col: 1, Row: 1, W: 1, H: 1},
		},
	}
	if err := store.Save("custom-1", layout); err != nil {
		t.Fatal(err)
	}

	// Load a fresh store from the same dir
	store2 := NewLayoutStore(dir)
	if err := store2.Load(); err != nil {
		t.Fatal(err)
	}

	got, ok := store2.Get("custom-1")
	if !ok {
		t.Fatal("persisted layout not found after reload")
	}
	if len(got.Widgets) != 1 || got.Widgets[0].Type != "crypto" {
		t.Error("persisted layout data mismatch")
	}
}

func TestLayoutStore_DeleteBuiltinFails(t *testing.T) {
	dir := t.TempDir()
	store := NewLayoutStore(dir)
	_ = store.Load()

	if err := store.Delete("ultrawide"); err == nil {
		t.Error("expected error deleting built-in preset")
	}
}

func TestLayoutStore_DeleteCustom(t *testing.T) {
	dir := t.TempDir()
	store := NewLayoutStore(dir)
	_ = store.Load()

	layout := PageLayout{Cols: 2, Rows: 1, Widgets: []WidgetPlacement{{Type: "news", Col: 1, Row: 1, W: 1, H: 1}}}
	_ = store.Save("deleteme", layout)

	if err := store.Delete("deleteme"); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}
	if _, ok := store.Get("deleteme"); ok {
		t.Error("layout still exists after delete")
	}
}

func TestLayoutStore_ValidationErrors(t *testing.T) {
	dir := t.TempDir()
	store := NewLayoutStore(dir)
	_ = store.Load()

	tests := []struct {
		name   string
		layout PageLayout
		errMsg string
	}{
		{"cols too high", PageLayout{Cols: 11, Rows: 2}, "cols must be"},
		{"rows zero", PageLayout{Cols: 2, Rows: 0}, "rows must be"},
		{"widget exceeds cols", PageLayout{Cols: 3, Rows: 3, Widgets: []WidgetPlacement{{Type: "news", Col: 3, Row: 1, W: 2, H: 1}}}, "extends beyond"},
		{"widget exceeds rows", PageLayout{Cols: 3, Rows: 2, Widgets: []WidgetPlacement{{Type: "news", Col: 1, Row: 2, W: 1, H: 2}}}, "extends beyond"},
		{"unknown widget type", PageLayout{Cols: 3, Rows: 3, Widgets: []WidgetPlacement{{Type: "invalid", Col: 1, Row: 1, W: 1, H: 1}}}, "unknown type"},
		{"widget zero col", PageLayout{Cols: 3, Rows: 3, Widgets: []WidgetPlacement{{Type: "news", Col: 0, Row: 1, W: 1, H: 1}}}, "must be >= 1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.Save("test-invalid", tt.layout)
			if err == nil {
				t.Error("expected error")
				_ = store.Delete("test-invalid")
			}
		})
	}
}

func TestLayoutStore_InvalidName(t *testing.T) {
	dir := t.TempDir()
	store := NewLayoutStore(dir)
	_ = store.Load()

	err := store.Save("bad name!", PageLayout{Cols: 2, Rows: 2})
	if err == nil {
		t.Error("expected error for invalid name")
	}
}
