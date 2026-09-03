package kiosk

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/austinkregel/compute-agent/pkg/logging"
)

func testLogger(t *testing.T) *logging.Logger {
	t.Helper()
	log, err := logging.New(logging.Options{Level: "error"})
	if err != nil {
		t.Fatalf("logging.New() error: %v", err)
	}
	return log
}

func TestContentStore_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := NewContentStore(dir)

	if _, ok := store.Load(); ok {
		t.Fatal("Load() on an empty dir returned ok=true, want false")
	}

	want := Content{Kind: "page", Layout: "system", Units: "metric",
		Widgets: []WidgetPlacement{{Type: "cpu", Col: 1, Row: 1, W: 1, H: 1}}}
	if err := store.Save(want); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// A fresh store, as a restarted agent would build.
	got, ok := NewContentStore(dir).Load()
	if !ok {
		t.Fatal("Load() after Save() returned ok=false")
	}
	if got.Kind != want.Kind || got.Layout != want.Layout || got.Units != want.Units {
		t.Fatalf("Load() = %+v, want %+v", got, want)
	}
	if len(got.Widgets) != 1 || got.Widgets[0].Type != "cpu" {
		t.Fatalf("Load() widgets = %+v, want one cpu widget", got.Widgets)
	}
}

func TestContentStore_SaveUsesRestrictiveMode(t *testing.T) {
	dir := t.TempDir()
	store := NewContentStore(dir)
	if err := store.Save(Content{Kind: "dashboard"}); err != nil {
		t.Fatalf("Save() error: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "kiosk-content.json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %o, want 600", perm)
	}
}

func TestContentStore_LoadRejectsUnusableState(t *testing.T) {
	cases := map[string]string{
		"malformed json":  `{"kind":`,
		"unknown kind":    `{"kind":"hologram"}`,
		"retired widget":  `{"kind":"page","layout":"system","widgets":[{"type":"tamagotchi","col":1,"row":1,"w":1,"h":1}]}`,
		"url without url": `{"kind":"url"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "kiosk-content.json"), []byte(body), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			if c, ok := NewContentStore(dir).Load(); ok {
				t.Fatalf("Load() = %+v, ok=true; want ok=false so the caller falls back to its default", c)
			}
		})
	}
}

// A kiosk restart must resume whatever the operator last set from the
// dashboard. Before content was persisted, every restart silently dropped back
// to the built-in default.
func TestManager_SetContentSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	layouts := NewLayoutStore(dir)
	if err := layouts.Load(); err != nil {
		t.Fatalf("layout Load() error: %v", err)
	}

	m := &manager{
		log:          testLogger(t),
		content:      Content{Kind: "dashboard"},
		layoutStore:  layouts,
		contentStore: NewContentStore(dir),
	}
	if err := m.SetContent(Content{Kind: "page", Layout: "classic"}); err != nil {
		t.Fatalf("SetContent() error: %v", err)
	}

	restored, ok := NewContentStore(dir).Load()
	if !ok {
		t.Fatal("content was not persisted by SetContent()")
	}
	if restored.Kind != "page" || restored.Layout != "classic" {
		t.Fatalf("restored = {%s %s}, want {page classic}", restored.Kind, restored.Layout)
	}
	// SetContent resolves widgets from the layout store, so the restored view
	// is renderable without a second lookup.
	if len(restored.Widgets) == 0 {
		t.Fatal("restored content has no widgets; layout resolution was not persisted")
	}
}

// Editing the active layout must update the persisted copy too, otherwise a
// restart resurrects the pre-edit widget set.
func TestManager_SaveLayoutRepersistsActiveContent(t *testing.T) {
	dir := t.TempDir()
	layouts := NewLayoutStore(dir)
	if err := layouts.Load(); err != nil {
		t.Fatalf("layout Load() error: %v", err)
	}

	m := &manager{
		log:          testLogger(t),
		content:      Content{Kind: "page", Layout: "classic"},
		layoutStore:  layouts,
		contentStore: NewContentStore(dir),
	}
	edited := PageLayout{Cols: 1, Rows: 1, Units: "metric",
		Widgets: []WidgetPlacement{{Type: "memory", Col: 1, Row: 1, W: 1, H: 1}}}
	if err := m.SaveLayout("classic", edited); err != nil {
		t.Fatalf("SaveLayout() error: %v", err)
	}

	restored, ok := NewContentStore(dir).Load()
	if !ok {
		t.Fatal("SaveLayout() did not persist the active content")
	}
	if len(restored.Widgets) != 1 || restored.Widgets[0].Type != "memory" {
		t.Fatalf("restored widgets = %+v, want the edited memory widget", restored.Widgets)
	}
	if restored.Units != "metric" {
		t.Fatalf("restored units = %q, want metric", restored.Units)
	}
}

func TestDefaultContent(t *testing.T) {
	dir := t.TempDir()
	store := NewLayoutStore(dir)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	t.Run("cold start uses the system page", func(t *testing.T) {
		c := defaultContent(Config{}, store)
		if c.Kind != "page" || c.Layout != DefaultLayoutName {
			t.Fatalf("defaultContent() = {%s %s}, want {page %s}", c.Kind, c.Layout, DefaultLayoutName)
		}
		if len(c.Widgets) != 6 {
			t.Fatalf("widgets = %d, want the 6 of the 3x2 system grid", len(c.Widgets))
		}
	})

	t.Run("explicit kinds are honoured", func(t *testing.T) {
		if c := defaultContent(Config{DefaultKind: "dashboard"}, store); c.Kind != "dashboard" {
			t.Fatalf("kind = %q, want dashboard", c.Kind)
		}
		if c := defaultContent(Config{DefaultKind: "blank"}, store); c.Kind != "blank" {
			t.Fatalf("kind = %q, want blank", c.Kind)
		}
	})

	t.Run("named layout", func(t *testing.T) {
		c := defaultContent(Config{DefaultKind: "page", DefaultLayout: "wide"}, store)
		if c.Kind != "page" || c.Layout != "wide" {
			t.Fatalf("defaultContent() = {%s %s}, want {page wide}", c.Kind, c.Layout)
		}
	})

	t.Run("unknown layout falls back to the dashboard", func(t *testing.T) {
		c := defaultContent(Config{DefaultLayout: "nonexistent"}, store)
		if c.Kind != "dashboard" {
			t.Fatalf("kind = %q, want dashboard for a layout that is not in the store", c.Kind)
		}
	})
}

// The 3x2 host-telemetry grid is the shape an unconfigured kiosk shows, and the
// dashboard editor mirrors it (KioskView.vue PRESETS/loadDefaultLayout).
func TestDefaultLayouts_SystemPreset(t *testing.T) {
	layout, ok := defaultLayouts()[DefaultLayoutName]
	if !ok {
		t.Fatalf("no built-in %q layout", DefaultLayoutName)
	}
	if layout.Cols != 3 || layout.Rows != 2 {
		t.Fatalf("grid = %dx%d, want 3x2", layout.Cols, layout.Rows)
	}
	want := []string{"cpu", "memory", "battery", "disk", "network", "system-health"}
	if len(layout.Widgets) != len(want) {
		t.Fatalf("widgets = %d, want %d", len(layout.Widgets), len(want))
	}
	for i, typ := range want {
		if layout.Widgets[i].Type != typ {
			t.Errorf("widget %d = %q, want %q", i, layout.Widgets[i].Type, typ)
		}
		if !ValidWidgetTypes[typ] {
			t.Errorf("%q is not in ValidWidgetTypes, so the agent would reject its own default", typ)
		}
	}
}
