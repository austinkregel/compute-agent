package app

import (
	"context"
	"errors"
	"testing"

	"github.com/austinkregel/compute-agent/internal/kiosk"
	"github.com/austinkregel/compute-agent/pkg/capability"
)

func TestDockerCap_Probe(t *testing.T) {
	t.Run("disabled by config", func(t *testing.T) {
		info := dockerCap{enabled: false}.Probe(context.Background())
		if info.State != capability.StateUnavailable {
			t.Errorf("state = %q, want unavailable", info.State)
		}
	})

	t.Run("enabled but no client (daemon unreachable)", func(t *testing.T) {
		info := dockerCap{enabled: true, client: nil}.Probe(context.Background())
		if info.State != capability.StateUnavailable {
			t.Errorf("state = %q, want unavailable", info.State)
		}
		if info.Detail == "" {
			t.Error("expected a Detail explaining why docker is unavailable")
		}
	})
}

func TestBatteryCap_Name(t *testing.T) {
	var bc batteryCap
	if bc.Name() != "battery" {
		t.Error("unexpected capability name")
	}
	if !bc.Dynamic() {
		t.Error("battery capability should be re-probed each tick")
	}
	// Probe() itself is platform-dependent (build-tagged battery_*.go); just
	// verify it never panics and always returns a valid state.
	info := bc.Probe(context.Background())
	switch info.State {
	case capability.StateEnabled, capability.StateUnavailable:
	default:
		t.Errorf("unexpected state %q", info.State)
	}
}

func TestThermalCap_Name(t *testing.T) {
	var tc thermalCap
	if tc.Name() != "thermal" {
		t.Error("unexpected capability name")
	}
	info := tc.Probe(context.Background())
	switch info.State {
	case capability.StateEnabled, capability.StateUnavailable:
	default:
		t.Errorf("unexpected state %q", info.State)
	}
}

func TestKioskCap_Probe(t *testing.T) {
	t.Run("nil manager reports available or unavailable, never enabled", func(t *testing.T) {
		info := kioskCap{mgr: nil}.Probe(context.Background())
		if info.State == capability.StateEnabled {
			t.Error("kiosk should never report enabled with no manager running")
		}
	})

	if !kiosk.IsAvailable() {
		// This test binary is built without CGO/kiosk support (the repo's
		// standard `make test` / CGO_ENABLED=0 path), so kioskCap must report
		// unavailable regardless of manager state.
		info := kioskCap{mgr: nil}.Probe(context.Background())
		if info.State != capability.StateUnavailable {
			t.Errorf("state = %q, want unavailable when not compiled with kiosk support", info.State)
		}
	}
}

func TestDirectCap_Probe(t *testing.T) {
	t.Run("disabled by config", func(t *testing.T) {
		info := directCap{enabled: false}.Probe(context.Background())
		if info.State != capability.StateUnavailable {
			t.Errorf("state = %q, want unavailable", info.State)
		}
		if info.Detail != "disabled by config" {
			t.Errorf("detail = %q, want %q", info.Detail, "disabled by config")
		}
	})

	t.Run("enabled but failed to start surfaces the start error", func(t *testing.T) {
		info := directCap{enabled: true, server: nil, startErr: errors.New("boom")}.Probe(context.Background())
		if info.State != capability.StateUnavailable {
			t.Errorf("state = %q, want unavailable", info.State)
		}
		if info.Detail != "boom" {
			t.Errorf("detail = %q, want %q", info.Detail, "boom")
		}
	})

	t.Run("enabled but misconfigured with no error recorded", func(t *testing.T) {
		info := directCap{enabled: true, server: nil}.Probe(context.Background())
		if info.Detail != "misconfigured" {
			t.Errorf("detail = %q, want %q", info.Detail, "misconfigured")
		}
	})
}

func TestFileCap_Probe(t *testing.T) {
	var fc fileCap
	if fc.Name() != "file" {
		t.Errorf("name = %q, want %q", fc.Name(), "file")
	}
	if fc.Dynamic() {
		t.Error("file capability is static, should not be re-probed each tick")
	}
	info := fc.Probe(context.Background())
	if info.State != capability.StateEnabled {
		t.Errorf("state = %q, want enabled", info.State)
	}
	found := false
	for _, f := range info.Features {
		if f == "range" {
			found = true
		}
	}
	if !found {
		t.Errorf("features = %v, want to include %q", info.Features, "range")
	}
}
