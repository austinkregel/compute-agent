package capability

import (
	"context"
	"testing"
)

type fakeCap struct {
	name    string
	dynamic bool
	info    Info
	panics  bool
	calls   int
}

func (f *fakeCap) Name() string  { return f.name }
func (f *fakeCap) Dynamic() bool { return f.dynamic }
func (f *fakeCap) Probe(ctx context.Context) Info {
	f.calls++
	if f.panics {
		panic("boom")
	}
	return f.info
}

func TestRegistry_ProbeAllPopulatesSnapshot(t *testing.T) {
	r := New()
	r.Register(&fakeCap{name: "docker", info: Info{State: StateEnabled}})
	r.Register(&fakeCap{name: "battery", info: Info{State: StateUnavailable, Detail: "no battery devices"}})

	r.ProbeAll(context.Background())

	snap := r.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("expected 2 capabilities in snapshot, got %d", len(snap))
	}
	if snap["docker"].State != StateEnabled {
		t.Errorf("expected docker StateEnabled, got %q", snap["docker"].State)
	}
	if snap["battery"].State != StateUnavailable {
		t.Errorf("expected battery StateUnavailable, got %q", snap["battery"].State)
	}
	if snap["docker"].LastProbe == "" {
		t.Error("expected LastProbe to be stamped")
	}
}

func TestRegistry_RefreshDynamicOnlyProbesDynamicCapabilities(t *testing.T) {
	r := New()
	dyn := &fakeCap{name: "docker", dynamic: true, info: Info{State: StateEnabled}}
	static := &fakeCap{name: "kiosk", dynamic: false, info: Info{State: StateAvailable}}
	r.Register(dyn)
	r.Register(static)

	r.ProbeAll(context.Background())
	if dyn.calls != 1 || static.calls != 1 {
		t.Fatalf("expected both probed once at startup, got dyn=%d static=%d", dyn.calls, static.calls)
	}

	r.RefreshDynamic(context.Background())
	if dyn.calls != 2 {
		t.Errorf("expected dynamic capability re-probed, calls=%d", dyn.calls)
	}
	if static.calls != 1 {
		t.Errorf("expected static capability NOT re-probed, calls=%d", static.calls)
	}
}

func TestRegistry_Has(t *testing.T) {
	r := New()
	r.Register(&fakeCap{name: "docker", info: Info{State: StateEnabled}})
	r.Register(&fakeCap{name: "kiosk", info: Info{State: StateAvailable}})
	r.ProbeAll(context.Background())

	if !r.Has("docker") {
		t.Error("expected Has(docker) true for StateEnabled")
	}
	if r.Has("kiosk") {
		t.Error("expected Has(kiosk) false for StateAvailable (not Enabled)")
	}
	if r.Has("telephony") {
		t.Error("expected Has(telephony) false for unregistered capability (fail-closed)")
	}
}

func TestRegistry_ProbePanicDegradesGracefully(t *testing.T) {
	r := New()
	r.Register(&fakeCap{name: "flaky", panics: true})

	r.ProbeAll(context.Background()) // must not panic

	info, ok := r.Get("flaky")
	if !ok {
		t.Fatal("expected an entry for flaky despite panic")
	}
	if info.State != StateUnavailable {
		t.Errorf("expected StateUnavailable after panic, got %q", info.State)
	}
}

func TestRegistry_NilSafety(t *testing.T) {
	var r *Registry
	r.Register(&fakeCap{name: "x"})
	r.ProbeAll(context.Background())
	r.RefreshDynamic(context.Background())
	if r.Snapshot() != nil {
		t.Error("expected nil snapshot from nil registry")
	}
	if r.Has("x") {
		t.Error("expected Has false from nil registry")
	}
}
