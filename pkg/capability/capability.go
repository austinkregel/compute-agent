// Package capability provides a centralized registry for agent host
// capabilities (Docker, battery, kiosk, direct-mode, telephony, etc.),
// replacing the ad hoc per-feature config-flag/build-tag gating that used to
// be reinvented for each subsystem.
package capability

import (
	"context"
	"sync"
	"time"
)

// State is the tri-state availability of a capability.
type State string

const (
	// StateUnavailable means the capability is not usable right now: not
	// compiled in, hardware absent, disabled by config, or a required
	// dependency is unreachable.
	StateUnavailable State = "unavailable"
	// StateAvailable means the dependency/hardware is present but not
	// currently active (e.g. a kiosk-capable binary that hasn't started
	// kiosk mode).
	StateAvailable State = "available"
	// StateEnabled means the capability is active and usable right now.
	StateEnabled State = "enabled"
)

// Info is the JSON-serializable snapshot of one capability's state, embedded
// in the agent's stats payload and mirrored server-side.
type Info struct {
	State     State          `json:"state"`
	Detail    string         `json:"detail,omitempty"`
	Features  []string       `json:"features,omitempty"`
	Meta      map[string]any `json:"meta,omitempty"`
	LastProbe string         `json:"lastProbe,omitempty"`
}

// Capability is implemented by each subsystem (docker, battery, kiosk, ...)
// that wants to participate in centralized discovery.
type Capability interface {
	// Name is the stable identifier used in the wire format and the
	// command-capability dispatch table (e.g. "docker", "telephony").
	Name() string
	// Probe inspects current host/subsystem state and returns a snapshot. It
	// must never panic and should degrade to StateUnavailable with a Detail
	// on any error rather than propagating, matching the rest of the agent's
	// "never crash on a missing feature" convention.
	Probe(ctx context.Context) Info
	// Dynamic reports whether this capability should be re-probed on every
	// telemetry tick (true — e.g. docker daemon reachability, battery
	// presence) or probed once at startup only (false — e.g.
	// compile-time/build-tag gated features that cannot change while the
	// process is running).
	Dynamic() bool
}

// Registry holds every registered Capability and caches the latest probe
// result for each. It does not run its own goroutine; callers drive probing
// (ProbeAll once at startup, RefreshDynamic on each telemetry tick).
type Registry struct {
	mu    sync.RWMutex
	caps  []Capability
	cache map[string]Info
}

// New creates an empty registry.
func New() *Registry {
	return &Registry{cache: make(map[string]Info)}
}

// Register adds a capability.
func (r *Registry) Register(c Capability) {
	if r == nil || c == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.caps = append(r.caps, c)
}

// ProbeAll probes every registered capability, regardless of Dynamic(). Call
// once at startup so the registry has an initial snapshot before the first
// telemetry tick.
func (r *Registry) ProbeAll(ctx context.Context) {
	r.probe(ctx, func(Capability) bool { return true })
}

// RefreshDynamic re-probes only capabilities that declared Dynamic() == true.
// Call on each telemetry tick.
func (r *Registry) RefreshDynamic(ctx context.Context) {
	r.probe(ctx, func(c Capability) bool { return c.Dynamic() })
}

func (r *Registry) probe(ctx context.Context, include func(Capability) bool) {
	if r == nil {
		return
	}
	r.mu.RLock()
	caps := make([]Capability, len(r.caps))
	copy(caps, r.caps)
	r.mu.RUnlock()

	now := time.Now().UTC().Format(time.RFC3339)
	for _, c := range caps {
		if !include(c) {
			continue
		}
		info := safeProbe(c, ctx)
		info.LastProbe = now

		r.mu.Lock()
		r.cache[c.Name()] = info
		r.mu.Unlock()
	}
}

// safeProbe recovers from a panicking Probe implementation so one broken
// capability can never take down the agent.
func safeProbe(c Capability, ctx context.Context) (info Info) {
	defer func() {
		if rec := recover(); rec != nil {
			info = Info{State: StateUnavailable, Detail: "probe panicked"}
		}
	}()
	return c.Probe(ctx)
}

// Snapshot returns a copy of the latest cached state for every registered
// capability, keyed by name.
func (r *Registry) Snapshot() map[string]Info {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]Info, len(r.cache))
	for k, v := range r.cache {
		out[k] = v
	}
	return out
}

// Get returns the cached state for a single capability.
func (r *Registry) Get(name string) (Info, bool) {
	if r == nil {
		return Info{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	info, ok := r.cache[name]
	return info, ok
}

// Has reports whether a capability is currently StateEnabled. This is the
// fail-closed check used to gate capability-scoped command dispatch: an
// unregistered or not-yet-probed capability returns false.
func (r *Registry) Has(name string) bool {
	info, ok := r.Get(name)
	return ok && info.State == StateEnabled
}
