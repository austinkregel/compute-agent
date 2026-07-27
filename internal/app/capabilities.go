package app

import (
	"context"

	"github.com/austinkregel/compute-agent/internal/directserver"
	"github.com/austinkregel/compute-agent/internal/kiosk"
	"github.com/austinkregel/compute-agent/pkg/capability"
	"github.com/austinkregel/compute-agent/pkg/docker"
	"github.com/austinkregel/compute-agent/pkg/telemetry"
	"github.com/austinkregel/compute-agent/pkg/telephony"
)

// dockerCap adapts the existing config-flag + live-Ping Docker client
// (agent.New's cfg.Docker.Enabled block, pkg/docker.Client.Available) into the
// centralized capability registry. No new detection logic — just a wrapper
// around what the agent already computes for telemetry.
type dockerCap struct {
	enabled bool
	client  *docker.Client
}

func (dockerCap) Name() string  { return "docker" }
func (dockerCap) Dynamic() bool { return true }

func (d dockerCap) Probe(ctx context.Context) capability.Info {
	if !d.enabled {
		return capability.Info{State: capability.StateUnavailable, Detail: "disabled by config"}
	}
	if d.client == nil || !d.client.Available() {
		return capability.Info{State: capability.StateUnavailable, Detail: "daemon unreachable"}
	}

	meta := map[string]any{}
	if status := d.client.CollectStatus(ctx); status != nil {
		if status.Version != "" {
			meta["version"] = status.Version
		}
		if status.Swarm != nil {
			meta["swarmActive"] = status.Swarm.Active
		}
	}
	return capability.Info{State: capability.StateEnabled, Meta: meta}
}

// batteryCap adapts telemetry's build-tag-gated battery probe. Unlike
// dockerCap, there's no config flag — battery presence is purely a runtime
// fact, but batterySupported (see telemetry.BatterySupported) now lets it
// distinguish "unsupported platform" from "supported but no battery" instead
// of both collapsing to the same nil.
type batteryCap struct{}

func (batteryCap) Name() string  { return "battery" }
func (batteryCap) Dynamic() bool { return true } // hot-plug / charge-state changes

func (batteryCap) Probe(ctx context.Context) capability.Info {
	if !telemetry.BatterySupported() {
		return capability.Info{State: capability.StateUnavailable, Detail: "unsupported platform"}
	}
	bi, err := telemetry.CollectBattery()
	switch {
	case err != nil:
		return capability.Info{State: capability.StateUnavailable, Detail: err.Error()}
	case bi == nil || len(bi.Devices) == 0:
		return capability.Info{State: capability.StateUnavailable, Detail: "no battery devices"}
	default:
		return capability.Info{State: capability.StateEnabled, Meta: map[string]any{"devices": len(bi.Devices)}}
	}
}

// thermalCap adapts telemetry's cross-platform sensor probe. See
// telemetry.CollectThermalSample's doc comment for what it does and doesn't
// cover relative to the full telemetry tick.
type thermalCap struct{}

func (thermalCap) Name() string  { return "thermal" }
func (thermalCap) Dynamic() bool { return true }

func (thermalCap) Probe(ctx context.Context) capability.Info {
	sensors, err := telemetry.CollectThermalSample()
	switch {
	case len(sensors) > 0:
		return capability.Info{State: capability.StateEnabled, Meta: map[string]any{"sensors": len(sensors)}}
	case err != nil:
		return capability.Info{State: capability.StateUnavailable, Detail: err.Error()}
	default:
		return capability.Info{State: capability.StateUnavailable, Detail: "no thermal sensors detected"}
	}
}

// kioskCap wraps the existing compile-time (build-tag) kiosk availability
// constant plus its runtime running-state, reusing the same tri-state that
// emitVariantStatus already computes for the `variant_status` message: not
// compiled in -> unavailable; compiled in but not running -> available;
// actively running -> enabled.
type kioskCap struct {
	mgr kiosk.Manager // nil until agent.New starts the kiosk subsystem
}

func (kioskCap) Name() string  { return "kiosk" }
func (kioskCap) Dynamic() bool { return true } // running state can change at runtime

func (k kioskCap) Probe(ctx context.Context) capability.Info {
	if !kiosk.IsAvailable() {
		return capability.Info{State: capability.StateUnavailable, Detail: "not compiled with kiosk support"}
	}
	if k.mgr == nil || !k.mgr.Status().Running {
		return capability.Info{State: capability.StateAvailable, Detail: "kiosk mode not active"}
	}
	return capability.Info{State: capability.StateEnabled}
}

// directCap wraps the direct-mode (P2P) inbound listener: disabled by
// config -> unavailable; enabled but failed validation/startup ->
// unavailable with the error; running -> enabled, mirroring what's already
// advertised via stats.direct.
type directCap struct {
	enabled  bool
	server   *directserver.Server // nil if disabled or failed to start
	startErr error
}

func (directCap) Name() string  { return "direct" }
func (directCap) Dynamic() bool { return true }

func (d directCap) Probe(ctx context.Context) capability.Info {
	if !d.enabled {
		return capability.Info{State: capability.StateUnavailable, Detail: "disabled by config"}
	}
	if d.server == nil {
		detail := "misconfigured"
		if d.startErr != nil {
			detail = d.startErr.Error()
		}
		return capability.Info{State: capability.StateUnavailable, Detail: detail}
	}
	if _, err := d.server.Advert(); err != nil {
		return capability.Info{State: capability.StateUnavailable, Detail: err.Error()}
	}
	return capability.Info{State: capability.StateEnabled}
}

// telephonyCap wraps the telephony.Manager's connection state to the Android
// companion app. Only ever StateEnabled on a phone-class agent with the
// companion app installed, paired, and running — dispatch enforcement (see
// transport.commandCapability) relies on this to fail-closed refuse sms_*/
// call_* commands on every other agent.
type telephonyCap struct {
	enabled bool
	mgr     *telephony.Manager
}

func (telephonyCap) Name() string  { return "telephony" }
func (telephonyCap) Dynamic() bool { return true } // companion connection can drop/reconnect

func (t telephonyCap) Probe(ctx context.Context) capability.Info {
	if !t.enabled || t.mgr == nil {
		return capability.Info{State: capability.StateUnavailable, Detail: "disabled by config"}
	}
	if !t.mgr.Connected() {
		return capability.Info{State: capability.StateUnavailable, Detail: "companion app not connected"}
	}
	return capability.Info{State: capability.StateEnabled, Features: []string{"sms"}}
}
