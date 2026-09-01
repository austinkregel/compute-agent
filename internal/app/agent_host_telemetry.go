package app

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/host"

	"github.com/austinkregel/compute-agent/pkg/logging"
	"github.com/austinkregel/compute-agent/pkg/telemetry"
	"github.com/austinkregel/compute-agent/pkg/telephony"
)

// companionHostProvider implements telemetry.HostProvider on top of the
// companion app's local IPC bridge.
//
// Only the android build of the telemetry package consults this (its sysfs
// collectors are excluded there); elsewhere it is registered but never called.
type companionHostProvider struct {
	mgr *telephony.Manager
	log *logging.Logger

	mu       sync.Mutex
	snapshot hostTelemetry
	fetched  time.Time
}

// hostTelemetry mirrors the JSON the companion app returns for
// "host.telemetry". The field shapes match telemetry.BatteryInfo and
// gopsutil's host.TemperatureStat exactly, so the app's payload decodes
// straight into the types the stats pipeline already uses.
type hostTelemetry struct {
	Battery      *telemetry.BatteryInfo `json:"battery"`
	Temperatures []host.TemperatureStat `json:"temperatures"`
}

// hostTelemetryTTL coalesces the battery and thermal reads that a single
// telemetry tick performs into one round trip to the companion.
const hostTelemetryTTL = 5 * time.Second

// hostTelemetryTimeout bounds a companion request; the collector is on the
// stats path and must not stall it if the app is wedged.
const hostTelemetryTimeout = 5 * time.Second

func newCompanionHostProvider(mgr *telephony.Manager, log *logging.Logger) *companionHostProvider {
	return &companionHostProvider{mgr: mgr, log: log}
}

func (p *companionHostProvider) BatteryInfo() (*telemetry.BatteryInfo, error) {
	snap, err := p.fetch()
	if err != nil {
		return nil, err
	}
	return snap.Battery, nil
}

func (p *companionHostProvider) Temperatures() ([]host.TemperatureStat, error) {
	snap, err := p.fetch()
	if err != nil {
		return nil, err
	}
	return snap.Temperatures, nil
}

func (p *companionHostProvider) fetch() (hostTelemetry, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if time.Since(p.fetched) < hostTelemetryTTL {
		return p.snapshot, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), hostTelemetryTimeout)
	defer cancel()

	raw, err := p.mgr.HostTelemetry(ctx)
	if err != nil {
		// Companion not connected is the common case (agent started first);
		// report no data rather than an error so the stats tick stays clean.
		p.log.Debug("companion host telemetry unavailable", "error", err)
		return hostTelemetry{}, nil
	}

	// Round-trip through JSON: the client hands back decoded values, and the
	// target types already carry the matching tags.
	encoded, err := json.Marshal(raw)
	if err != nil {
		return hostTelemetry{}, err
	}
	var snap hostTelemetry
	if err := json.Unmarshal(encoded, &snap); err != nil {
		p.log.Debug("malformed companion host telemetry", "error", err)
		return hostTelemetry{}, nil
	}

	p.snapshot = snap
	p.fetched = time.Now()
	return snap, nil
}
