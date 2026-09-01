package telemetry

import (
	"sync/atomic"

	"github.com/shirou/gopsutil/v3/host"
)

// HostProvider supplies telemetry that must come from the platform's own APIs
// rather than from sysfs.
//
// This exists for Android. A Go agent there runs inside an app's uid, which
// cannot read /sys/class/power_supply or /sys/class/thermal — those are
// privileged on a stock device, and no amount of retrying the "classic Linux
// way" changes that. The companion app can read the same facts through
// BatteryManager and PowerManager (no runtime permission required) and hand
// them over the local IPC bridge, so the data is collected the way Android
// intends rather than lost.
//
// Only the android build consults this (see battery_android.go and
// thermal_android.go); on every other platform the sysfs implementations are
// used and a registered provider is simply never called.
type HostProvider interface {
	// BatteryInfo returns battery state, or nil when unavailable.
	BatteryInfo() (*BatteryInfo, error)
	// Temperatures returns thermal sensors, or nil when unavailable.
	Temperatures() ([]host.TemperatureStat, error)
}

var hostProvider atomic.Value // of HostProvider

// SetHostProvider registers the platform telemetry source. Safe to call from
// any goroutine; a nil provider clears it.
func SetHostProvider(p HostProvider) {
	if p == nil {
		hostProvider.Store((HostProvider)(nil))
		return
	}
	hostProvider.Store(p)
}

// currentHostProvider returns the registered provider, or nil.
func currentHostProvider() HostProvider {
	v, _ := hostProvider.Load().(HostProvider)
	return v
}
