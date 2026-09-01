//go:build android

package telemetry

import "github.com/shirou/gopsutil/v3/host"

// readLinuxSysfsTemperatures is the seam telemetry.go binds for thermal
// collection. On Android the name is a misnomer inherited from that wiring:
// there is no sysfs read here, because /sys/class/thermal is not readable
// from an app uid. The companion app supplies what the platform does expose.
//
// In practice that is the battery temperature. Android has no unprivileged
// API for the per-zone CPU/GPU sensors a Linux host reports —
// HardwarePropertiesManager requires a system permission — so the sensor set
// here is deliberately small rather than padded out with invented values.
func readLinuxSysfsTemperatures() ([]host.TemperatureStat, error) {
	p := currentHostProvider()
	if p == nil {
		return nil, nil
	}
	return p.Temperatures()
}
