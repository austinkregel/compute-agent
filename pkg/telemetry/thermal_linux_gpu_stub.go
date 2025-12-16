//go:build !linux

package telemetry

import "github.com/shirou/gopsutil/v3/host"

// Stub for non-Linux builds.
func readLinuxGPUTemps() ([]host.TemperatureStat, error) {
	return nil, nil
}
