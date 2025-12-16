//go:build !windows

package telemetry

import "github.com/shirou/gopsutil/v3/host"

// Stub for non-Windows builds; Windows implementation lives in thermal_windows.go.
func readWindowsOHMTemperatures(int) ([]host.TemperatureStat, error) {
	return nil, nil
}
