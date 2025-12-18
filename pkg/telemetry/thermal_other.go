//go:build !linux

package telemetry

import "github.com/shirou/gopsutil/v3/host"

func readLinuxSysfsTemperatures() ([]host.TemperatureStat, error) {
	return nil, nil
}
