//go:build linux

package telemetry

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func getBatteryInfoImpl() (*BatteryInfo, error) {
	const root = "/sys/class/power_supply"
	ents, err := os.ReadDir(root)
	if err != nil {
		// If sysfs is missing (containers, unusual environments), treat as "no battery".
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	var devices []BatteryDevice
	for _, ent := range ents {
		if !ent.IsDir() {
			continue
		}
		name := ent.Name()
		dir := filepath.Join(root, name)

		typ, _ := readTrimmed(filepath.Join(dir, "type"))
		if strings.ToLower(typ) != "battery" {
			continue
		}

		dev := BatteryDevice{ID: name}

		// Capacity (percent)
		if capStr, err := readTrimmed(filepath.Join(dir, "capacity")); err == nil {
			if v, err := strconv.ParseFloat(capStr, 64); err == nil {
				if v < 0 {
					v = 0
				}
				if v > 100 {
					v = 100
				}
				dev.Percent = v
			}
		}

		// Status
		if st, err := readTrimmed(filepath.Join(dir, "status")); err == nil {
			dev.Status = normalizeBatteryStatus(st)
		}

		// Energy / charge (sysfs uses µWh/µAh)
		// Prefer energy_*; fall back to charge_* and derive Wh if voltage available.
		energyNowU, _ := readInt64(filepath.Join(dir, "energy_now"))
		energyFullU, _ := readInt64(filepath.Join(dir, "energy_full"))
		if energyNowU > 0 {
			dev.EnergyNowWh = float64(energyNowU) / 1e6
		}
		if energyFullU > 0 {
			dev.EnergyFullWh = float64(energyFullU) / 1e6
		}

		chargeNowU, _ := readInt64(filepath.Join(dir, "charge_now"))
		chargeFullU, _ := readInt64(filepath.Join(dir, "charge_full"))

		// Power / current (sysfs uses µW/µA)
		powerNowU, _ := readInt64(filepath.Join(dir, "power_now"))
		if powerNowU > 0 {
			dev.PowerNowW = float64(powerNowU) / 1e6
		}
		currentNowU, _ := readInt64(filepath.Join(dir, "current_now"))

		// Voltage (µV)
		voltageNowU, _ := readInt64(filepath.Join(dir, "voltage_now"))
		if voltageNowU > 0 {
			dev.VoltageNowV = float64(voltageNowU) / 1e6
		}

		// If power_now missing but we have current and voltage, estimate power.
		if dev.PowerNowW == 0 && currentNowU > 0 && dev.VoltageNowV > 0 {
			currentA := float64(currentNowU) / 1e6
			dev.PowerNowW = currentA * dev.VoltageNowV
		}

		// If energy_* missing but we have charge_* and voltage, derive Wh.
		if dev.EnergyNowWh == 0 && chargeNowU > 0 && dev.VoltageNowV > 0 {
			chargeAh := float64(chargeNowU) / 1e6
			dev.EnergyNowWh = chargeAh * dev.VoltageNowV
		}
		if dev.EnergyFullWh == 0 && chargeFullU > 0 && dev.VoltageNowV > 0 {
			chargeAh := float64(chargeFullU) / 1e6
			dev.EnergyFullWh = chargeAh * dev.VoltageNowV
		}

		// Temperature (varies; often tenths of °C, sometimes milli-°C). Best-effort normalize.
		if tempRaw, err := readInt64(filepath.Join(dir, "temp")); err == nil && tempRaw != 0 {
			dev.TempC = normalizeTempC(tempRaw)
		}

		// Cycle count
		if cycles, err := readInt64(filepath.Join(dir, "cycle_count")); err == nil && cycles > 0 {
			dev.CycleCount = cycles
		}

		// Time estimates (seconds)
		estimateBatteryTimes(&dev)

		// Only append if we got at least one meaningful signal.
		if dev.Percent != 0 || dev.Status != "" || dev.EnergyNowWh != 0 || dev.PowerNowW != 0 || dev.TempC != 0 {
			devices = append(devices, dev)
		}
	}

	if len(devices) == 0 {
		return nil, nil
	}
	return &BatteryInfo{Devices: devices}, nil
}

func readTrimmed(p string) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func readInt64(p string) (int64, error) {
	s, err := readTrimmed(p)
	if err != nil {
		return 0, err
	}
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	return v, nil
}

func normalizeBatteryStatus(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "charging":
		return "charging"
	case "discharging":
		return "discharging"
	case "full":
		return "full"
	case "not charging":
		// Often means AC present but not filling.
		return "charging"
	default:
		return "unknown"
	}
}

func normalizeTempC(raw int64) float64 {
	// Heuristic:
	// - If raw is very large, assume milli-°C (e.g., 42000).
	// - Else if raw looks like tenths of °C (e.g., 420), divide by 10.
	// - Else treat as °C.
	if raw >= 10000 {
		return float64(raw) / 1000.0
	}
	if raw >= 200 && raw <= 2000 {
		return float64(raw) / 10.0
	}
	return float64(raw)
}

func estimateBatteryTimes(dev *BatteryDevice) {
	if dev == nil {
		return
	}
	if dev.PowerNowW <= 0 || dev.EnergyNowWh <= 0 {
		return
	}

	status := dev.Status
	switch status {
	case "discharging":
		dev.TimeToEmptySec = int64(math.Round((dev.EnergyNowWh / dev.PowerNowW) * 3600))
	case "charging":
		if dev.EnergyFullWh > dev.EnergyNowWh && dev.EnergyFullWh > 0 {
			dev.TimeToFullSec = int64(math.Round(((dev.EnergyFullWh - dev.EnergyNowWh) / dev.PowerNowW) * 3600))
		}
	}

	// Avoid negative / absurd values from noisy sensors.
	if dev.TimeToEmptySec < 0 {
		dev.TimeToEmptySec = 0
	}
	if dev.TimeToFullSec < 0 {
		dev.TimeToFullSec = 0
	}
	// Cap to ~7 days to avoid nonsense from near-zero power readings.
	const capSec = 7 * 24 * 3600
	if dev.TimeToEmptySec > capSec {
		dev.TimeToEmptySec = 0
	}
	if dev.TimeToFullSec > capSec {
		dev.TimeToFullSec = 0
	}
}
