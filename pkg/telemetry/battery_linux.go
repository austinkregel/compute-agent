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

// batteryDebugLog is a debug logger function for battery discovery. Set to non-nil to enable debug logging.
// The function takes a formatted message string (already formatted with fmt.Sprintf).
var batteryDebugLog func(msg string)

// batterySupported is true on platforms with a real battery telemetry
// implementation (as opposed to battery_other.go's always-nil stub). Backs
// BatterySupported(), which the batteryCap capability adapter uses to
// distinguish "unsupported platform" from "supported but no battery present".
const batterySupported = true

// isBatteryDevice checks if a power_supply device is a battery based on type file and device name.
// This supports various Linux battery drivers including:
// - Standard ACPI batteries (BAT0, BAT1, etc.)
// - Chrome OS EC batteries (cros-ec-battery, sbs-battery, etc.)
// - Smart Battery System devices (sbs-*)
// - Generic battery devices with "battery" in the name
func isBatteryDevice(dir, name, typ string) bool {
	typLower := strings.ToLower(typ)
	nameLower := strings.ToLower(name)
	nameUpper := strings.ToUpper(name)

	// Primary check: type file says "battery"
	if typLower == "battery" {
		return true
	}

	// Fallback checks for when type file is missing, empty, or has unusual values
	// Check device name patterns used by various battery drivers:

	// Standard ACPI battery naming: BAT0, BAT1, BATC, BATT, etc.
	if strings.HasPrefix(nameUpper, "BAT") {
		return true
	}

	// Chrome OS EC battery driver
	if strings.HasPrefix(nameLower, "cros") && strings.Contains(nameLower, "battery") {
		return true
	}
	if nameLower == "cros-ec-battery" || nameLower == "cros_ec_battery" {
		return true
	}

	// Smart Battery System (SBS) batteries - common on Chromebooks and some laptops
	if strings.HasPrefix(nameLower, "sbs") {
		// sbs-battery, sbs-charger, etc. - only match battery variants
		if strings.Contains(nameLower, "battery") || strings.Contains(nameLower, "bat") {
			return true
		}
		// sbs-* without "charger" or "mains" is likely a battery
		if !strings.Contains(nameLower, "charger") && !strings.Contains(nameLower, "mains") && !strings.Contains(nameLower, "ac") {
			// Check if it has battery-like attributes (capacity file exists)
			if _, err := os.Stat(filepath.Join(dir, "capacity")); err == nil {
				return true
			}
		}
	}

	// Generic battery naming
	if strings.Contains(nameLower, "battery") {
		return true
	}

	// Some systems use BATT, CMB0, CMB1 (common battery), etc.
	if strings.HasPrefix(nameUpper, "CMB") {
		return true
	}

	// Check if type is empty but device has battery-like sysfs attributes
	if typ == "" {
		// If capacity file exists and status file exists, likely a battery
		hasCapacity := false
		hasStatus := false
		if _, err := os.Stat(filepath.Join(dir, "capacity")); err == nil {
			hasCapacity = true
		}
		if _, err := os.Stat(filepath.Join(dir, "status")); err == nil {
			hasStatus = true
		}
		if hasCapacity && hasStatus {
			// Final check: make sure it's not an AC adapter or USB power
			if !strings.Contains(nameLower, "ac") && !strings.Contains(nameLower, "usb") &&
				!strings.Contains(nameLower, "mains") && !strings.Contains(nameLower, "charger") {
				return true
			}
		}
	}

	return false
}

// readBatteryDevice reads battery information from a sysfs power_supply directory.
func readBatteryDevice(dir, name, typ string) BatteryDevice {
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

	// Debug log discovered battery device
	if batteryDebugLog != nil {
		msg := fmt.Sprintf("battery discovered: id=%s type=%s percent=%.1f status=%s energyNowWh=%.3f energyFullWh=%.3f powerNowW=%.3f voltageNowV=%.3f tempC=%.1f cycleCount=%d",
			dev.ID, typ, dev.Percent, dev.Status, dev.EnergyNowWh, dev.EnergyFullWh, dev.PowerNowW, dev.VoltageNowV, dev.TempC, dev.CycleCount)
		batteryDebugLog(msg)
	}

	return dev
}

func getBatteryInfoImpl() (*BatteryInfo, error) {
	const root = "/sys/class/power_supply"
	ents, err := os.ReadDir(root)
	if err != nil {
		// If sysfs is missing (containers, unusual environments), treat as "no battery".
		if errors.Is(err, os.ErrNotExist) {
			if batteryDebugLog != nil {
				batteryDebugLog("battery: /sys/class/power_supply does not exist")
			}
			return nil, nil
		}
		return nil, err
	}

	if batteryDebugLog != nil {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		batteryDebugLog(fmt.Sprintf("battery: scanning %d power_supply devices: %v", len(ents), names))
	}

	var devices []BatteryDevice
	for _, ent := range ents {
		name := ent.Name()
		dir := filepath.Join(root, name)

		// Check if entry is a directory or a symlink pointing to a directory.
		// In /sys/class/power_supply/, entries are typically symlinks to device directories.
		info, err := os.Stat(dir) // Stat follows symlinks, unlike Lstat
		if err != nil {
			if batteryDebugLog != nil {
				batteryDebugLog(fmt.Sprintf("battery: cannot stat %s: %v", name, err))
			}
			continue
		}
		if !info.IsDir() {
			continue
		}

		typ, _ := readTrimmed(filepath.Join(dir, "type"))

		if !isBatteryDevice(dir, name, typ) {
			if batteryDebugLog != nil {
				batteryDebugLog(fmt.Sprintf("battery: skipping non-battery device: %s (type=%q)", name, typ))
			}
			continue
		}

		dev := readBatteryDevice(dir, name, typ)
		devices = append(devices, dev)
	}

	if len(devices) == 0 {
		if batteryDebugLog != nil {
			batteryDebugLog("battery: no battery devices found")
		}
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
