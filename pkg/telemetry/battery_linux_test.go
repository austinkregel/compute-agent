//go:build linux

package telemetry

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestGetBatteryInfo_DetectsByType(t *testing.T) {
	tmpDir := t.TempDir()
	root := filepath.Join(tmpDir, "power_supply")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}

	// Create a battery device with type file
	batteryDir := filepath.Join(root, "BAT1")
	if err := os.MkdirAll(batteryDir, 0755); err != nil {
		t.Fatalf("failed to create battery dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(batteryDir, "type"), []byte("Battery\n"), 0644); err != nil {
		t.Fatalf("failed to write type file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(batteryDir, "capacity"), []byte("85\n"), 0644); err != nil {
		t.Fatalf("failed to write capacity file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(batteryDir, "status"), []byte("Discharging\n"), 0644); err != nil {
		t.Fatalf("failed to write status file: %v", err)
	}

	// Create a non-battery device (AC adapter)
	acDir := filepath.Join(root, "ACAD")
	if err := os.MkdirAll(acDir, 0755); err != nil {
		t.Fatalf("failed to create AC dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(acDir, "type"), []byte("Mains\n"), 0644); err != nil {
		t.Fatalf("failed to write AC type file: %v", err)
	}

	// Temporarily override the root path
	origGetBatteryInfo := getBatteryInfo
	defer func() { getBatteryInfo = origGetBatteryInfo }()

	// Create a testable version that uses our temp dir
	getBatteryInfo = func() (*BatteryInfo, error) {
		return getBatteryInfoFromRoot(root)
	}

	info, err := getBatteryInfo()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("expected battery info, got nil")
	}
	if len(info.Devices) != 1 {
		t.Fatalf("expected 1 battery device, got %d", len(info.Devices))
	}

	dev := info.Devices[0]
	if dev.ID != "BAT1" {
		t.Errorf("expected device ID BAT1, got %s", dev.ID)
	}
	if dev.Percent != 85.0 {
		t.Errorf("expected percent 85.0, got %.1f", dev.Percent)
	}
	if dev.Status != "discharging" {
		t.Errorf("expected status discharging, got %s", dev.Status)
	}
}

func TestGetBatteryInfo_DetectsByNameFallback(t *testing.T) {
	tmpDir := t.TempDir()
	root := filepath.Join(tmpDir, "power_supply")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}

	// Create a battery device without type file (empty type)
	batteryDir := filepath.Join(root, "BAT0")
	if err := os.MkdirAll(batteryDir, 0755); err != nil {
		t.Fatalf("failed to create battery dir: %v", err)
	}
	// No type file, or empty type file
	if err := os.WriteFile(filepath.Join(batteryDir, "type"), []byte("\n"), 0644); err != nil {
		t.Fatalf("failed to write type file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(batteryDir, "capacity"), []byte("50\n"), 0644); err != nil {
		t.Fatalf("failed to write capacity file: %v", err)
	}

	// Temporarily override
	origGetBatteryInfo := getBatteryInfo
	defer func() { getBatteryInfo = origGetBatteryInfo }()

	getBatteryInfo = func() (*BatteryInfo, error) {
		return getBatteryInfoFromRoot(root)
	}

	info, err := getBatteryInfo()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("expected battery info, got nil")
	}
	if len(info.Devices) != 1 {
		t.Fatalf("expected 1 battery device, got %d", len(info.Devices))
	}
	if info.Devices[0].ID != "BAT0" {
		t.Errorf("expected device ID BAT0, got %s", info.Devices[0].ID)
	}
}

func TestGetBatteryInfo_DetectsWithAllZeroValues(t *testing.T) {
	tmpDir := t.TempDir()
	root := filepath.Join(tmpDir, "power_supply")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}

	// Create a battery device with type but all values are 0 or missing
	batteryDir := filepath.Join(root, "BAT1")
	if err := os.MkdirAll(batteryDir, 0755); err != nil {
		t.Fatalf("failed to create battery dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(batteryDir, "type"), []byte("Battery\n"), 0644); err != nil {
		t.Fatalf("failed to write type file: %v", err)
	}
	// No capacity, status, energy, power, or temp files - all will be 0 or empty
	// This tests the fix where we now include batteries even with all-zero values

	origGetBatteryInfo := getBatteryInfo
	defer func() { getBatteryInfo = origGetBatteryInfo }()

	getBatteryInfo = func() (*BatteryInfo, error) {
		return getBatteryInfoFromRoot(root)
	}

	info, err := getBatteryInfo()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("expected battery info even with all-zero values, got nil")
	}
	if len(info.Devices) != 1 {
		t.Fatalf("expected 1 battery device, got %d", len(info.Devices))
	}

	dev := info.Devices[0]
	if dev.ID != "BAT1" {
		t.Errorf("expected device ID BAT1, got %s", dev.ID)
	}
	// All values should be 0 or empty, but device should still be included
	if dev.Percent != 0 {
		t.Errorf("expected percent 0, got %.1f", dev.Percent)
	}
	if dev.Status != "" {
		t.Errorf("expected empty status, got %s", dev.Status)
	}
}

func TestGetBatteryInfo_ReadsEnergyAndPower(t *testing.T) {
	tmpDir := t.TempDir()
	root := filepath.Join(tmpDir, "power_supply")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}

	batteryDir := filepath.Join(root, "BAT1")
	if err := os.MkdirAll(batteryDir, 0755); err != nil {
		t.Fatalf("failed to create battery dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(batteryDir, "type"), []byte("Battery\n"), 0644); err != nil {
		t.Fatalf("failed to write type file: %v", err)
	}
	// Energy in µWh (micro-watt-hours)
	if err := os.WriteFile(filepath.Join(batteryDir, "energy_now"), []byte("45000000\n"), 0644); err != nil {
		t.Fatalf("failed to write energy_now: %v", err)
	}
	if err := os.WriteFile(filepath.Join(batteryDir, "energy_full"), []byte("53000000\n"), 0644); err != nil {
		t.Fatalf("failed to write energy_full: %v", err)
	}
	// Power in µW (micro-watts)
	if err := os.WriteFile(filepath.Join(batteryDir, "power_now"), []byte("12345000\n"), 0644); err != nil {
		t.Fatalf("failed to write power_now: %v", err)
	}
	// Voltage in µV (micro-volts)
	if err := os.WriteFile(filepath.Join(batteryDir, "voltage_now"), []byte("12600000\n"), 0644); err != nil {
		t.Fatalf("failed to write voltage_now: %v", err)
	}

	origGetBatteryInfo := getBatteryInfo
	defer func() { getBatteryInfo = origGetBatteryInfo }()

	getBatteryInfo = func() (*BatteryInfo, error) {
		return getBatteryInfoFromRoot(root)
	}

	info, err := getBatteryInfo()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info == nil || len(info.Devices) == 0 {
		t.Fatal("expected battery device")
	}

	dev := info.Devices[0]
	// 45000000 µWh = 45.0 Wh
	if dev.EnergyNowWh != 45.0 {
		t.Errorf("expected EnergyNowWh 45.0, got %.3f", dev.EnergyNowWh)
	}
	// 53000000 µWh = 53.0 Wh
	if dev.EnergyFullWh != 53.0 {
		t.Errorf("expected EnergyFullWh 53.0, got %.3f", dev.EnergyFullWh)
	}
	// 12345000 µW = 12.345 W
	if dev.PowerNowW != 12.345 {
		t.Errorf("expected PowerNowW 12.345, got %.3f", dev.PowerNowW)
	}
	// 12600000 µV = 12.6 V
	if dev.VoltageNowV != 12.6 {
		t.Errorf("expected VoltageNowV 12.6, got %.3f", dev.VoltageNowV)
	}
}

func TestGetBatteryInfo_DebugLogging(t *testing.T) {
	tmpDir := t.TempDir()
	root := filepath.Join(tmpDir, "power_supply")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}

	batteryDir := filepath.Join(root, "BAT1")
	if err := os.MkdirAll(batteryDir, 0755); err != nil {
		t.Fatalf("failed to create battery dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(batteryDir, "type"), []byte("Battery\n"), 0644); err != nil {
		t.Fatalf("failed to write type file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(batteryDir, "capacity"), []byte("75\n"), 0644); err != nil {
		t.Fatalf("failed to write capacity file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(batteryDir, "status"), []byte("Charging\n"), 0644); err != nil {
		t.Fatalf("failed to write status file: %v", err)
	}

	var loggedMessages []string
	origDebugLog := batteryDebugLog
	defer func() { batteryDebugLog = origDebugLog }()

	batteryDebugLog = func(msg string) {
		loggedMessages = append(loggedMessages, msg)
	}

	origGetBatteryInfo := getBatteryInfo
	defer func() { getBatteryInfo = origGetBatteryInfo }()

	getBatteryInfo = func() (*BatteryInfo, error) {
		return getBatteryInfoFromRoot(root)
	}

	info, err := getBatteryInfo()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info == nil || len(info.Devices) == 0 {
		t.Fatal("expected battery device")
	}

	// Check that debug logging was called
	if len(loggedMessages) != 1 {
		t.Fatalf("expected 1 debug log message, got %d", len(loggedMessages))
	}

	msg := loggedMessages[0]
	if !strings.Contains(msg, "battery discovered") {
		t.Errorf("expected log message to contain 'battery discovered', got: %s", msg)
	}
	if !strings.Contains(msg, "id=BAT1") {
		t.Errorf("expected log message to contain 'id=BAT1', got: %s", msg)
	}
	if !strings.Contains(msg, "type=Battery") {
		t.Errorf("expected log message to contain 'type=Battery', got: %s", msg)
	}
	if !strings.Contains(msg, "percent=75.0") {
		t.Errorf("expected log message to contain 'percent=75.0', got: %s", msg)
	}
}

func TestGetBatteryInfo_NoBatteries(t *testing.T) {
	tmpDir := t.TempDir()
	root := filepath.Join(tmpDir, "power_supply")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}

	// Only create non-battery devices
	acDir := filepath.Join(root, "ACAD")
	if err := os.MkdirAll(acDir, 0755); err != nil {
		t.Fatalf("failed to create AC dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(acDir, "type"), []byte("Mains\n"), 0644); err != nil {
		t.Fatalf("failed to write AC type file: %v", err)
	}

	origGetBatteryInfo := getBatteryInfo
	defer func() { getBatteryInfo = origGetBatteryInfo }()

	getBatteryInfo = func() (*BatteryInfo, error) {
		return getBatteryInfoFromRoot(root)
	}

	info, err := getBatteryInfo()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info != nil {
		t.Errorf("expected nil when no batteries present, got %+v", info)
	}
}

func TestGetBatteryInfo_MultipleBatteries(t *testing.T) {
	tmpDir := t.TempDir()
	root := filepath.Join(tmpDir, "power_supply")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}

	// Create two battery devices
	for i, name := range []string{"BAT0", "BAT1"} {
		batteryDir := filepath.Join(root, name)
		if err := os.MkdirAll(batteryDir, 0755); err != nil {
			t.Fatalf("failed to create battery dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(batteryDir, "type"), []byte("Battery\n"), 0644); err != nil {
			t.Fatalf("failed to write type file: %v", err)
		}
		capacity := 50 + i*25 // BAT0=50%, BAT1=75%
		if err := os.WriteFile(filepath.Join(batteryDir, "capacity"), []byte(fmt.Sprintf("%d\n", capacity)), 0644); err != nil {
			t.Fatalf("failed to write capacity file: %v", err)
		}
	}

	origGetBatteryInfo := getBatteryInfo
	defer func() { getBatteryInfo = origGetBatteryInfo }()

	getBatteryInfo = func() (*BatteryInfo, error) {
		return getBatteryInfoFromRoot(root)
	}

	info, err := getBatteryInfo()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("expected battery info, got nil")
	}
	if len(info.Devices) != 2 {
		t.Fatalf("expected 2 battery devices, got %d", len(info.Devices))
	}

	// Check both devices are present
	ids := make(map[string]bool)
	for _, dev := range info.Devices {
		ids[dev.ID] = true
	}
	if !ids["BAT0"] || !ids["BAT1"] {
		t.Errorf("expected both BAT0 and BAT1, got IDs: %v", ids)
	}
}

// getBatteryInfoFromRoot is a test helper that allows us to test getBatteryInfoImpl
// with a custom root directory instead of the hardcoded /sys/class/power_supply
func getBatteryInfoFromRoot(root string) (*BatteryInfo, error) {
	ents, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
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
		typLower := strings.ToLower(typ)
		if typLower != "battery" {
			if typ == "" && (strings.HasPrefix(strings.ToUpper(name), "BAT") || strings.Contains(strings.ToLower(name), "battery")) {
				// Device name suggests it's a battery, proceed
			} else {
				continue
			}
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

		// Temperature
		if tempRaw, err := readInt64(filepath.Join(dir, "temp")); err == nil && tempRaw != 0 {
			dev.TempC = normalizeTempC(tempRaw)
		}

		// Cycle count
		if cycles, err := readInt64(filepath.Join(dir, "cycle_count")); err == nil && cycles > 0 {
			dev.CycleCount = cycles
		}

		// Time estimates
		estimateBatteryTimes(&dev)

		devices = append(devices, dev)

		// Debug log discovered battery device
		if batteryDebugLog != nil {
			msg := fmt.Sprintf("battery discovered: id=%s type=%s percent=%.1f status=%s energyNowWh=%.3f energyFullWh=%.3f powerNowW=%.3f voltageNowV=%.3f tempC=%.1f",
				dev.ID, typ, dev.Percent, dev.Status, dev.EnergyNowWh, dev.EnergyFullWh, dev.PowerNowW, dev.VoltageNowV, dev.TempC)
			batteryDebugLog(msg)
		}
	}

	if len(devices) == 0 {
		return nil, nil
	}
	return &BatteryInfo{Devices: devices}, nil
}

func TestNormalizeBatteryStatus(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Charging", "charging"},
		{"CHARGING", "charging"},
		{"Discharging", "discharging"},
		{"discharging", "discharging"},
		{"Full", "full"},
		{"FULL", "full"},
		{"Not charging", "charging"},
		{"Not Charging", "charging"},
		{"Unknown", "unknown"},
		{"", "unknown"},
		{"invalid", "unknown"},
		{"  Charging  ", "charging"}, // with whitespace
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeBatteryStatus(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeBatteryStatus(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNormalizeTempC(t *testing.T) {
	tests := []struct {
		input    int64
		expected float64
		desc     string
	}{
		{42000, 42.0, "millidegree (large value)"},
		{420, 42.0, "tenths of degree"},
		{42, 42.0, "degrees"},
		{25000, 25.0, "millidegree (25000)"},
		{350, 35.0, "tenths (350)"},
		{100, 100.0, "degrees (100)"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			result := normalizeTempC(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeTempC(%d) = %.1f, want %.1f", tt.input, result, tt.expected)
			}
		})
	}
}
