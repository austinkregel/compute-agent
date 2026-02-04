//go:build linux

package telemetry

import (
	"fmt"
	"os"
	"path/filepath"
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

func TestGetBatteryInfo_ChromeOSBattery(t *testing.T) {
	tmpDir := t.TempDir()
	root := filepath.Join(tmpDir, "power_supply")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}

	// Create a Chrome OS EC battery device
	batteryDir := filepath.Join(root, "sbs-battery")
	if err := os.MkdirAll(batteryDir, 0755); err != nil {
		t.Fatalf("failed to create battery dir: %v", err)
	}
	// Chrome OS batteries often have type=Battery
	if err := os.WriteFile(filepath.Join(batteryDir, "type"), []byte("Battery\n"), 0644); err != nil {
		t.Fatalf("failed to write type file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(batteryDir, "capacity"), []byte("92\n"), 0644); err != nil {
		t.Fatalf("failed to write capacity file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(batteryDir, "status"), []byte("Charging\n"), 0644); err != nil {
		t.Fatalf("failed to write status file: %v", err)
	}

	// Also create an AC adapter that should be ignored
	acDir := filepath.Join(root, "sbs-charger")
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
	if info == nil {
		t.Fatal("expected battery info, got nil")
	}
	if len(info.Devices) != 1 {
		t.Fatalf("expected 1 battery device, got %d", len(info.Devices))
	}

	dev := info.Devices[0]
	if dev.ID != "sbs-battery" {
		t.Errorf("expected device ID sbs-battery, got %s", dev.ID)
	}
	if dev.Percent != 92.0 {
		t.Errorf("expected percent 92.0, got %.1f", dev.Percent)
	}
	if dev.Status != "charging" {
		t.Errorf("expected status charging, got %s", dev.Status)
	}
}

func TestGetBatteryInfo_SBSBatteryWithoutTypeFile(t *testing.T) {
	tmpDir := t.TempDir()
	root := filepath.Join(tmpDir, "power_supply")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}

	// Create an SBS battery device without a type file but with battery attributes
	batteryDir := filepath.Join(root, "sbs-20-000b")
	if err := os.MkdirAll(batteryDir, 0755); err != nil {
		t.Fatalf("failed to create battery dir: %v", err)
	}
	// No type file - should still be detected via capacity file presence
	if err := os.WriteFile(filepath.Join(batteryDir, "capacity"), []byte("78\n"), 0644); err != nil {
		t.Fatalf("failed to write capacity file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(batteryDir, "status"), []byte("Discharging\n"), 0644); err != nil {
		t.Fatalf("failed to write status file: %v", err)
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
		t.Fatal("expected battery info for SBS device, got nil")
	}
	if len(info.Devices) != 1 {
		t.Fatalf("expected 1 battery device, got %d", len(info.Devices))
	}

	dev := info.Devices[0]
	if dev.ID != "sbs-20-000b" {
		t.Errorf("expected device ID sbs-20-000b, got %s", dev.ID)
	}
	if dev.Percent != 78.0 {
		t.Errorf("expected percent 78.0, got %.1f", dev.Percent)
	}
}

func TestGetBatteryInfo_CrosECBattery(t *testing.T) {
	tmpDir := t.TempDir()
	root := filepath.Join(tmpDir, "power_supply")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}

	// Create a cros-ec-battery device (common on Chromebooks)
	batteryDir := filepath.Join(root, "cros-ec-battery")
	if err := os.MkdirAll(batteryDir, 0755); err != nil {
		t.Fatalf("failed to create battery dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(batteryDir, "type"), []byte("Battery\n"), 0644); err != nil {
		t.Fatalf("failed to write type file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(batteryDir, "capacity"), []byte("65\n"), 0644); err != nil {
		t.Fatalf("failed to write capacity file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(batteryDir, "status"), []byte("Not charging\n"), 0644); err != nil {
		t.Fatalf("failed to write status file: %v", err)
	}
	// Add charge-based values (common on Chrome OS)
	if err := os.WriteFile(filepath.Join(batteryDir, "charge_now"), []byte("3500000\n"), 0644); err != nil {
		t.Fatalf("failed to write charge_now: %v", err)
	}
	if err := os.WriteFile(filepath.Join(batteryDir, "charge_full"), []byte("5400000\n"), 0644); err != nil {
		t.Fatalf("failed to write charge_full: %v", err)
	}
	if err := os.WriteFile(filepath.Join(batteryDir, "voltage_now"), []byte("7600000\n"), 0644); err != nil {
		t.Fatalf("failed to write voltage_now: %v", err)
	}
	if err := os.WriteFile(filepath.Join(batteryDir, "cycle_count"), []byte("245\n"), 0644); err != nil {
		t.Fatalf("failed to write cycle_count: %v", err)
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
	if len(info.Devices) != 1 {
		t.Fatalf("expected 1 battery device, got %d", len(info.Devices))
	}

	dev := info.Devices[0]
	if dev.ID != "cros-ec-battery" {
		t.Errorf("expected device ID cros-ec-battery, got %s", dev.ID)
	}
	if dev.Percent != 65.0 {
		t.Errorf("expected percent 65.0, got %.1f", dev.Percent)
	}
	// "Not charging" should normalize to "charging"
	if dev.Status != "charging" {
		t.Errorf("expected status charging (from 'Not charging'), got %s", dev.Status)
	}
	if dev.CycleCount != 245 {
		t.Errorf("expected cycle count 245, got %d", dev.CycleCount)
	}
	// Check derived energy values from charge * voltage
	// 3.5 Ah * 7.6 V = 26.6 Wh
	expectedEnergyNow := 3.5 * 7.6
	if dev.EnergyNowWh < expectedEnergyNow-0.1 || dev.EnergyNowWh > expectedEnergyNow+0.1 {
		t.Errorf("expected EnergyNowWh ~%.1f, got %.3f", expectedEnergyNow, dev.EnergyNowWh)
	}
}

func TestGetBatteryInfo_CMBBattery(t *testing.T) {
	tmpDir := t.TempDir()
	root := filepath.Join(tmpDir, "power_supply")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}

	// Create a CMB (Common Battery) device - used by some Lenovo/Thinkpad laptops
	batteryDir := filepath.Join(root, "CMB0")
	if err := os.MkdirAll(batteryDir, 0755); err != nil {
		t.Fatalf("failed to create battery dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(batteryDir, "type"), []byte("Battery\n"), 0644); err != nil {
		t.Fatalf("failed to write type file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(batteryDir, "capacity"), []byte("88\n"), 0644); err != nil {
		t.Fatalf("failed to write capacity file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(batteryDir, "status"), []byte("Full\n"), 0644); err != nil {
		t.Fatalf("failed to write status file: %v", err)
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
	if len(info.Devices) != 1 {
		t.Fatalf("expected 1 battery device, got %d", len(info.Devices))
	}

	dev := info.Devices[0]
	if dev.ID != "CMB0" {
		t.Errorf("expected device ID CMB0, got %s", dev.ID)
	}
	if dev.Status != "full" {
		t.Errorf("expected status full, got %s", dev.Status)
	}
}

func TestIsBatteryDevice(t *testing.T) {
	// Create a temp dir for testing attribute-based detection
	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		devName  string
		typ      string
		setup    func(dir string) // optional setup for sysfs attributes
		expected bool
	}{
		{"standard BAT0", "BAT0", "Battery", nil, true},
		{"standard BAT1", "BAT1", "battery", nil, true},
		{"BAT with empty type", "BAT0", "", nil, true},
		{"BATT variant", "BATT", "Battery", nil, true},
		{"CMB0", "CMB0", "Battery", nil, true},
		{"CMB1", "CMB1", "", nil, true},
		{"sbs-battery", "sbs-battery", "Battery", nil, true},
		{"cros-ec-battery", "cros-ec-battery", "Battery", nil, true},
		{"cros_ec_battery", "cros_ec_battery", "", nil, true},
		{"cros-battery", "cros-battery", "", nil, true},
		{"generic battery name", "my-battery", "", nil, true},
		{"AC adapter", "ACAD", "Mains", nil, false},
		{"AC0", "AC0", "Mains", nil, false},
		{"USB charger", "usb-charger", "USB", nil, false},
		{"sbs-charger", "sbs-charger", "Mains", nil, false},
		{"random device", "hwmon0", "", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(tmpDir, tt.devName)
			os.MkdirAll(dir, 0755)
			if tt.setup != nil {
				tt.setup(dir)
			}
			result := isBatteryDevice(dir, tt.devName, tt.typ)
			if result != tt.expected {
				t.Errorf("isBatteryDevice(%q, %q) = %v, want %v", tt.devName, tt.typ, result, tt.expected)
			}
		})
	}
}

func TestGetBatteryInfo_SymlinkedDevice(t *testing.T) {
	tmpDir := t.TempDir()
	root := filepath.Join(tmpDir, "power_supply")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}

	// Create the actual battery device in a different location (simulating sysfs structure)
	actualDeviceDir := filepath.Join(tmpDir, "devices", "LNXSYSTM", "BAT1")
	if err := os.MkdirAll(actualDeviceDir, 0755); err != nil {
		t.Fatalf("failed to create actual device dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(actualDeviceDir, "type"), []byte("Battery\n"), 0644); err != nil {
		t.Fatalf("failed to write type file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(actualDeviceDir, "capacity"), []byte("86\n"), 0644); err != nil {
		t.Fatalf("failed to write capacity file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(actualDeviceDir, "status"), []byte("Discharging\n"), 0644); err != nil {
		t.Fatalf("failed to write status file: %v", err)
	}

	// Create a symlink in power_supply pointing to the actual device (like real sysfs)
	symlinkPath := filepath.Join(root, "BAT1")
	if err := os.Symlink(actualDeviceDir, symlinkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
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
		t.Fatal("expected battery info for symlinked device, got nil")
	}
	if len(info.Devices) != 1 {
		t.Fatalf("expected 1 battery device, got %d", len(info.Devices))
	}

	dev := info.Devices[0]
	if dev.ID != "BAT1" {
		t.Errorf("expected device ID BAT1, got %s", dev.ID)
	}
	if dev.Percent != 86.0 {
		t.Errorf("expected percent 86.0, got %.1f", dev.Percent)
	}
	if dev.Status != "discharging" {
		t.Errorf("expected status discharging, got %s", dev.Status)
	}
}

func TestIsBatteryDevice_AttributeBased(t *testing.T) {
	tmpDir := t.TempDir()

	// Test: SBS device without type but with capacity file
	sbsDir := filepath.Join(tmpDir, "sbs-20-000b")
	os.MkdirAll(sbsDir, 0755)
	os.WriteFile(filepath.Join(sbsDir, "capacity"), []byte("50\n"), 0644)

	if !isBatteryDevice(sbsDir, "sbs-20-000b", "") {
		t.Error("expected sbs-20-000b with capacity file to be detected as battery")
	}

	// Test: Unknown device with capacity+status files should be detected
	unknownDir := filepath.Join(tmpDir, "unknown-power-device")
	os.MkdirAll(unknownDir, 0755)
	os.WriteFile(filepath.Join(unknownDir, "capacity"), []byte("75\n"), 0644)
	os.WriteFile(filepath.Join(unknownDir, "status"), []byte("Discharging\n"), 0644)

	if !isBatteryDevice(unknownDir, "unknown-power-device", "") {
		t.Error("expected unknown device with capacity+status to be detected as battery")
	}

	// Test: AC-like device with capacity+status should NOT be detected
	acLikeDir := filepath.Join(tmpDir, "ac-power")
	os.MkdirAll(acLikeDir, 0755)
	os.WriteFile(filepath.Join(acLikeDir, "capacity"), []byte("100\n"), 0644)
	os.WriteFile(filepath.Join(acLikeDir, "status"), []byte("Full\n"), 0644)

	if isBatteryDevice(acLikeDir, "ac-power", "") {
		t.Error("expected ac-power device to NOT be detected as battery despite having capacity+status")
	}
}

// getBatteryInfoFromRoot is a test helper that allows us to test getBatteryInfoImpl
// with a custom root directory instead of the hardcoded /sys/class/power_supply.
// It uses the same isBatteryDevice and readBatteryDevice functions as the real implementation.
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
		name := ent.Name()
		dir := filepath.Join(root, name)

		// Use os.Stat to follow symlinks (like the real implementation)
		info, err := os.Stat(dir)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			continue
		}

		typ, _ := readTrimmed(filepath.Join(dir, "type"))

		if !isBatteryDevice(dir, name, typ) {
			continue
		}

		dev := readBatteryDevice(dir, name, typ)
		devices = append(devices, dev)
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
