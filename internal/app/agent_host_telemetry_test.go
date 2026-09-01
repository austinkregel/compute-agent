package app

import (
	"encoding/json"
	"testing"
)

// The companion app builds this JSON by hand (HostTelemetry.kt), so the shape
// is a cross-plane contract with no shared schema to enforce it. This pins it:
// if either side's field names drift, the decode silently yields zero values
// and battery/thermal quietly vanish from the dashboard.
func TestHostTelemetryDecodesCompanionPayload(t *testing.T) {
	// Captured verbatim from a device response to op "host.telemetry".
	const payload = `{
	  "battery": {
	    "devices": [
	      {
	        "id": "battery",
	        "status": "charging",
	        "percent": 46,
	        "voltageNowV": 4.107,
	        "tempC": 25.1,
	        "energyNowWh": 7.647234,
	        "energyFullWh": 16.62442,
	        "powerNowW": 5.33268,
	        "cycleCount": 525
	      }
	    ]
	  },
	  "temperatures": [
	    { "sensorKey": "battery", "temperature": 25.1 }
	  ]
	}`

	var snap hostTelemetry
	if err := json.Unmarshal([]byte(payload), &snap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if snap.Battery == nil {
		t.Fatal("battery missing")
	}
	if got := len(snap.Battery.Devices); got != 1 {
		t.Fatalf("devices = %d, want 1", got)
	}
	dev := snap.Battery.Devices[0]
	if dev.ID != "battery" {
		t.Errorf("ID = %q, want %q", dev.ID, "battery")
	}
	if dev.Status != "charging" {
		t.Errorf("Status = %q, want %q", dev.Status, "charging")
	}
	if dev.Percent != 46 {
		t.Errorf("Percent = %v, want 46", dev.Percent)
	}
	if dev.VoltageNowV != 4.107 {
		t.Errorf("VoltageNowV = %v, want 4.107", dev.VoltageNowV)
	}
	if dev.TempC != 25.1 {
		t.Errorf("TempC = %v, want 25.1", dev.TempC)
	}
	if dev.CycleCount != 525 {
		t.Errorf("CycleCount = %v, want 525", dev.CycleCount)
	}
	if dev.PowerNowW == 0 || dev.EnergyNowWh == 0 || dev.EnergyFullWh == 0 {
		t.Errorf("energy/power fields not decoded: %+v", dev)
	}

	if len(snap.Temperatures) != 1 {
		t.Fatalf("temperatures = %d, want 1", len(snap.Temperatures))
	}
	if snap.Temperatures[0].SensorKey != "battery" {
		t.Errorf("SensorKey = %q, want %q", snap.Temperatures[0].SensorKey, "battery")
	}
	if snap.Temperatures[0].Temperature != 25.1 {
		t.Errorf("Temperature = %v, want 25.1", snap.Temperatures[0].Temperature)
	}
}

// An absent companion (or a companion that knows no battery) must decode to
// empty rather than erroring, since that is the steady state before the app
// connects.
func TestHostTelemetryDecodesEmptyPayload(t *testing.T) {
	var snap hostTelemetry
	if err := json.Unmarshal([]byte(`{"battery":{"devices":[]},"temperatures":[]}`), &snap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if snap.Battery == nil || len(snap.Battery.Devices) != 0 {
		t.Errorf("want empty devices, got %+v", snap.Battery)
	}
	if len(snap.Temperatures) != 0 {
		t.Errorf("want no temperatures, got %+v", snap.Temperatures)
	}
}
