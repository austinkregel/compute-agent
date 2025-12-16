//go:build linux

package telemetry

import (
	"context"
	"errors"
	"testing"
)

func TestParseNvidiaSmiCSV(t *testing.T) {
	body := `
45, NVIDIA A100-PCIE-40GB, GPU-1234
52, Tesla V100, GPU-5678
60, , 
`
	temps := parseNvidiaSmiCSV(body)
	if len(temps) != 3 {
		t.Fatalf("expected 3 temps, got %d", len(temps))
	}
	if temps[0].SensorKey == "" || temps[1].SensorKey == "" {
		t.Fatalf("expected sensor keys populated")
	}
	if temps[0].Temperature != 45 {
		t.Fatalf("expected first temp 45, got %v", temps[0].Temperature)
	}
	if temps[2].SensorKey == "" {
		t.Fatalf("expected fallback key on missing name/uuid")
	}
}

func TestParseRocmSmiJSON(t *testing.T) {
	body := []byte(`{
		"card0": {"Temperature (Sensor die) (C)": "39.0", "Other": "x"},
		"card1": {"Temp 2": 55}
	}`)
	temps, err := parseRocmSmiJSON(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(temps) != 2 {
		t.Fatalf("expected 2 temps, got %d", len(temps))
	}
}

func TestReadLinuxGPUTempsUsesCommands(t *testing.T) {
	orig := runGpuCommand
	defer func() { runGpuCommand = orig }()

	callCount := 0
	runGpuCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		callCount++
		switch name {
		case "nvidia-smi":
			return []byte("40, NVIDIA RTX 3080, GPU-1111"), nil
		case "rocm-smi":
			return []byte(`{"card0":{"Temperature (Sensor die) (C)":"50.0"}}`), nil
		default:
			return nil, errors.New("unexpected command")
		}
	}

	temps, err := readLinuxGPUTemps()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(temps) != 2 {
		t.Fatalf("expected 2 temps, got %d", len(temps))
	}
	if callCount != 2 {
		t.Fatalf("expected 2 command calls, got %d", callCount)
	}
}
