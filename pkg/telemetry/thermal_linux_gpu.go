//go:build linux

package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/host"
)

// Function indirection for testability.
var runGpuCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Output()
}

// readLinuxGPUTemps attempts best-effort GPU temperature collection using vendor CLIs.
// It augments sysfs temps with NVIDIA (nvidia-smi) and AMD (rocm-smi) data when available.
func readLinuxGPUTemps() ([]host.TemperatureStat, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var temps []host.TemperatureStat

	if nvidia, err := readNvidiaSmiTemps(ctx); err == nil && len(nvidia) > 0 {
		temps = append(temps, nvidia...)
	}
	if amd, err := readRocmSmiTemps(ctx); err == nil && len(amd) > 0 {
		temps = append(temps, amd...)
	}

	if len(temps) == 0 {
		return nil, nil
	}
	return temps, nil
}

func readNvidiaSmiTemps(ctx context.Context) ([]host.TemperatureStat, error) {
	out, err := runGpuCommand(ctx, "nvidia-smi",
		"--query-gpu=temperature.gpu,name,uuid",
		"--format=csv,noheader,nounits")
	if err != nil {
		return nil, err
	}
	return parseNvidiaSmiCSV(string(out)), nil
}

func parseNvidiaSmiCSV(body string) []host.TemperatureStat {
	lines := strings.Split(body, "\n")
	var temps []host.TemperatureStat
	for idx, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}
		tempStr := strings.TrimSpace(parts[0])
		tempVal, err := strconv.ParseFloat(tempStr, 64)
		if err != nil {
			continue
		}
		name := "nvidia"
		if len(parts) >= 2 {
			name = strings.TrimSpace(parts[1])
		}
		uuid := ""
		if len(parts) >= 3 {
			uuid = strings.TrimSpace(parts[2])
		}
		keyParts := []string{"gpu", "nvidia"}
		if name != "" {
			keyParts = append(keyParts, sanitizeGPUKeyPart(name))
		}
		if uuid != "" {
			keyParts = append(keyParts, sanitizeGPUKeyPart(uuid))
		} else {
			keyParts = append(keyParts, fmt.Sprintf("index%d", idx))
		}
		key := strings.Join(keyParts, "_")
		temps = append(temps, host.TemperatureStat{
			SensorKey:   key,
			Temperature: tempVal,
		})
	}
	return temps
}

func readRocmSmiTemps(ctx context.Context) ([]host.TemperatureStat, error) {
	out, err := runGpuCommand(ctx, "rocm-smi", "--showtemp", "--json")
	if err != nil {
		return nil, err
	}
	return parseRocmSmiJSON(out)
}

func parseRocmSmiJSON(body []byte) ([]host.TemperatureStat, error) {
	// rocm-smi --showtemp --json output is typically: {"card0": {"Temperature (Sensor die) (C)": "39.0", ...}, ...}
	var raw map[string]map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil
	}

	var temps []host.TemperatureStat
	for card, fields := range raw {
		if fields == nil {
			continue
		}
		for k, v := range fields {
			if !strings.Contains(strings.ToLower(k), "temp") {
				continue
			}
			valStr := fmt.Sprint(v)
			valStr = strings.TrimSpace(strings.TrimSuffix(valStr, "C"))
			valStr = strings.TrimSuffix(valStr, "c")
			valStr = strings.TrimSuffix(valStr, "°")
			valStr = strings.TrimSpace(valStr)
			tempVal, err := strconv.ParseFloat(valStr, 64)
			if err != nil {
				continue
			}
			key := strings.Join([]string{"gpu", "amd", sanitizeGPUKeyPart(card), sanitizeGPUKeyPart(k)}, "_")
			temps = append(temps, host.TemperatureStat{
				SensorKey:   key,
				Temperature: tempVal,
			})
		}
	}
	if len(temps) == 0 {
		return nil, nil
	}
	return temps, nil
}

// sanitizeGPUKeyPart is local to GPU helpers to avoid exporting symbols used elsewhere.
var gpuKeyPartRe = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

func sanitizeGPUKeyPart(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	s = gpuKeyPartRe.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}
