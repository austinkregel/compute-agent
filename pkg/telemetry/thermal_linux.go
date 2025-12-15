//go:build linux

package telemetry

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/v3/host"
)

func readLinuxSysfsTemperatures() ([]host.TemperatureStat, error) {
	// Best-effort: read from hwmon first (most useful on servers), then thermal_zone.
	if temps, err := readLinuxHwmonTemps(); err != nil {
		return nil, err
	} else if len(temps) > 0 {
		return temps, nil
	}
	if temps, err := readLinuxThermalZoneTemps(); err != nil {
		return nil, err
	} else if len(temps) > 0 {
		return temps, nil
	}
	return nil, nil
}

func readLinuxHwmonTemps() ([]host.TemperatureStat, error) {
	const root = "/sys/class/hwmon"
	ents, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read hwmon dir: %w", err)
	}

	reInput := regexp.MustCompile(`^temp(\d+)_input$`)
	byKey := make(map[string]host.TemperatureStat)

	for _, ent := range ents {
		if !ent.IsDir() {
			continue
		}
		dir := filepath.Join(root, ent.Name())
		name := readFirstLine(filepath.Join(dir, "name"))
		if name == "" {
			name = ent.Name()
		}
		name = sanitizeKeyPart(name)

		files, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, f := range files {
			m := reInput.FindStringSubmatch(f.Name())
			if m == nil {
				continue
			}
			nStr := m[1]
			raw, ok := readInt64BestEffort(filepath.Join(dir, f.Name()))
			if !ok {
				continue
			}
			// hwmon temps are millidegree Celsius.
			tempC := float64(raw) / 1000.0

			key := fmt.Sprintf("%s_temp%s", name, nStr)
			stat := host.TemperatureStat{
				SensorKey:   key,
				Temperature: tempC,
			}
			if maxRaw, ok := readInt64BestEffort(filepath.Join(dir, "temp"+nStr+"_max")); ok {
				stat.High = float64(maxRaw) / 1000.0
			}
			if critRaw, ok := readInt64BestEffort(filepath.Join(dir, "temp"+nStr+"_crit")); ok {
				stat.Critical = float64(critRaw) / 1000.0
			}
			byKey[stat.SensorKey] = stat
		}
	}

	if len(byKey) == 0 {
		return nil, nil
	}
	out := make([]host.TemperatureStat, 0, len(byKey))
	for _, v := range byKey {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SensorKey < out[j].SensorKey })
	return out, nil
}

func readLinuxThermalZoneTemps() ([]host.TemperatureStat, error) {
	const root = "/sys/class/thermal"
	ents, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read thermal dir: %w", err)
	}

	byKey := make(map[string]host.TemperatureStat)
	for _, ent := range ents {
		if !ent.IsDir() || !strings.HasPrefix(ent.Name(), "thermal_zone") {
			continue
		}
		dir := filepath.Join(root, ent.Name())
		raw, ok := readInt64BestEffort(filepath.Join(dir, "temp"))
		if !ok {
			continue
		}
		typ := sanitizeKeyPart(readFirstLine(filepath.Join(dir, "type")))
		key := ent.Name()
		if typ != "" {
			key = key + "_" + typ
		}
		byKey[key] = host.TemperatureStat{
			SensorKey:   key,
			Temperature: float64(raw) / 1000.0, // thermal_zone temps are typically millidegree Celsius
		}
	}

	if len(byKey) == 0 {
		return nil, nil
	}
	out := make([]host.TemperatureStat, 0, len(byKey))
	for _, v := range byKey {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SensorKey < out[j].SensorKey })
	return out, nil
}

func readFirstLine(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return ""
	}
	// keep only first line
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

func readInt64BestEffort(p string) (int64, bool) {
	b, err := os.ReadFile(p)
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

var reKeyPart = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

func sanitizeKeyPart(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	s = reKeyPart.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}


