//go:build windows

package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/host"
)

// readWindowsOHMTemperatures queries the OpenHardwareMonitor HTTP API for temperature sensors.
// It prefers OHM as the primary source on Windows and returns a normalized slice of TemperatureStat.
func readWindowsOHMTemperatures(port int) ([]host.TemperatureStat, error) {
	if port <= 0 {
		port = 8085
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	url := fmt.Sprintf("http://localhost:%d/data.json", port)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request OpenHardwareMonitor: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openhardwaremonitor returned status %d", resp.StatusCode)
	}

	var root ohmNode
	if err := json.NewDecoder(resp.Body).Decode(&root); err != nil {
		return nil, fmt.Errorf("decode openhardwaremonitor json: %w", err)
	}

	var temps []host.TemperatureStat
	walkOHMTree(root, nil, &temps)
	return temps, nil
}

type ohmNode struct {
	Text       string    `json:"Text"`
	SensorType string    `json:"SensorType"`
	Value      any       `json:"Value"`
	Max        any       `json:"Max"`
	Children   []ohmNode `json:"Children"`
}

func walkOHMTree(node ohmNode, parents []string, out *[]host.TemperatureStat) {
	label := strings.TrimSpace(node.Text)
	path := parents
	if label != "" {
		path = append(path, label)
	}

	if strings.EqualFold(node.SensorType, "Temperature") {
		if val, ok := parseOHMFloat(node.Value); ok {
			ts := host.TemperatureStat{
				SensorKey:   strings.Join(path, "/"),
				Temperature: val,
			}
			if maxVal, ok := parseOHMFloat(node.Max); ok {
				ts.High = maxVal
			}
			*out = append(*out, ts)
		}
	}

	for _, child := range node.Children {
		walkOHMTree(child, path, out)
	}
}

func parseOHMFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case nil:
		return 0, false
	case float64:
		return t, true
	case json.Number:
		if f, err := t.Float64(); err == nil {
			return f, true
		}
	case string:
		s := scrubNumericPrefix(t)
		if s == "" {
			return 0, false
		}
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f, true
		}
	}
	return 0, false
}

func scrubNumericPrefix(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		if (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '+' {
			b.WriteRune(r)
			continue
		}
		if b.Len() > 0 {
			break
		}
	}
	return b.String()
}
