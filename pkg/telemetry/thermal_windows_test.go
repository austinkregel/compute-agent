//go:build windows

package telemetry

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestReadWindowsOHMTemperatures_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"Text": "",
			"Children": [{
				"Text": "Host",
				"Children": [{
					"Text": "CPU",
					"Children": [
						{"Text": "Core #1", "SensorType": "Temperature", "Value": 45.5, "Max": "100\u00b0C"},
						{"Text": "Core #2", "SensorType": "Temperature", "Value": "47.2 \u00b0C", "Max": "105"}
					]
				}]
			}]
		}`))
	}))
	defer server.Close()

	_, portStr, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	temps, err := readWindowsOHMTemperatures(port)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(temps) != 2 {
		t.Fatalf("expected 2 temps, got %d", len(temps))
	}
	if temps[0].SensorKey == "" || temps[1].SensorKey == "" {
		t.Fatalf("expected sensor keys to be populated")
	}
	if temps[0].Temperature != 45.5 {
		t.Errorf("expected first temp 45.5, got %v", temps[0].Temperature)
	}
	if temps[0].High != 100 {
		t.Errorf("expected first max 100, got %v", temps[0].High)
	}
	if temps[1].Temperature != 47.2 {
		t.Errorf("expected second temp 47.2, got %v", temps[1].Temperature)
	}
	if temps[1].High != 105 {
		t.Errorf("expected second max 105, got %v", temps[1].High)
	}
}

func TestReadWindowsOHMTemperatures_HTTPFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer server.Close()

	_, portStr, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	if _, err := readWindowsOHMTemperatures(port); err == nil {
		t.Fatalf("expected error for non-200 response")
	}
}
