package telemetry

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/austinkregel/compute-agent/pkg/config"
	"github.com/austinkregel/compute-agent/pkg/logging"
	"github.com/shirou/gopsutil/v3/host"
)

type mockEmitter struct {
	events []emittedEvent
}

type emittedEvent struct {
	event   string
	payload any
}

func (m *mockEmitter) Emit(event string, payload any) error {
	m.events = append(m.events, emittedEvent{
		event:   event,
		payload: payload,
	})
	return nil
}

func (m *mockEmitter) Events() []emittedEvent {
	return m.events
}

func (m *mockEmitter) Clear() {
	m.events = m.events[:0]
}

func TestNewPublisher(t *testing.T) {
	cfg := &config.Config{
		StatsIntervalSec: 60,
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	emitter := &mockEmitter{}

	pub := NewPublisher(cfg, log, emitter)
	if pub == nil {
		t.Fatal("NewPublisher returned nil")
	}
	if pub.cfg != cfg {
		t.Error("config not set correctly")
	}
	if pub.log != log {
		t.Error("logger not set correctly")
	}
	if pub.emitter != emitter {
		t.Error("emitter not set correctly")
	}
}

func TestRun_ContextCancellation(t *testing.T) {
	cfg := &config.Config{
		StatsIntervalSec: 1,
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	emitter := &mockEmitter{}
	pub := NewPublisher(cfg, log, emitter)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := pub.Run(ctx)
	if err == nil {
		t.Error("expected error from cancelled context")
	}
}

func TestRun_EmitsStats(t *testing.T) {
	cfg := &config.Config{
		StatsIntervalSec: 1,
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	emitter := &mockEmitter{}
	pub := NewPublisher(cfg, log, emitter)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- pub.Run(ctx)
	}()

	// Wait for at least one stats emission
	time.Sleep(1500 * time.Millisecond)
	cancel()

	<-done

	// Check that stats were emitted
	events := emitter.Events()
	if len(events) == 0 {
		t.Error("expected at least one stats event")
	}

	statsFound := false
	for _, e := range events {
		if e.event == "stats" {
			statsFound = true
			break
		}
	}
	if !statsFound {
		t.Error("expected 'stats' event")
	}
}

func TestEmitSample_StatsStructure(t *testing.T) {
	cfg := &config.Config{
		StatsIntervalSec: 60,
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	emitter := &mockEmitter{}
	pub := NewPublisher(cfg, log, emitter)

	origBattery := getBatteryInfo
	origTemps := hostSensorsTemperatures
	t.Cleanup(func() {
		getBatteryInfo = origBattery
		hostSensorsTemperatures = origTemps
	})

	getBatteryInfo = func() (*BatteryInfo, error) {
		return &BatteryInfo{Devices: []BatteryDevice{
			{ID: "BAT0", Status: "discharging", Percent: 42.0, TempC: 33.3},
		}}, nil
	}
	hostSensorsTemperatures = func() ([]host.TemperatureStat, error) {
		return []host.TemperatureStat{
			{SensorKey: "cpu_thermal", Temperature: 55.5, High: 90, Critical: 100},
		}, nil
	}

	pub.emitSample()

	events := emitter.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if events[0].event != "stats" {
		t.Errorf("expected event 'stats', got %q", events[0].event)
	}

	payload, ok := events[0].payload.(map[string]any)
	if !ok {
		t.Fatalf("expected payload to be map[string]any, got %T", events[0].payload)
	}

	data, ok := payload["data"]
	if !ok {
		t.Fatal("expected 'data' field in payload")
	}

	// StatsSample is passed as a struct, which gets serialized
	// We can check it's a StatsSample type or verify it has expected fields
	dataMap, ok := data.(map[string]any)
	if !ok {
		// If it's still a StatsSample struct, that's fine too
		sample, ok := data.(StatsSample)
		if ok {
			if sample.Timestamp == "" {
				t.Error("expected timestamp to be set")
			}
			_, err := time.Parse(time.RFC3339, sample.Timestamp)
			if err != nil {
				t.Errorf("timestamp not in RFC3339 format: %v", err)
			}
			if sample.Battery == nil || len(sample.Battery.Devices) == 0 {
				t.Error("expected battery to be present in sample when collector returns data")
			}
			if len(sample.Thermal) == 0 {
				t.Error("expected thermal to be present in sample when collector returns data")
			}
			return
		}
		t.Fatalf("expected payload.data to be StatsSample or map, got %T", data)
	}

	// Check that timestamp exists
	if ts, ok := dataMap["ts"].(string); ok {
		_, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			t.Errorf("timestamp not in RFC3339 format: %v", err)
		}
	} else {
		t.Error("expected timestamp 'ts' in stats data")
	}
}

func TestEmitSample_OmitsBatteryAndThermalWhenUnavailable(t *testing.T) {
	cfg := &config.Config{StatsIntervalSec: 60}
	log, _ := logging.New(logging.Options{Level: "error"})
	emitter := &mockEmitter{}
	pub := NewPublisher(cfg, log, emitter)

	origBattery := getBatteryInfo
	origTemps := hostSensorsTemperatures
	t.Cleanup(func() {
		getBatteryInfo = origBattery
		hostSensorsTemperatures = origTemps
	})

	getBatteryInfo = func() (*BatteryInfo, error) { return nil, nil }
	hostSensorsTemperatures = func() ([]host.TemperatureStat, error) { return nil, nil }

	pub.emitSample()
	events := emitter.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	payload, ok := events[0].payload.(map[string]any)
	if !ok {
		t.Fatalf("expected payload to be map[string]any, got %T", events[0].payload)
	}
	sampleAny := payload["data"]
	sample, ok := sampleAny.(StatsSample)
	if !ok {
		// If serialization already happened to map, just accept that shape.
		return
	}

	b, err := json.Marshal(sample)
	if err != nil {
		t.Fatalf("marshal stats sample: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal stats sample: %v", err)
	}
	if _, ok := m["battery"]; ok {
		t.Error("expected battery to be omitted when nil")
	}
	if _, ok := m["thermal"]; ok {
		t.Error("expected thermal to be omitted when empty/nil")
	}
}

func TestEmitSample_PartialStats(t *testing.T) {
	// This test verifies that partial stats collection doesn't fail
	cfg := &config.Config{
		StatsIntervalSec: 60,
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	emitter := &mockEmitter{}
	pub := NewPublisher(cfg, log, emitter)

	// Should not panic even if some stats fail to collect
	pub.emitSample()

	events := emitter.Events()
	if len(events) != 1 {
		t.Errorf("expected 1 event even with partial stats, got %d", len(events))
	}
}

func TestRun_IntervalRespected(t *testing.T) {
	cfg := &config.Config{
		StatsIntervalSec: 2,
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	emitter := &mockEmitter{}
	pub := NewPublisher(cfg, log, emitter)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- pub.Run(ctx)
	}()

	// Wait for at least one interval
	time.Sleep(2500 * time.Millisecond)
	cancel()

	<-done

	events := emitter.Events()
	// Should have emitted at least once, but not too many times
	if len(events) == 0 {
		t.Error("expected at least one stats event")
	}
	if len(events) > 3 {
		t.Errorf("expected at most 3 events in 3 seconds with 2s interval, got %d", len(events))
	}
}

func TestEmitSample_TransportOffline(t *testing.T) {
	cfg := &config.Config{
		StatsIntervalSec: 60,
	}
	log, _ := logging.New(logging.Options{Level: "error"})
	emitter := &failingEmitter{}
	pub := NewPublisher(cfg, log, emitter)

	// Should not panic when transport is offline
	pub.emitSample()
}

type failingEmitter struct{}

func (f *failingEmitter) Emit(event string, payload any) error {
	return context.Canceled
}
