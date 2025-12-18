//go:build linux

package telemetry

import (
	"encoding/json"
	"testing"

	"github.com/austinkregel/compute-agent/pkg/config"
	"github.com/austinkregel/compute-agent/pkg/logging"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
)

func TestEmitSample_FiltersSnapMountsOnLinux(t *testing.T) {
	log, _ := logging.New(logging.Options{Level: "error"})
	emitter := &mockEmitter{}
	pub := NewPublisher(&config.Config{StatsIntervalSec: 60}, log, emitter)

	origBattery := getBatteryInfo
	origTemps := hostSensorsTemperatures
	origSysfsTemps := sysfsSensorsTemperatures
	origGpuTemps := linuxGPUTemperatures
	origPartitions := diskPartitions
	origUsage := diskUsage
	t.Cleanup(func() {
		getBatteryInfo = origBattery
		hostSensorsTemperatures = origTemps
		sysfsSensorsTemperatures = origSysfsTemps
		linuxGPUTemperatures = origGpuTemps
		diskPartitions = origPartitions
		diskUsage = origUsage
	})

	// Keep telemetry emit deterministic and avoid touching real host hardware.
	getBatteryInfo = func() (*BatteryInfo, error) { return nil, nil }
	hostSensorsTemperatures = func() ([]host.TemperatureStat, error) { return nil, nil }
	sysfsSensorsTemperatures = func() ([]host.TemperatureStat, error) { return nil, nil }
	linuxGPUTemperatures = func() ([]host.TemperatureStat, error) { return nil, nil }

	diskPartitions = func(all bool) ([]disk.PartitionStat, error) {
		return []disk.PartitionStat{
			{Device: "/dev/root", Mountpoint: "/", Fstype: "ext4"},
			{Device: "/dev/sda1", Mountpoint: "/home", Fstype: "ext4"},
			{Device: "/dev/loop0", Mountpoint: "/snap/core/8592", Fstype: "squashfs"},
			{Device: "/dev/loop1", Mountpoint: "/var/snap/snapd/123", Fstype: "squashfs"},
		}, nil
	}

	var usageCalls []string
	diskUsage = func(path string) (*disk.UsageStat, error) {
		usageCalls = append(usageCalls, path)
		return &disk.UsageStat{
			Used:        1,
			Free:        2,
			UsedPercent: 33.3,
		}, nil
	}

	pub.emitSample()

	events := emitter.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	payload, ok := events[0].payload.(map[string]any)
	if !ok {
		t.Fatalf("expected payload to be map[string]any, got %T", events[0].payload)
	}

	// Serialize to JSON so we can assert on the wire shape regardless of whether the emitter
	// still has a concrete StatsSample or a map.
	b, err := json.Marshal(payload["data"])
	if err != nil {
		t.Fatalf("marshal stats sample: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal stats sample: %v", err)
	}

	// Verify snap mounts are not present in emitted disk list.
	rawDisk, ok := m["disk"]
	if !ok {
		t.Fatalf("expected disk field to be present")
	}
	items, ok := rawDisk.([]any)
	if !ok {
		t.Fatalf("expected disk to be an array, got %T", rawDisk)
	}

	var mounts []string
	for _, it := range items {
		obj, ok := it.(map[string]any)
		if !ok {
			continue
		}
		if s, ok := obj["mount"].(string); ok {
			mounts = append(mounts, s)
		}
	}

	contains := func(ss []string, want string) bool {
		for _, s := range ss {
			if s == want {
				return true
			}
		}
		return false
	}

	if !contains(mounts, "/") || !contains(mounts, "/home") {
		t.Fatalf("expected mounts to include / and /home, got %v", mounts)
	}
	if contains(mounts, "/snap/core/8592") || contains(mounts, "/var/snap/snapd/123") {
		t.Fatalf("expected snap mounts to be filtered out, got %v", mounts)
	}

	// Also ensure we never even attempted disk.Usage() for snap mountpoints.
	if contains(usageCalls, "/snap/core/8592") || contains(usageCalls, "/var/snap/snapd/123") {
		t.Fatalf("expected disk usage not called for snap mounts; calls=%v", usageCalls)
	}
	if !contains(usageCalls, "/") || !contains(usageCalls, "/home") {
		t.Fatalf("expected disk usage called for / and /home; calls=%v", usageCalls)
	}
}
