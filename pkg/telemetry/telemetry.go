package telemetry

import (
	"context"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	gopsutilnet "github.com/shirou/gopsutil/v3/net"

	"github.com/austinkregel/compute-agent/pkg/config"
	"github.com/austinkregel/compute-agent/pkg/logging"
	"github.com/austinkregel/compute-agent/pkg/transport"
	"github.com/austinkregel/compute-agent/pkg/version"
)

// Function indirections to make telemetry collection testable without depending on host hardware.
var (
	hostSensorsTemperatures = host.SensorsTemperatures
	getBatteryInfo          = getBatteryInfoImpl
	sysfsSensorsTemperatures = readLinuxSysfsTemperatures
)

// Publisher periodically gathers system metrics and ships them over the transport.
type Publisher struct {
	cfg     *config.Config
	log     *logging.Logger
	emitter transport.Emitter

	warnMu          sync.Mutex
	lastBatteryWarn time.Time
	lastThermalWarn time.Time
}

// NewPublisher creates a telemetry publisher.
func NewPublisher(cfg *config.Config, log *logging.Logger, emitter transport.Emitter) *Publisher {
	return &Publisher{cfg: cfg, log: log, emitter: emitter}
}

// Run blocks, emitting stats until context cancellation.
func (p *Publisher) Run(ctx context.Context) error {
	intervalSec := p.cfg.StatsIntervalSec
	if intervalSec <= 0 {
		intervalSec = 60
	}
	interval := time.Duration(intervalSec) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	p.log.Info("telemetry loop starting", "intervalSec", intervalSec)
	for {
		select {
		case <-ctx.Done():
			p.log.Info("telemetry loop exiting", "reason", ctx.Err())
			return ctx.Err()
		case <-ticker.C:
			p.emitSample()
		}
	}
}

// EmitNow emits a stats sample immediately (best effort). This is useful on startup so the
// control plane learns agentVersion and other metadata without waiting for the next interval tick.
func (p *Publisher) EmitNow() {
	if p == nil {
		return
	}
	p.emitSample()
}

func (p *Publisher) emitSample() {
	sample := StatsSample{
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		AgentVersion: version.Version,
	}

	// CPU percentage
	if cpuPct, err := cpu.Percent(0, false); err == nil && len(cpuPct) > 0 {
		sample.CPUPercent = cpuPct[0]
	}

	// Memory - convert to object with used/free/total (UI expects mem object, not percent)
	if vm, err := mem.VirtualMemory(); err == nil {
		sample.Mem = &MemInfo{
			Used:  vm.Used,
			Free:  vm.Free,
			Total: vm.Total,
		}
	}

	// Load average - convert to object with 1m/5m/15m
	if avg, err := load.Avg(); err == nil {
		sample.Load = LoadAvg{
			Load1:  avg.Load1,
			Load5:  avg.Load5,
			Load15: avg.Load15,
		}
	}

	// Host info - get hostname, platform, release, arch, cpus
	if hi, err := host.Info(); err == nil {
		sample.UptimeSec = hi.Uptime
		sample.Hostname = hi.Hostname
		sample.Platform = hi.Platform
		sample.Release = hi.PlatformVersion
		sample.Arch = hi.KernelArch
		sample.CPUs = int(hi.Procs)
	}

	// Battery - best effort, omitted on hosts without a battery (most servers).
	if bi, err := getBatteryInfo(); err != nil {
		p.rateLimitedWarn(&p.lastBatteryWarn, 10*time.Minute, "battery telemetry collection failed", "error", err)
	} else if bi != nil {
		sample.Battery = bi
		p.log.Debug("battery telemetry collected", "devices", len(bi.Devices))
	}

	// Thermal sensors - best effort; omitted if not available on this host.
	temps, tempsErr := hostSensorsTemperatures()
	if tempsErr != nil {
		p.rateLimitedWarn(&p.lastThermalWarn, 10*time.Minute, "thermal telemetry collection failed", "source", "gopsutil", "error", tempsErr)
	}
	// If gopsutil returns nothing (common on some hosts) attempt a Linux sysfs fallback.
	if (tempsErr != nil || len(temps) == 0) && runtime.GOOS == "linux" {
		if fb, fbErr := sysfsSensorsTemperatures(); fbErr != nil {
			p.rateLimitedWarn(&p.lastThermalWarn, 10*time.Minute, "thermal telemetry collection failed", "source", "sysfs", "error", fbErr)
		} else if len(fb) > 0 {
			temps = fb
			p.log.Debug("thermal telemetry collected via sysfs fallback", "sensors", len(temps))
		}
	}
	if len(temps) > 0 {
		var thermal []ThermalSensor
		for _, t := range temps {
			if norm, ok := normalizeThermal(t); ok {
				thermal = append(thermal, norm)
			}
		}
		if len(thermal) > 0 {
			sample.Thermal = thermal
			p.log.Debug("thermal telemetry collected", "sensors", len(thermal))
		}
	}

	// Disk usage - get all mount points
	if partitions, err := disk.Partitions(false); err == nil {
		var diskInfo []DiskInfo
		for _, part := range partitions {
			// Skip special filesystems
			if part.Fstype == "" || part.Mountpoint == "" {
				continue
			}
			if usage, err := disk.Usage(part.Mountpoint); err == nil {
				diskInfo = append(diskInfo, DiskInfo{
					Mount:    part.Mountpoint,
					FSName:   part.Device,
					FSType:   part.Fstype,
					Used:     usage.Used,
					Avail:    usage.Free,
					Capacity: usage.UsedPercent,
				})
			}
		}
		if len(diskInfo) > 0 {
			sample.Disk = diskInfo
		}
	}

	// Network interfaces
	if interfaces, err := gopsutilnet.Interfaces(); err == nil {
		var netIfaces []NetInterface
		for _, iface := range interfaces {
			// Process addresses from gopsutil InterfaceAddrList
			for _, addr := range iface.Addrs {
				// Parse the address string (format: "192.168.1.1/24" or "::1/128")
				ip, ipNet, err := net.ParseCIDR(addr.Addr)
				if err != nil {
					// Try parsing as plain IP
					ip = net.ParseIP(addr.Addr)
					if ip == nil {
						continue
					}
				}
				// Skip loopback and link-local
				if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
					continue
				}
				// Determine if internal (private) IP
				internal := ip.IsPrivate() || ip.IsLinkLocalUnicast()
				// Get CIDR notation
				var cidr string
				if ipNet != nil {
					cidr = ipNet.String()
				} else {
					cidr = ip.String()
				}
				// Determine family
				family := "IPv4"
				if ip.To4() == nil {
					family = "IPv6"
				}
				netIfaces = append(netIfaces, NetInterface{
					Name:     iface.Name,
					Family:   family,
					Address:  ip.String(),
					CIDR:     cidr,
					Internal: internal,
				})
			}
		}
		if len(netIfaces) > 0 {
			sample.NetIfaces = netIfaces
		}
	}

	if err := p.emitter.Emit("stats", map[string]any{"data": sample}); err != nil {
		p.log.Debug("skipping stats emit (transport offline)", "error", err)
	}
}

func (p *Publisher) rateLimitedWarn(last *time.Time, every time.Duration, msg string, args ...any) {
	if p == nil || p.log == nil {
		return
	}
	p.warnMu.Lock()
	defer p.warnMu.Unlock()

	now := time.Now()
	if last == nil || last.IsZero() || now.Sub(*last) >= every {
		if last != nil {
			*last = now
		}
		p.log.Warn(msg, args...)
	}
}

// StatsSample defines the schema sent to the control plane.
type StatsSample struct {
	AgentVersion string          `json:"agentVersion,omitempty"`
	CPUPercent   float64         `json:"cpu"`
	Mem          *MemInfo        `json:"mem,omitempty"` // UI expects mem object, not memPercent
	Load         LoadAvg         `json:"load"`
	Disk         []DiskInfo      `json:"disk,omitempty"`
	NetIfaces    []NetInterface  `json:"netIfaces,omitempty"`
	Hostname     string          `json:"hostname,omitempty"`
	Platform     string          `json:"platform,omitempty"`
	Release      string          `json:"release,omitempty"`
	Arch         string          `json:"arch,omitempty"`
	CPUs         int             `json:"cpus,omitempty"`
	UptimeSec    uint64          `json:"uptimeSec,omitempty"`
	Battery      *BatteryInfo    `json:"battery,omitempty"`
	Thermal      []ThermalSensor `json:"thermal,omitempty"`
	Timestamp    string          `json:"ts"`
}

// BatteryInfo is a best-effort snapshot of battery state. It is omitted on hosts without batteries.
// Units are normalized where possible but may be partially filled depending on platform capabilities.
type BatteryInfo struct {
	Devices []BatteryDevice `json:"devices"`
}

type BatteryDevice struct {
	ID string `json:"id"`

	// Status is one of: "charging", "discharging", "full", "unknown".
	Status string `json:"status,omitempty"`

	Percent float64 `json:"percent,omitempty"` // 0..100

	// Energy/power are in Wh/W if available (Linux sysfs exposes µWh/µW; we normalize).
	EnergyNowWh  float64 `json:"energyNowWh,omitempty"`
	EnergyFullWh float64 `json:"energyFullWh,omitempty"`
	PowerNowW    float64 `json:"powerNowW,omitempty"`

	VoltageNowV float64 `json:"voltageNowV,omitempty"`
	TempC       float64 `json:"tempC,omitempty"`

	CycleCount int64 `json:"cycleCount,omitempty"`

	// Time estimates in seconds, if available/derivable.
	TimeToEmptySec int64 `json:"timeToEmptySec,omitempty"`
	TimeToFullSec  int64 `json:"timeToFullSec,omitempty"`
}

// ThermalSensor mirrors gopsutil's TemperatureStat but nested under stats.
type ThermalSensor struct {
	// SensorKey is the raw sensor identifier as reported by the OS / gopsutil.
	SensorKey string `json:"sensorKey"`
	// Component is a coarse grouping ("CPU", "NVMe", "GPU", "ACPI", etc.) derived from SensorKey.
	// It is best-effort; consumers should tolerate empty values.
	Component string `json:"component,omitempty"`
	// Name is a short human-friendly label derived from SensorKey.
	// It is best-effort; consumers should tolerate empty values.
	Name        string  `json:"name,omitempty"`
	Temperature float64 `json:"temperature"`
	High        float64 `json:"sensorHigh,omitempty"`
	Critical    float64 `json:"sensorCritical,omitempty"`
}

// normalizeThermal returns a sanitized thermal sensor payload.
//
// Notes on High/Critical:
// On Linux, gopsutil reads hwmon sysfs `temp*_max` and `temp*_crit` (millidegree Celsius)
// as documented in the kernel hwmon sysfs interface:
// https://www.kernel.org/doc/Documentation/hwmon/sysfs-interface
//
// Some drivers expose these files but populate them with sentinel/garbage values (e.g., ~65000°C).
// We drop obviously-nonsensical thresholds so dashboards don't display misleading numbers.
func normalizeThermal(t host.TemperatureStat) (ThermalSensor, bool) {
	const (
		// Anything beyond these bounds is almost certainly a sentinel/driver error for our use case.
		// (Realistic machine temps are typically in [-30°C, 130°C].)
		minSaneC = -100.0
		maxSaneC = 300.0
	)

	s := ThermalSensor{
		SensorKey:   t.SensorKey,
		Temperature: t.Temperature,
	}

	// Drop totally nonsensical current temperatures too (rare but possible).
	if s.Temperature < minSaneC || s.Temperature > maxSaneC {
		return ThermalSensor{}, false
	}

	comp, name := classifyThermalKey(t.SensorKey)
	s.Component = comp
	s.Name = name

	if t.High >= minSaneC && t.High <= maxSaneC {
		s.High = t.High
	}
	if t.Critical >= minSaneC && t.Critical <= maxSaneC {
		s.Critical = t.Critical
	}
	return s, true
}

func classifyThermalKey(sensorKey string) (component string, name string) {
	k := strings.ToLower(strings.TrimSpace(sensorKey))
	if k == "" {
		return "", ""
	}

	// Common Linux hwmon drivers / naming patterns:
	switch {
	case strings.HasPrefix(k, "nvme"):
		// e.g. nvme_composite, nvme_sensor_1
		return "NVMe", shortThermalName(k, "NVMe")
	case strings.Contains(k, "k10temp") || strings.Contains(k, "coretemp") || strings.Contains(k, "cpu"):
		return "CPU", shortThermalName(k, "CPU")
	case strings.Contains(k, "amdgpu") || strings.Contains(k, "radeon") || strings.Contains(k, "nvidia") || strings.Contains(k, "gpu"):
		return "GPU", shortThermalName(k, "GPU")
	case strings.Contains(k, "acpitz") || strings.Contains(k, "thermal_zone"):
		return "ACPI", shortThermalName(k, "ACPI")
	case strings.Contains(k, "pch") || strings.Contains(k, "chipset"):
		return "Chipset", shortThermalName(k, "Chipset")
	default:
		return "Other", shortThermalName(k, "")
	}
}

func shortThermalName(k string, fallback string) string {
	// Keep names compact and stable; consumers can still use SensorKey for full detail.
	k = strings.TrimSpace(k)
	if k == "" {
		return fallback
	}
	// Drop redundant prefixes like "k10temp_" and "coretemp_"
	for _, p := range []string{"k10temp_", "coretemp_", "acpitz_", "amdgpu_", "nvme_"} {
		k = strings.TrimPrefix(k, p)
	}
	// Replace underscores with spaces for readability.
	k = strings.ReplaceAll(k, "_", " ")
	// Title-case-ish for a nicer UI without locale complexity.
	if len(k) > 0 {
		k = strings.ToUpper(k[:1]) + k[1:]
	}
	return k
}

// MemInfo represents memory statistics
type MemInfo struct {
	Used  uint64 `json:"used"`
	Free  uint64 `json:"free"`
	Total uint64 `json:"total"`
}

// LoadAvg represents load average statistics
type LoadAvg struct {
	Load1  float64 `json:"1m"`
	Load5  float64 `json:"5m"`
	Load15 float64 `json:"15m"`
}

// DiskInfo represents disk usage information
type DiskInfo struct {
	Mount    string  `json:"mount"`
	FSName   string  `json:"fsname"`
	FSType   string  `json:"fstype,omitempty"`
	Used     uint64  `json:"used"`
	Avail    uint64  `json:"avail"`
	Capacity float64 `json:"capacity"`
}

// NetInterface represents network interface information
type NetInterface struct {
	Name     string `json:"name"`
	Family   string `json:"family"`
	Address  string `json:"address"`
	CIDR     string `json:"cidr"`
	Internal bool   `json:"internal"`
}
