package telemetry

import (
	"context"
	"errors"
	"fmt"
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
	hostSensorsTemperatures       = host.SensorsTemperatures
	getBatteryInfo                = getBatteryInfoImpl
	sysfsSensorsTemperatures      = readLinuxSysfsTemperatures
	windowsOHMSensorsTemperatures = readWindowsOHMTemperatures
	linuxGPUTemperatures          = readLinuxGPUTemps
	diskPartitions                = disk.Partitions
	diskUsage                     = disk.Usage
)

// Publisher periodically gathers system metrics and ships them over the transport.
type Publisher struct {
	cfg     *config.Config
	log     *logging.Logger
	emitter transport.Emitter
	updates *UpdateChecker

	warnMu          sync.Mutex
	lastBatteryWarn time.Time
	lastThermalWarn time.Time

	healthMu             sync.Mutex
	lastTimeSyncCheck    time.Time
	cachedTimeSyncStatus string
	lastServiceCheck     time.Time
	cachedServiceHealth  *ServiceHealth
}

// NewPublisher creates a telemetry publisher.
func NewPublisher(cfg *config.Config, log *logging.Logger, emitter transport.Emitter) *Publisher {
	p := &Publisher{cfg: cfg, log: log, emitter: emitter}
	if cfg != nil && cfg.UpdateChecksEnabled() {
		interval := time.Duration(cfg.UpdateCheckIntervalHours) * time.Hour
		p.updates = NewUpdateChecker(interval)
	}
	// Wire up battery debug logging if logger is available
	if log != nil {
		batteryDebugLog = func(msg string) {
			log.Debug(msg)
		}
	}
	return p
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

	// Update checks run on their own cadence (default 12h) and are cached into stats samples.
	if p.updates != nil {
		go func() {
			if err := p.updates.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				p.log.Debug("update checker exited", "error", err)
			}
		}()
	}
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

// CheckUpdatesNow forces an immediate OS update check (best effort) and emits a fresh stats sample.
// If update checks are disabled, this is a no-op.
func (p *Publisher) CheckUpdatesNow() {
	if p == nil || p.updates == nil {
		return
	}
	p.updates.CheckNow(context.Background())
	p.EmitNow()
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

	// Host info - get hostname, platform, release, arch
	if hi, err := host.Info(); err == nil {
		sample.UptimeSec = hi.Uptime
		sample.Hostname = hi.Hostname
		sample.Platform = hi.Platform
		sample.Release = hi.PlatformVersion
		sample.Arch = hi.KernelArch
		if strings.TrimSpace(hi.KernelVersion) != "" {
			sample.KernelVersion = strings.TrimSpace(hi.KernelVersion)
		}

		// Derive last reboot timestamp from uptime (UTC).
		if hi.Uptime > 0 {
			boot := time.Now().UTC().Add(-time.Duration(hi.Uptime) * time.Second)
			sample.LastReboot = boot.Format(time.RFC3339)
		}
	}

	// CPU count - use runtime.NumCPU() which returns the number of logical CPUs (cores/threads)
	// This is more accurate than hi.Procs which represents the number of processes
	sample.CPUs = runtime.NumCPU()

	// Update status (cached) + human summary.
	if p.updates != nil {
		info := p.updates.Snapshot()
		if strings.TrimSpace(info.LastChecked) != "" {
			sample.Updates = &info
			// Prefer a human-readable summary string so operators can triage quickly.
			if info.CheckError != "" {
				sample.SecurityPatchStatus = "unknown (update check failed)"
			} else if info.Security > 0 {
				sample.SecurityPatchStatus = fmt.Sprintf("%d security update(s) pending", info.Security)
			} else if info.Available > 0 {
				sample.SecurityPatchStatus = fmt.Sprintf("%d update(s) pending", info.Available)
			} else {
				sample.SecurityPatchStatus = "up to date"
			}
			if info.RestartRequired && sample.SecurityPatchStatus != "" {
				sample.SecurityPatchStatus = sample.SecurityPatchStatus + "; reboot required"
			}
		}
	}

	// Host health details: best-effort and cached to avoid heavy commands each tick.
	if runtime.GOOS == "linux" {
		if ts := p.getTimeSyncStatusCached(); ts != "" {
			sample.TimeSyncStatus = ts
		}
		if sh := p.getServiceHealthCached(); sh != nil {
			sample.ServiceHealth = sh
		}
	}

	// Battery - best effort, omitted on hosts without a battery (most servers).
	if bi, err := getBatteryInfo(); err != nil {
		p.rateLimitedWarn(&p.lastBatteryWarn, 10*time.Minute, "battery telemetry collection failed", "error", err)
	} else if bi != nil {
		sample.Battery = bi
		p.log.Debug("battery telemetry collected", "devices", len(bi.Devices))
	}

	// Thermal sensors - best effort; omitted if not available on this host.
	var temps []host.TemperatureStat
	var tempsErr error
	if runtime.GOOS == "windows" {
		if ohmTemps, ohmErr := windowsOHMSensorsTemperatures(p.cfg.OpenHardwareMonitorPort); ohmErr != nil {
			p.rateLimitedWarn(&p.lastThermalWarn, 10*time.Minute, "thermal telemetry collection failed", "source", "openhardwaremonitor", "error", ohmErr)
		} else if len(ohmTemps) > 0 {
			temps = ohmTemps
			p.log.Debug("thermal telemetry collected via openhardwaremonitor", "sensors", len(temps))
		} else {
			p.log.Debug("openhardwaremonitor returned no temperature sensors; falling back to gopsutil")
		}
		if len(temps) == 0 {
			temps, tempsErr = hostSensorsTemperatures()
		}
	} else {
		temps, tempsErr = hostSensorsTemperatures()
		// If gopsutil returns nothing (common on some hosts) attempt a Linux sysfs fallback.
		if (tempsErr != nil || len(temps) == 0) && runtime.GOOS == "linux" {
			if fb, fbErr := sysfsSensorsTemperatures(); fbErr != nil {
				// Only warn here if we truly have no temps at all (gopsutil returned none and sysfs failed).
				if len(temps) == 0 {
					p.rateLimitedWarn(&p.lastThermalWarn, 10*time.Minute, "thermal telemetry collection failed", "source", "sysfs", "error", fbErr)
				} else {
					p.log.Debug("thermal telemetry sysfs fallback failed (gopsutil still returned temps)", "error", fbErr, "gopsutilSensors", len(temps))
				}
			} else if len(fb) > 0 {
				temps = fb
				p.log.Debug("thermal telemetry collected via sysfs fallback", "sensors", len(temps))
			}
		}
	}

	// Linux GPU temps (best-effort via vendor CLIs) augment other sensors.
	if runtime.GOOS == "linux" {
		if gpuTemps, gpuErr := linuxGPUTemperatures(); gpuErr != nil {
			p.log.Debug("gpu thermal telemetry collection failed", "source", "gpu_cli", "error", gpuErr)
		} else if len(gpuTemps) > 0 {
			temps = append(temps, gpuTemps...)
			p.log.Debug("thermal telemetry collected via gpu cli", "sensors", len(gpuTemps))
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
		} else if tempsErr != nil {
			// gopsutil can return non-fatal errors/warnings alongside data; don't escalate unless empty.
			p.log.Debug("thermal telemetry had collection warnings", "source", "gopsutil", "error", tempsErr, "rawSensors", len(temps))
		}
	} else if tempsErr != nil {
		// If we got no temps at all, surface the gopsutil error (rate-limited).
		p.rateLimitedWarn(&p.lastThermalWarn, 10*time.Minute, "thermal telemetry collection failed", "source", "gopsutil", "error", tempsErr)
	}

	// Disk usage - get all mount points
	if partitions, err := diskPartitions(false); err == nil {
		var diskInfo []DiskInfo
		for _, part := range partitions {
			// Skip special filesystems
			if part.Fstype == "" || part.Mountpoint == "" {
				continue
			}
			// Filter out snap-related mounts on Linux (loop-mounted squashfs images under /snap and /var/snap).
			if runtime.GOOS == "linux" &&
				(strings.HasPrefix(part.Mountpoint, "/snap/") || strings.HasPrefix(part.Mountpoint, "/var/snap/")) {
				continue
			}
			if usage, err := diskUsage(part.Mountpoint); err == nil {
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

func (p *Publisher) getTimeSyncStatusCached() string {
	// Recompute at most every 15 minutes.
	const every = 15 * time.Minute
	now := time.Now()

	p.healthMu.Lock()
	defer p.healthMu.Unlock()

	if !p.lastTimeSyncCheck.IsZero() && now.Sub(p.lastTimeSyncCheck) < every {
		return p.cachedTimeSyncStatus
	}
	p.lastTimeSyncCheck = now

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stdout, _, _, err := runCmd(ctx, "timedatectl", "show", "-p", "NTPSynchronized", "--value")
	if err != nil {
		p.cachedTimeSyncStatus = ""
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(stdout)) {
	case "yes", "true", "1":
		p.cachedTimeSyncStatus = "synced"
	case "no", "false", "0":
		p.cachedTimeSyncStatus = "unsynced"
	default:
		p.cachedTimeSyncStatus = ""
	}
	return p.cachedTimeSyncStatus
}

func (p *Publisher) getServiceHealthCached() *ServiceHealth {
	// Recompute at most every 15 minutes.
	const every = 15 * time.Minute
	now := time.Now()

	p.healthMu.Lock()
	defer p.healthMu.Unlock()

	if !p.lastServiceCheck.IsZero() && now.Sub(p.lastServiceCheck) < every {
		return p.cachedServiceHealth
	}
	p.lastServiceCheck = now

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stdout, _, _, err := runCmd(ctx, "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager")
	if err != nil {
		p.cachedServiceHealth = nil
		return nil
	}

	var total, running, failed int
	for _, raw := range strings.Split(stdout, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		// Fields: UNIT LOAD ACTIVE SUB ...
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		unit := fields[0]
		if !strings.HasSuffix(unit, ".service") {
			continue
		}
		total++
		active := strings.ToLower(fields[2])
		sub := strings.ToLower(fields[3])
		if active == "failed" {
			failed++
			continue
		}
		if active == "active" && sub == "running" {
			running++
		}
	}
	p.cachedServiceHealth = &ServiceHealth{
		Total:   total,
		Running: running,
		Failed:  failed,
	}
	return p.cachedServiceHealth
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
	AgentVersion        string          `json:"agentVersion,omitempty"`
	CPUPercent          float64         `json:"cpu"`
	Mem                 *MemInfo        `json:"mem,omitempty"` // UI expects mem object, not memPercent
	Load                LoadAvg         `json:"load"`
	Disk                []DiskInfo      `json:"disk,omitempty"`
	NetIfaces           []NetInterface  `json:"netIfaces,omitempty"`
	Hostname            string          `json:"hostname,omitempty"`
	Platform            string          `json:"platform,omitempty"`
	Release             string          `json:"release,omitempty"`
	Arch                string          `json:"arch,omitempty"`
	CPUs                int             `json:"cpus,omitempty"`
	UptimeSec           uint64          `json:"uptimeSec,omitempty"`
	Battery             *BatteryInfo    `json:"battery,omitempty"`
	Thermal             []ThermalSensor `json:"thermal,omitempty"`
	Updates             *UpdateInfo     `json:"updates,omitempty"`
	LastReboot          string          `json:"lastReboot,omitempty"` // RFC3339 timestamp (UTC)
	KernelVersion       string          `json:"kernelVersion,omitempty"`
	SecurityPatchStatus string          `json:"securityPatchStatus,omitempty"`
	ServiceHealth       *ServiceHealth  `json:"serviceHealth,omitempty"`
	TimeSyncStatus      string          `json:"timeSyncStatus,omitempty"`
	Timestamp           string          `json:"ts"`
}

type ServiceHealth struct {
	Total          int      `json:"total"`
	Running        int      `json:"running"`
	Failed         int      `json:"failed"`
	CriticalFailed []string `json:"criticalFailed,omitempty"`
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
