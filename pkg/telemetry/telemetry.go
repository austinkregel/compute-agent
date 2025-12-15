package telemetry

import (
	"context"
	"net"
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
)

// Publisher periodically gathers system metrics and ships them over the transport.
type Publisher struct {
	cfg     *config.Config
	log     *logging.Logger
	emitter transport.Emitter
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
	if bi, err := getBatteryInfo(); err == nil && bi != nil {
		sample.Battery = bi
	}

	// Thermal sensors - best effort; omitted if not available on this host.
	if temps, err := hostSensorsTemperatures(); err == nil && len(temps) > 0 {
		var thermal []ThermalSensor
		for _, t := range temps {
			thermal = append(thermal, ThermalSensor{
				SensorKey:   t.SensorKey,
				Temperature: t.Temperature,
				High:        t.High,
				Critical:    t.Critical,
			})
		}
		if len(thermal) > 0 {
			sample.Thermal = thermal
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
	SensorKey   string  `json:"sensorKey"`
	Temperature float64 `json:"temperature"`
	High        float64 `json:"sensorHigh,omitempty"`
	Critical    float64 `json:"sensorCritical,omitempty"`
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
