package telemetry

import (
	"context"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"

	"github.com/austinkregel/compute-agent/pkg/config"
	"github.com/austinkregel/compute-agent/pkg/logging"
	"github.com/austinkregel/compute-agent/pkg/transport"
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
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	if cpuPct, err := cpu.Percent(0, false); err == nil && len(cpuPct) > 0 {
		sample.CPUPercent = cpuPct[0]
	}
	if vm, err := mem.VirtualMemory(); err == nil {
		sample.MemPercent = vm.UsedPercent
	}
	if avg, err := load.Avg(); err == nil {
		// requirements.md expects a single `load` value (Node parity).
		// We use the 1-minute load average as the closest match.
		sample.Load = avg.Load1
	}
	if hi, err := host.Info(); err == nil {
		sample.UptimeSec = hi.Uptime
	}

	mount := "/"
	if runtime.GOOS == "windows" {
		mount = `C:\`
	}
	if usage, err := disk.Usage(mount); err == nil {
		v := usage.UsedPercent
		sample.DiskPercent = &v
	}

	if err := p.emitter.Emit("stats", map[string]any{"data": sample}); err != nil {
		p.log.Debug("skipping stats emit (transport offline)", "error", err)
	}
}

// StatsSample defines the schema sent to the control plane.
type StatsSample struct {
	CPUPercent  float64  `json:"cpu"`
	MemPercent  float64  `json:"mem"`
	Load        float64  `json:"load"`
	DiskPercent *float64 `json:"diskPercent,omitempty"`
	UptimeSec   uint64   `json:"uptimeSec,omitempty"`
	Timestamp   string   `json:"ts"`
}
