package telemetry

import (
	"context"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
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
		sample.MemUsedBytes = vm.Used
		sample.MemTotalBytes = vm.Total
	}
	if avg, err := load.Avg(); err == nil {
		sample.Load1 = avg.Load1
		sample.Load5 = avg.Load5
		sample.Load15 = avg.Load15
	}
	if hi, err := host.Info(); err == nil {
		sample.UptimeSec = hi.Uptime
		sample.Hostname = hi.Hostname
	}

	if err := p.emitter.Emit("stats", map[string]any{"data": sample}); err != nil {
		p.log.Debug("skipping stats emit (transport offline)", "error", err)
	}
}

// StatsSample defines the schema sent to the control plane.
type StatsSample struct {
	CPUPercent    float64 `json:"cpu"`
	MemPercent    float64 `json:"mem"`
	MemUsedBytes  uint64  `json:"memUsedBytes"`
	MemTotalBytes uint64  `json:"memTotalBytes"`
	Load1         float64 `json:"load1"`
	Load5         float64 `json:"load5"`
	Load15        float64 `json:"load15"`
	UptimeSec     uint64  `json:"uptimeSec"`
	Hostname      string  `json:"hostname"`
	Timestamp     string  `json:"ts"`
}
