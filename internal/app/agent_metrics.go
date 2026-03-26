package app

import (
	"context"
	"time"

	"github.com/austinkregel/compute-agent/pkg/compose"
)

func (a *Agent) runContainerMetricsEmitter() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.emitContainerMetrics()
		}
	}
}

func (a *Agent) emitContainerMetrics() {
	dc := a.getDockerClient()
	if dc == nil || dc.Raw() == nil {
		return
	}

	ctx, cancel := context.WithTimeout(a.ctxOrBackground(), 20*time.Second)
	defer cancel()

	metrics, err := compose.CollectContainerMetrics(ctx, dc.Raw())
	if err != nil {
		a.log.Debug("container metrics collection failed", "error", err)
		return
	}
	if len(metrics) == 0 {
		return
	}

	_ = a.transport.Emit("container_metrics", map[string]any{
		"metrics": metrics,
		"ts":      time.Now().UTC().Format(time.RFC3339),
	})
}
