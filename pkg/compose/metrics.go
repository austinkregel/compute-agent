package compose

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	dockerclient "github.com/docker/docker/client"
)

// ContainerMetrics holds per-container resource usage.
type ContainerMetrics struct {
	ContainerID  string  `json:"containerId"`
	Name         string  `json:"name"`
	StackName    string  `json:"stackName,omitempty"`
	Service      string  `json:"service,omitempty"`
	CPUPercent   float64 `json:"cpuPercent"`
	MemoryUsage  uint64  `json:"memoryUsage"`
	MemoryLimit  uint64  `json:"memoryLimit"`
	NetworkRx    uint64  `json:"networkRx"`
	NetworkTx    uint64  `json:"networkTx"`
	PIDs         uint64  `json:"pids"`
	Timestamp    string  `json:"ts"`
}

// CollectContainerMetrics gathers resource stats for all managed containers.
func CollectContainerMetrics(ctx context.Context, cli *dockerclient.Client) ([]ContainerMetrics, error) {
	f := filters.NewArgs(
		filters.Arg("label", labelManagedBy+"="+managedByValue),
		filters.Arg("status", "running"),
	)

	containers, err := cli.ContainerList(ctx, container.ListOptions{Filters: f})
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}

	var metrics []ContainerMetrics
	for _, c := range containers {
		m, err := getContainerStats(ctx, cli, c)
		if err != nil {
			continue
		}
		metrics = append(metrics, *m)
	}
	return metrics, nil
}

func getContainerStats(ctx context.Context, cli *dockerclient.Client, c container.Summary) (*ContainerMetrics, error) {
	statsResp, err := cli.ContainerStatsOneShot(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	defer statsResp.Body.Close()

	var stats container.StatsResponse
	if err := json.NewDecoder(statsResp.Body).Decode(&stats); err != nil {
		return nil, err
	}

	var cpuPercent float64
	cpuDelta := float64(stats.CPUStats.CPUUsage.TotalUsage - stats.PreCPUStats.CPUUsage.TotalUsage)
	systemDelta := float64(stats.CPUStats.SystemUsage - stats.PreCPUStats.SystemUsage)
	if systemDelta > 0 && cpuDelta > 0 {
		cpuPercent = (cpuDelta / systemDelta) * float64(stats.CPUStats.OnlineCPUs) * 100.0
	}

	var netRx, netTx uint64
	for _, n := range stats.Networks {
		netRx += n.RxBytes
		netTx += n.TxBytes
	}

	name := ""
	if len(c.Names) > 0 {
		name = c.Names[0]
	}

	return &ContainerMetrics{
		ContainerID: c.ID[:12],
		Name:        name,
		StackName:   c.Labels[labelStackName],
		Service:     c.Labels[labelStackService],
		CPUPercent:  cpuPercent,
		MemoryUsage: stats.MemoryStats.Usage,
		MemoryLimit: stats.MemoryStats.Limit,
		NetworkRx:   netRx,
		NetworkTx:   netTx,
		PIDs:        stats.PidsStats.Current,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}, nil
}
