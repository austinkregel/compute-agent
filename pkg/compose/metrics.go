package compose

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

// ContainerMetric holds per-container resource usage.
type ContainerMetric struct {
	ContainerID   string  `json:"containerId"`
	ContainerName string  `json:"containerName"`
	CPUPercent    float64 `json:"cpuPercent"`
	MemoryUsage   uint64  `json:"memoryUsage"`
	MemoryLimit   uint64  `json:"memoryLimit"`
	MemoryPercent float64 `json:"memoryPercent"`
	NetRx         uint64  `json:"netRx"`
	NetTx         uint64  `json:"netTx"`
	PIDs          uint64  `json:"pids"`
	StackName     string  `json:"stackName,omitempty"`
	Service       string  `json:"service,omitempty"`
}

// CollectContainerMetrics gathers CPU/memory/network stats for all running containers.
func CollectContainerMetrics(ctx context.Context, cli *client.Client) ([]ContainerMetric, error) {
	containers, err := cli.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		return nil, err
	}

	var metrics []ContainerMetric
	for _, c := range containers {
		statsResp, err := cli.ContainerStatsOneShot(ctx, c.ID)
		if err != nil {
			continue
		}

		var stats container.StatsResponse
		if err := json.NewDecoder(statsResp.Body).Decode(&stats); err != nil {
			statsResp.Body.Close()
			continue
		}
		statsResp.Body.Close()

		cpuDelta := float64(stats.CPUStats.CPUUsage.TotalUsage - stats.PreCPUStats.CPUUsage.TotalUsage)
		sysDelta := float64(stats.CPUStats.SystemUsage - stats.PreCPUStats.SystemUsage)
		cpuPercent := 0.0
		if sysDelta > 0 && cpuDelta > 0 {
			cpuPercent = (cpuDelta / sysDelta) * float64(stats.CPUStats.OnlineCPUs) * 100.0
		}

		memUsage := stats.MemoryStats.Usage
		memLimit := stats.MemoryStats.Limit
		memPercent := 0.0
		if memLimit > 0 {
			memPercent = float64(memUsage) / float64(memLimit) * 100.0
		}

		var netRx, netTx uint64
		for _, n := range stats.Networks {
			netRx += n.RxBytes
			netTx += n.TxBytes
		}

		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}

		metrics = append(metrics, ContainerMetric{
			ContainerID:   c.ID[:12],
			ContainerName: name,
			CPUPercent:    cpuPercent,
			MemoryUsage:   memUsage,
			MemoryLimit:   memLimit,
			MemoryPercent: memPercent,
			NetRx:         netRx,
			NetTx:         netTx,
			PIDs:          stats.PidsStats.Current,
			StackName:     c.Labels["com.docker.compose.project"],
			Service:       c.Labels["com.docker.compose.service"],
		})
	}
	return metrics, nil
}
