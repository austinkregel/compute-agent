package docker

import (
	"context"
	"fmt"
	"io"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
)

// ServiceList returns all swarm services (manager-only).
func (c *Client) ServiceList(ctx context.Context) ([]ServiceSummary, error) {
	if c == nil || c.cli == nil {
		return nil, fmt.Errorf("docker not available")
	}
	services, err := c.cli.ServiceList(ctx, types.ServiceListOptions{})
	if err != nil {
		return nil, fmt.Errorf("service list: %w", err)
	}
	out := make([]ServiceSummary, len(services))
	for i, s := range services {
		ss := ServiceSummary{
			ID:     s.ID,
			Name:   s.Spec.Name,
			Labels: s.Spec.Labels,
		}
		if s.Spec.TaskTemplate.ContainerSpec != nil {
			ss.Image = s.Spec.TaskTemplate.ContainerSpec.Image
		}
		if s.Spec.Mode.Replicated != nil {
			ss.Mode = "replicated"
			running := uint64(0)
			if s.ServiceStatus != nil {
				running = s.ServiceStatus.RunningTasks
			}
			ss.Replicas = fmt.Sprintf("%d/%d", running, *s.Spec.Mode.Replicated.Replicas)
		} else {
			ss.Mode = "global"
		}
		for _, p := range s.Endpoint.Ports {
			ss.Ports = append(ss.Ports, PortMapping{
				TargetPort:    p.TargetPort,
				PublishedPort: p.PublishedPort,
				Protocol:      string(p.Protocol),
			})
		}
		out[i] = ss
	}
	return out, nil
}

// ServiceLogs returns a reader for service logs.
func (c *Client) ServiceLogs(ctx context.Context, serviceID string, tail string) (io.ReadCloser, error) {
	if c == nil || c.cli == nil {
		return nil, fmt.Errorf("docker not available")
	}
	if tail == "" {
		tail = "100"
	}
	return c.cli.ServiceLogs(ctx, serviceID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       tail,
		Follow:     false,
	})
}
