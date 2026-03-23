package docker

import (
	"context"
	"fmt"
	"io"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/swarm"
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

// ServiceCreate creates a new swarm service.
func (c *Client) ServiceCreate(ctx context.Context, spec swarm.ServiceSpec) (string, error) {
	if c == nil || c.cli == nil {
		return "", fmt.Errorf("docker not available")
	}
	resp, err := c.cli.ServiceCreate(ctx, spec, types.ServiceCreateOptions{})
	if err != nil {
		return "", fmt.Errorf("service create: %w", err)
	}
	return resp.ID, nil
}

// ServiceUpdate updates an existing swarm service.
func (c *Client) ServiceUpdate(ctx context.Context, serviceID string, spec swarm.ServiceSpec) error {
	if c == nil || c.cli == nil {
		return fmt.Errorf("docker not available")
	}
	svc, _, err := c.cli.ServiceInspectWithRaw(ctx, serviceID, types.ServiceInspectOptions{})
	if err != nil {
		return fmt.Errorf("service inspect: %w", err)
	}
	_, err = c.cli.ServiceUpdate(ctx, serviceID, svc.Version, spec, types.ServiceUpdateOptions{})
	if err != nil {
		return fmt.Errorf("service update: %w", err)
	}
	return nil
}

// ServiceRemove removes a swarm service.
func (c *Client) ServiceRemove(ctx context.Context, serviceID string) error {
	if c == nil || c.cli == nil {
		return fmt.Errorf("docker not available")
	}
	return c.cli.ServiceRemove(ctx, serviceID)
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
