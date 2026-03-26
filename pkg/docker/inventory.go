package docker

import (
	"context"
	"fmt"
	"strings"

	"github.com/docker/docker/api/types/container"
)

// ContainerInfo describes a single container on the host.
type ContainerInfo struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Image     string            `json:"image"`
	State     string            `json:"state"`
	Status    string            `json:"status"`
	ManagedBy string            `json:"managedBy"`
	StackName string            `json:"stackName,omitempty"`
	Service   string            `json:"service,omitempty"`
	CreatedAt int64             `json:"createdAt"`
	Ports     []PortMapping     `json:"ports,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// ContainerInventory is a classified summary of all containers on the host.
type ContainerInventory struct {
	Total      int             `json:"total"`
	Managed    int             `json:"managed"`
	Swarm      int             `json:"swarm"`
	Unmanaged  int             `json:"unmanaged"`
	Containers []ContainerInfo `json:"containers"`
}

// ListAllContainers lists every container on the host and classifies them.
func (c *Client) ListAllContainers(ctx context.Context) (*ContainerInventory, error) {
	if c == nil || c.cli == nil {
		return nil, fmt.Errorf("docker client unavailable")
	}

	containers, err := c.cli.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}

	inv := &ContainerInventory{
		Total:      len(containers),
		Containers: make([]ContainerInfo, 0, len(containers)),
	}

	for _, ctr := range containers {
		classification := classifyContainer(ctr.Labels)

		name := ""
		if len(ctr.Names) > 0 {
			name = strings.TrimPrefix(ctr.Names[0], "/")
		}

		var ports []PortMapping
		for _, p := range ctr.Ports {
			ports = append(ports, PortMapping{
				TargetPort:    uint32(p.PrivatePort),
				PublishedPort: uint32(p.PublicPort),
				Protocol:      p.Type,
			})
		}

		info := ContainerInfo{
			ID:        ctr.ID[:12],
			Name:      name,
			Image:     ctr.Image,
			State:     ctr.State,
			Status:    ctr.Status,
			ManagedBy: classification,
			StackName: ctr.Labels["stack.name"],
			Service:   ctr.Labels["stack.service"],
			CreatedAt: ctr.Created,
			Ports:     ports,
			Labels:    ctr.Labels,
		}

		switch classification {
		case "backup-server":
			inv.Managed++
		case "swarm":
			inv.Swarm++
		default:
			inv.Unmanaged++
		}

		inv.Containers = append(inv.Containers, info)
	}

	return inv, nil
}

func classifyContainer(labels map[string]string) string {
	if labels["managed-by"] == "backup-server" {
		return "backup-server"
	}
	if _, ok := labels["com.docker.swarm.service.id"]; ok {
		return "swarm"
	}
	if _, ok := labels["com.docker.swarm.task.id"]; ok {
		return "swarm"
	}
	return "unmanaged"
}
