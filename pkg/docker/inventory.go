package docker

import (
	"context"
	"strings"

	"github.com/docker/docker/api/types/container"
)

// ContainerInfo describes a single container in the inventory.
type ContainerInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Image     string `json:"image"`
	State     string `json:"state"`
	Status    string `json:"status"`
	Category  string `json:"category"`
	StackName string `json:"stackName,omitempty"`
	Service   string `json:"service,omitempty"`
}

// ContainerInventory is the result of listing all containers.
type ContainerInventory struct {
	Containers []ContainerInfo `json:"containers"`
	Total      int             `json:"total"`
	Managed    int             `json:"managed"`
	Swarm      int             `json:"swarm"`
	Unmanaged  int             `json:"unmanaged"`
}

// ListAllContainers enumerates every container on the host and classifies each
// as "managed" (by backup-server), "swarm", or "unmanaged".
func (c *Client) ListAllContainers(ctx context.Context) (*ContainerInventory, error) {
	if c == nil || c.cli == nil {
		return nil, errDockerUnavail
	}
	all, err := c.cli.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, err
	}

	inv := &ContainerInventory{}
	for _, ct := range all {
		name := ""
		if len(ct.Names) > 0 {
			name = strings.TrimPrefix(ct.Names[0], "/")
		}

		ci := ContainerInfo{
			ID:     ct.ID[:12],
			Name:   name,
			Image:  ct.Image,
			State:  ct.State,
			Status: ct.Status,
		}

		switch {
		case ct.Labels["managed-by"] == "backup-server":
			ci.Category = "managed"
			ci.StackName = ct.Labels["com.docker.compose.project"]
			ci.Service = ct.Labels["com.docker.compose.service"]
			inv.Managed++
		case ct.Labels["com.docker.swarm.service.id"] != "" ||
			ct.Labels["com.docker.swarm.node.id"] != "" ||
			ct.Labels["com.docker.swarm.task.id"] != "":
			ci.Category = "swarm"
			inv.Swarm++
		default:
			ci.Category = "unmanaged"
			ci.StackName = ct.Labels["com.docker.compose.project"]
			ci.Service = ct.Labels["com.docker.compose.service"]
			inv.Unmanaged++
		}

		inv.Containers = append(inv.Containers, ci)
	}
	inv.Total = len(inv.Containers)
	return inv, nil
}

var errDockerUnavail = errString("docker not available")

type errString string

func (e errString) Error() string { return string(e) }
