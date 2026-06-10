package compose

import (
	"context"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

// CheckStackStatus returns status info for containers in a stack, identified by
// the standard com.docker.compose.project label. It is read-only and works for
// stacks deployed by any tool (docker compose, Portainer, etc.).
func CheckStackStatus(ctx context.Context, cli *client.Client, stackName string) ([]map[string]any, error) {
	containers, err := cli.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, err
	}
	var result []map[string]any
	for _, c := range containers {
		if c.Labels["com.docker.compose.project"] != stackName {
			continue
		}
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		result = append(result, map[string]any{
			"id":      c.ID[:12],
			"name":    name,
			"image":   c.Image,
			"state":   c.State,
			"status":  c.Status,
			"service": c.Labels["com.docker.compose.service"],
		})
	}
	return result, nil
}

// StackState represents the overall status of a deployed stack.
type StackState struct {
	StackName  string           `json:"stackName"`
	Running    int              `json:"running"`
	Stopped    int              `json:"stopped"`
	Total      int              `json:"total"`
	Containers []ContainerState `json:"containers,omitempty"`
}

// ContainerState describes a single container within a stack.
type ContainerState struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Image   string `json:"image"`
	State   string `json:"state"`
	Status  string `json:"status"`
	Service string `json:"service,omitempty"`
}
