package compose

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	dockerclient "github.com/docker/docker/client"
)

// StackStatus summarizes the health state of a deployed stack.
type StackStatus struct {
	StackName  string            `json:"stackName"`
	Containers []ContainerStatus `json:"containers"`
	Healthy    int               `json:"healthy"`
	Unhealthy  int               `json:"unhealthy"`
	Stopped    int               `json:"stopped"`
}

// ContainerStatus describes one container in the stack.
type ContainerStatus struct {
	Name   string `json:"name"`
	ID     string `json:"id"`
	State  string `json:"state"`
	Health string `json:"health,omitempty"`
}

// CheckStackStatus inspects all containers belonging to stackName.
func CheckStackStatus(ctx context.Context, cli *dockerclient.Client, stackName string) (*StackStatus, error) {
	f := filters.NewArgs(
		filters.Arg("label", labelManagedBy+"="+managedByValue),
		filters.Arg("label", labelStackName+"="+stackName),
	)

	containers, err := cli.ContainerList(ctx, container.ListOptions{All: true, Filters: f})
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}

	status := &StackStatus{StackName: stackName}

	for _, c := range containers {
		cs := ContainerStatus{
			ID:    c.ID[:12],
			State: c.State,
		}
		if len(c.Names) > 0 {
			cs.Name = c.Names[0]
		}

		inspect, err := cli.ContainerInspect(ctx, c.ID)
		if err == nil && inspect.State != nil && inspect.State.Health != nil {
			cs.Health = inspect.State.Health.Status
		}

		switch {
		case cs.Health == "healthy":
			status.Healthy++
		case cs.Health == "unhealthy":
			status.Unhealthy++
		case cs.State != "running":
			status.Stopped++
		case cs.Health == "":
			// Running with no health check counts as healthy
			status.Healthy++
		}

		status.Containers = append(status.Containers, cs)
	}

	return status, nil
}
