package compose

import (
	"context"
	"fmt"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// DeploySpec describes a set of containers to deploy.
type DeploySpec struct {
	StackName  string          `json:"stackName"`
	Containers []ContainerSpec `json:"containers"`
	Networks   []NetworkSpec   `json:"networks,omitempty"`
}

// ContainerSpec describes a single container to create.
type ContainerSpec struct {
	Name          string            `json:"name"`
	Image         string            `json:"image"`
	Env           []string          `json:"env,omitempty"`
	Ports         []string          `json:"ports,omitempty"`
	Volumes       []string          `json:"volumes,omitempty"`
	Networks      []string          `json:"networks,omitempty"`
	RestartPolicy string            `json:"restartPolicy,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	Command       []string          `json:"command,omitempty"`
}

// NetworkSpec describes a network to ensure exists.
type NetworkSpec struct {
	Name   string `json:"name"`
	Driver string `json:"driver,omitempty"`
}

// DeployResult summarizes the outcome of a deploy operation.
type DeployResult struct {
	OK         bool     `json:"ok"`
	Error      string   `json:"error,omitempty"`
	Containers []string `json:"containers,omitempty"`
}

// Executor uses the Docker SDK to deploy and manage containers.
type Executor struct {
	cli *client.Client
}

// NewExecutor creates an Executor backed by the given Docker client.
func NewExecutor(cli *client.Client) *Executor {
	return &Executor{cli: cli}
}

// Deploy creates networks and containers as described in spec.
func (e *Executor) Deploy(ctx context.Context, spec *DeploySpec) DeployResult {
	for _, n := range spec.Networks {
		driver := n.Driver
		if driver == "" {
			driver = "bridge"
		}
		_, _ = e.cli.NetworkCreate(ctx, n.Name, network.CreateOptions{Driver: driver})
	}

	var created []string
	for _, cs := range spec.Containers {
		labels := make(map[string]string)
		for k, v := range cs.Labels {
			labels[k] = v
		}
		labels["managed-by"] = "backup-server"
		labels["com.docker.compose.project"] = spec.StackName
		labels["com.docker.compose.service"] = cs.Name

		_, _, err := e.cli.ImageInspectWithRaw(ctx, cs.Image)
		if err != nil {
			_, pullErr := e.cli.ImagePull(ctx, cs.Image, image.PullOptions{})
			if pullErr != nil {
				return DeployResult{OK: false, Error: fmt.Sprintf("pull %s: %v", cs.Image, pullErr)}
			}
		}

		containerName := fmt.Sprintf("%s-%s", spec.StackName, cs.Name)

		cfg := &container.Config{
			Image:  cs.Image,
			Env:    cs.Env,
			Labels: labels,
		}
		if len(cs.Command) > 0 {
			cfg.Cmd = cs.Command
		}

		hostCfg := &container.HostConfig{
			Binds: cs.Volumes,
		}
		if cs.RestartPolicy != "" {
			hostCfg.RestartPolicy = container.RestartPolicy{Name: container.RestartPolicyMode(cs.RestartPolicy)}
		}

		resp, err := e.cli.ContainerCreate(ctx, cfg, hostCfg, nil, (*ocispec.Platform)(nil), containerName)
		if err != nil {
			return DeployResult{OK: false, Error: fmt.Sprintf("create %s: %v", containerName, err), Containers: created}
		}

		for _, net := range cs.Networks {
			_ = e.cli.NetworkConnect(ctx, net, resp.ID, nil)
		}

		if err := e.cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
			return DeployResult{OK: false, Error: fmt.Sprintf("start %s: %v", containerName, err), Containers: created}
		}
		created = append(created, resp.ID)
	}

	return DeployResult{OK: true, Containers: created}
}

// Stop removes all containers belonging to a stack by label.
func (e *Executor) Stop(ctx context.Context, stackName string) error {
	containers, err := e.cli.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return err
	}
	for _, c := range containers {
		if c.Labels["com.docker.compose.project"] == stackName && c.Labels["managed-by"] == "backup-server" {
			_ = e.cli.ContainerStop(ctx, c.ID, container.StopOptions{})
			_ = e.cli.ContainerRemove(ctx, c.ID, container.RemoveOptions{Force: true})
		}
	}
	return nil
}

// CheckStackStatus returns status info for containers in a stack.
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
