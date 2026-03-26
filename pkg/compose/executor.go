package compose

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/volume"
	dockerclient "github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
)

// DeploySpec describes a full stack deployment.
type DeploySpec struct {
	StackName string            `json:"stackName"`
	Services  []ServiceSpec     `json:"services"`
	Networks  []NetworkSpec     `json:"networks,omitempty"`
	Volumes   []VolumeSpec      `json:"volumes,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
}

// ServiceSpec describes a single service to deploy.
type ServiceSpec struct {
	Name          string                  `json:"name"`
	Image         string                  `json:"image"`
	Ports         []string                `json:"ports,omitempty"`
	Mounts        []string                `json:"mounts,omitempty"`
	Command       []string                `json:"command,omitempty"`
	Entrypoint    []string                `json:"entrypoint,omitempty"`
	Environment   map[string]string       `json:"environment,omitempty"`
	Labels        map[string]string       `json:"labels,omitempty"`
	DependsOn     map[string]DependencySpec `json:"dependsOn,omitempty"`
	HealthCheck   *HealthCheckSpec        `json:"healthCheck,omitempty"`
	RestartPolicy string                  `json:"restartPolicy,omitempty"`
	Resources     *ResourceSpec           `json:"resources,omitempty"`
	Networks      []string                `json:"networks,omitempty"`
	Devices       []DeviceRequest         `json:"devices,omitempty"`
}

// DependencySpec captures the condition for a service dependency.
type DependencySpec struct {
	Condition string `json:"condition"`
}

// HealthCheckSpec is the runtime health-check configuration.
type HealthCheckSpec struct {
	Test           []string `json:"test,omitempty"`
	IntervalSec    float64  `json:"intervalSec,omitempty"`
	TimeoutSec     float64  `json:"timeoutSec,omitempty"`
	StartPeriodSec float64  `json:"startPeriodSec,omitempty"`
	Retries        int      `json:"retries,omitempty"`
}

// NetworkSpec describes a network to create for the stack.
type NetworkSpec struct {
	Name     string `json:"name"`
	Driver   string `json:"driver,omitempty"`
	Internal bool   `json:"internal,omitempty"`
}

// VolumeSpec describes a volume to create for the stack.
type VolumeSpec struct {
	Name   string `json:"name"`
	Driver string `json:"driver,omitempty"`
}

// DeviceRequest describes a device (e.g. GPU) request for a container.
type DeviceRequest struct {
	Capabilities []string `json:"capabilities,omitempty"`
	Count        int      `json:"count,omitempty"`
	Driver       string   `json:"driver,omitempty"`
}

// DeployResult is the outcome of a stack deployment.
type DeployResult struct {
	OK         bool              `json:"ok"`
	Error      string            `json:"error,omitempty"`
	Containers map[string]string `json:"containers,omitempty"`
}

const (
	labelManagedBy   = "managed-by"
	labelStackName   = "stack.name"
	labelStackService = "stack.service"
	managedByValue   = "backup-server"
)

// Executor deploys containers via the Docker SDK.
type Executor struct {
	cli *dockerclient.Client
}

// NewExecutor wraps a Docker SDK client.
func NewExecutor(cli *dockerclient.Client) *Executor {
	return &Executor{cli: cli}
}

// Deploy creates networks, volumes, pulls images, and starts containers.
func (e *Executor) Deploy(ctx context.Context, spec *DeploySpec) *DeployResult {
	result := &DeployResult{Containers: map[string]string{}}

	for _, n := range spec.Networks {
		name := fmt.Sprintf("%s_%s", spec.StackName, n.Name)
		driver := n.Driver
		if driver == "" {
			driver = "bridge"
		}
		_, err := e.cli.NetworkCreate(ctx, name, network.CreateOptions{
			Driver:   driver,
			Internal: n.Internal,
			Labels: map[string]string{
				labelManagedBy: managedByValue,
				labelStackName: spec.StackName,
			},
		})
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			result.Error = fmt.Sprintf("create network %s: %v", name, err)
			return result
		}
	}

	for _, v := range spec.Volumes {
		name := fmt.Sprintf("%s_%s", spec.StackName, v.Name)
		driver := v.Driver
		if driver == "" {
			driver = "local"
		}
		_, err := e.cli.VolumeCreate(ctx, volume.CreateOptions{
			Name:   name,
			Driver: driver,
			Labels: map[string]string{
				labelManagedBy: managedByValue,
				labelStackName: spec.StackName,
			},
		})
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			result.Error = fmt.Sprintf("create volume %s: %v", name, err)
			return result
		}
	}

	ordered := topoSort(spec.Services)

	for _, svc := range ordered {
		rc, err := e.cli.ImagePull(ctx, svc.Image, image.PullOptions{})
		if err != nil {
			result.Error = fmt.Sprintf("pull image %s: %v", svc.Image, err)
			return result
		}
		io.Copy(io.Discard, rc)
		rc.Close()

		cName := containerName(spec.StackName, svc.Name)

		labels := map[string]string{
			labelManagedBy:    managedByValue,
			labelStackName:    spec.StackName,
			labelStackService: svc.Name,
		}
		for k, v := range svc.Labels {
			labels[k] = v
		}

		env := make([]string, 0, len(svc.Environment))
		for k, v := range svc.Environment {
			env = append(env, k+"="+v)
		}
		for k, v := range spec.Env {
			env = append(env, k+"="+v)
		}

		exposedPorts, portBindings := parsePortBindings(svc.Ports)

		var binds []string
		for _, m := range svc.Mounts {
			binds = append(binds, m)
		}

		restartPolicy := container.RestartPolicy{Name: container.RestartPolicyDisabled}
		switch svc.RestartPolicy {
		case "always":
			restartPolicy.Name = container.RestartPolicyAlways
		case "unless-stopped":
			restartPolicy.Name = container.RestartPolicyUnlessStopped
		case "on-failure":
			restartPolicy.Name = container.RestartPolicyOnFailure
		}

		hostCfg := &container.HostConfig{
			Binds:         binds,
			PortBindings:  portBindings,
			RestartPolicy: restartPolicy,
		}

		if len(svc.Devices) > 0 {
			for _, d := range svc.Devices {
				hostCfg.Resources.DeviceRequests = append(hostCfg.Resources.DeviceRequests, container.DeviceRequest{
					Capabilities: [][]string{d.Capabilities},
					Count:        d.Count,
					Driver:       d.Driver,
				})
			}
		}

		containerCfg := &container.Config{
			Image:        svc.Image,
			Env:          env,
			Labels:       labels,
			ExposedPorts: exposedPorts,
			Cmd:          svc.Command,
			Entrypoint:   svc.Entrypoint,
		}

		if svc.HealthCheck != nil {
			containerCfg.Healthcheck = &container.HealthConfig{
				Test:     svc.HealthCheck.Test,
				Retries:  svc.HealthCheck.Retries,
			}
		}

		netCfg := &network.NetworkingConfig{}
		if len(svc.Networks) > 0 {
			netCfg.EndpointsConfig = map[string]*network.EndpointSettings{}
			for _, n := range svc.Networks {
				netName := fmt.Sprintf("%s_%s", spec.StackName, n)
				netCfg.EndpointsConfig[netName] = &network.EndpointSettings{}
			}
		}

		// Remove existing container if present
		e.cli.ContainerRemove(ctx, cName, container.RemoveOptions{Force: true})

		resp, err := e.cli.ContainerCreate(ctx, containerCfg, hostCfg, netCfg, nil, cName)
		if err != nil {
			result.Error = fmt.Sprintf("create container %s: %v", cName, err)
			return result
		}

		if err := e.cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
			result.Error = fmt.Sprintf("start container %s: %v", cName, err)
			return result
		}

		result.Containers[svc.Name] = resp.ID
	}

	result.OK = true
	return result
}

// Stop removes all containers and networks for a stack.
func (e *Executor) Stop(ctx context.Context, stackName string) error {
	f := filters.NewArgs(
		filters.Arg("label", labelManagedBy+"="+managedByValue),
		filters.Arg("label", labelStackName+"="+stackName),
	)

	containers, err := e.cli.ContainerList(ctx, container.ListOptions{All: true, Filters: f})
	if err != nil {
		return fmt.Errorf("list containers: %w", err)
	}

	for _, c := range containers {
		e.cli.ContainerStop(ctx, c.ID, container.StopOptions{})
		e.cli.ContainerRemove(ctx, c.ID, container.RemoveOptions{Force: true})
	}

	networks, err := e.cli.NetworkList(ctx, network.ListOptions{Filters: f})
	if err != nil {
		return fmt.Errorf("list networks: %w", err)
	}
	for _, n := range networks {
		e.cli.NetworkRemove(ctx, n.ID)
	}

	return nil
}

func parsePortBindings(ports []string) (nat.PortSet, nat.PortMap) {
	exposed := nat.PortSet{}
	bindings := nat.PortMap{}

	for _, p := range ports {
		parts := strings.SplitN(p, ":", 3)
		var hostIP, hostPort, containerPort string

		switch len(parts) {
		case 3:
			hostIP = parts[0]
			hostPort = parts[1]
			containerPort = parts[2]
		case 2:
			hostPort = parts[0]
			containerPort = parts[1]
		case 1:
			containerPort = parts[0]
		}

		// Ensure protocol suffix
		if !strings.Contains(containerPort, "/") {
			containerPort += "/tcp"
		}

		port := nat.Port(containerPort)
		exposed[port] = struct{}{}
		bindings[port] = append(bindings[port], nat.PortBinding{
			HostIP:   hostIP,
			HostPort: hostPort,
		})
	}

	return exposed, bindings
}

// topoSort orders services respecting depends_on.
func topoSort(services []ServiceSpec) []ServiceSpec {
	byName := map[string]*ServiceSpec{}
	for i := range services {
		byName[services[i].Name] = &services[i]
	}

	visited := map[string]bool{}
	var order []string

	var visit func(name string)
	visit = func(name string) {
		if visited[name] {
			return
		}
		visited[name] = true
		svc := findService(services, name)
		if svc != nil {
			for dep := range svc.DependsOn {
				visit(dep)
			}
		}
		order = append(order, name)
	}

	// Sort service names for deterministic ordering
	names := make([]string, 0, len(services))
	for _, s := range services {
		names = append(names, s.Name)
	}
	sort.Strings(names)

	for _, name := range names {
		visit(name)
	}

	result := make([]ServiceSpec, 0, len(order))
	for _, name := range order {
		if s, ok := byName[name]; ok {
			result = append(result, *s)
		}
	}
	return result
}

func findService(services []ServiceSpec, name string) *ServiceSpec {
	for i := range services {
		if services[i].Name == name {
			return &services[i]
		}
	}
	return nil
}

func containerName(stack, service string) string {
	return fmt.Sprintf("%s-%s", stack, service)
}
