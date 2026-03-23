package docker

import (
	"context"
	"sync"
	"time"

	dockerclient "github.com/docker/docker/client"
)

// Client wraps the Docker SDK client with auto-detection and caching.
type Client struct {
	cli *dockerclient.Client

	mu         sync.Mutex
	lastStatus *DockerStatus
	lastCheck  time.Time
	cacheTTL   time.Duration
}

// NewClient attempts to connect to the Docker daemon. Returns nil if
// Docker is unavailable (not an error — the agent degrades gracefully).
func NewClient(socketPath string) *Client {
	opts := []dockerclient.Opt{
		dockerclient.FromEnv,
		dockerclient.WithAPIVersionNegotiation(),
	}
	if socketPath != "" {
		opts = append(opts, dockerclient.WithHost("unix://"+socketPath))
	}

	cli, err := dockerclient.NewClientWithOpts(opts...)
	if err != nil {
		return nil
	}

	// Verify we can actually talk to the daemon
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := cli.Ping(ctx); err != nil {
		cli.Close()
		return nil
	}

	return &Client{
		cli:      cli,
		cacheTTL: 30 * time.Second,
	}
}

// Close releases the Docker client resources.
func (c *Client) Close() error {
	if c == nil || c.cli == nil {
		return nil
	}
	return c.cli.Close()
}

// Available returns true if the Docker daemon is reachable.
func (c *Client) Available() bool {
	if c == nil || c.cli == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := c.cli.Ping(ctx)
	return err == nil
}

// CollectStatus gathers a snapshot of Docker/Swarm state. Results are cached
// for c.cacheTTL to avoid excessive API calls during frequent telemetry cycles.
func (c *Client) CollectStatus(ctx context.Context) *DockerStatus {
	if c == nil || c.cli == nil {
		return &DockerStatus{Available: false}
	}

	c.mu.Lock()
	if c.lastStatus != nil && time.Since(c.lastCheck) < c.cacheTTL {
		s := c.lastStatus
		c.mu.Unlock()
		return s
	}
	c.mu.Unlock()

	status := c.collectFresh(ctx)

	c.mu.Lock()
	c.lastStatus = status
	c.lastCheck = time.Now()
	c.mu.Unlock()

	return status
}

func (c *Client) collectFresh(ctx context.Context) *DockerStatus {
	info, err := c.cli.Info(ctx)
	if err != nil {
		return &DockerStatus{Available: false}
	}

	status := &DockerStatus{
		Available: true,
		Version:   info.ServerVersion,
		Containers: &ContainerSummary{
			Running: info.ContainersRunning,
			Stopped: info.ContainersStopped,
			Total:   info.Containers,
		},
	}

	swarm := info.Swarm
	if swarm.LocalNodeState == "active" {
		ss := &SwarmStatus{
			Active:    true,
			NodeID:    swarm.NodeID,
			IsManager: swarm.ControlAvailable,
			NodeState: string(swarm.LocalNodeState),
			Nodes:     swarm.Nodes,
			Managers:  swarm.Managers,
		}
		if swarm.Cluster != nil {
			ss.ClusterID = swarm.Cluster.ID
		}
		if len(swarm.RemoteManagers) > 0 {
			ss.ManagerAddr = swarm.RemoteManagers[0].Addr
		}
		status.Swarm = ss
	} else {
		status.Swarm = &SwarmStatus{Active: false, NodeState: string(swarm.LocalNodeState)}
	}

	return status
}

// IsSwarmActive returns true if the node is part of a swarm.
func (c *Client) IsSwarmActive() bool {
	if c == nil || c.cli == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	info, err := c.cli.Info(ctx)
	if err != nil {
		return false
	}
	return info.Swarm.LocalNodeState == "active"
}

// IsManager returns true if this node is a swarm manager.
func (c *Client) IsManager() bool {
	if c == nil || c.cli == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	info, err := c.cli.Info(ctx)
	if err != nil {
		return false
	}
	return info.Swarm.ControlAvailable
}

// Raw returns the underlying Docker client for direct API access.
func (c *Client) Raw() *dockerclient.Client {
	if c == nil {
		return nil
	}
	return c.cli
}
