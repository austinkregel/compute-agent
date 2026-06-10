package docker

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types/swarm"
)

// SwarmInspect returns the swarm info if this node is a manager.
func (c *Client) SwarmInspect(ctx context.Context) (*swarm.Swarm, error) {
	if c == nil || c.cli == nil {
		return nil, fmt.Errorf("docker not available")
	}
	sw, err := c.cli.SwarmInspect(ctx)
	if err != nil {
		return nil, fmt.Errorf("swarm inspect: %w", err)
	}
	return &sw, nil
}

// SwarmInit initializes a new swarm.
func (c *Client) SwarmInit(ctx context.Context, advertiseAddr string, listenAddr string) (string, error) {
	if c == nil || c.cli == nil {
		return "", fmt.Errorf("docker not available")
	}
	if listenAddr == "" {
		listenAddr = "0.0.0.0:2377"
	}
	nodeID, err := c.cli.SwarmInit(ctx, swarm.InitRequest{
		AdvertiseAddr: advertiseAddr,
		ListenAddr:    listenAddr,
	})
	if err != nil {
		return "", fmt.Errorf("swarm init: %w", err)
	}
	return nodeID, nil
}

// SwarmJoin joins an existing swarm.
func (c *Client) SwarmJoin(ctx context.Context, joinToken string, remoteAddrs []string, advertiseAddr string) error {
	if c == nil || c.cli == nil {
		return fmt.Errorf("docker not available")
	}
	return c.cli.SwarmJoin(ctx, swarm.JoinRequest{
		JoinToken:     joinToken,
		RemoteAddrs:   remoteAddrs,
		AdvertiseAddr: advertiseAddr,
	})
}

// SwarmLeave leaves the current swarm. Force=true removes the last manager.
func (c *Client) SwarmLeave(ctx context.Context, force bool) error {
	if c == nil || c.cli == nil {
		return fmt.Errorf("docker not available")
	}
	return c.cli.SwarmLeave(ctx, force)
}

// NodeList returns all nodes in the swarm (manager-only).
func (c *Client) NodeList(ctx context.Context) ([]NodeSummary, error) {
	if c == nil || c.cli == nil {
		return nil, fmt.Errorf("docker not available")
	}
	nodes, err := c.cli.NodeList(ctx, nodesListOptions())
	if err != nil {
		return nil, fmt.Errorf("node list: %w", err)
	}
	out := make([]NodeSummary, len(nodes))
	for i, n := range nodes {
		out[i] = NodeSummary{
			ID:            n.ID,
			Hostname:      n.Description.Hostname,
			Role:          string(n.Spec.Role),
			Availability:  string(n.Spec.Availability),
			Status:        string(n.Status.State),
			Addr:          n.Status.Addr,
			EngineVersion: n.Description.Engine.EngineVersion,
		}
	}
	return out, nil
}
