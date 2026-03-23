package docker

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types/network"
)

// NetworkList returns all Docker networks.
func (c *Client) NetworkList(ctx context.Context) ([]NetworkSummary, error) {
	if c == nil || c.cli == nil {
		return nil, fmt.Errorf("docker not available")
	}
	nets, err := c.cli.NetworkList(ctx, network.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("network list: %w", err)
	}
	out := make([]NetworkSummary, len(nets))
	for i, n := range nets {
		out[i] = NetworkSummary{
			ID:     n.ID,
			Name:   n.Name,
			Driver: n.Driver,
			Scope:  n.Scope,
		}
	}
	return out, nil
}

// NetworkCreate creates a new Docker network.
func (c *Client) NetworkCreate(ctx context.Context, name string, driver string, opts map[string]string) (string, error) {
	if c == nil || c.cli == nil {
		return "", fmt.Errorf("docker not available")
	}
	if driver == "" {
		driver = "overlay"
	}
	resp, err := c.cli.NetworkCreate(ctx, name, network.CreateOptions{
		Driver:  driver,
		Options: opts,
	})
	if err != nil {
		return "", fmt.Errorf("network create: %w", err)
	}
	return resp.ID, nil
}

// NetworkRemove removes a Docker network by ID or name.
func (c *Client) NetworkRemove(ctx context.Context, networkID string) error {
	if c == nil || c.cli == nil {
		return fmt.Errorf("docker not available")
	}
	return c.cli.NetworkRemove(ctx, networkID)
}
