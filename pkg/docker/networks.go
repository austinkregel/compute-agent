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
