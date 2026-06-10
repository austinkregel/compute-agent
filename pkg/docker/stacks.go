package docker

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types"
)

// StackList returns names of deployed stacks by inspecting service labels.
func (c *Client) StackList(ctx context.Context) ([]string, error) {
	if c == nil || c.cli == nil {
		return nil, fmt.Errorf("docker not available")
	}
	services, err := c.cli.ServiceList(ctx, types.ServiceListOptions{})
	if err != nil {
		return nil, fmt.Errorf("service list: %w", err)
	}
	seen := map[string]bool{}
	for _, s := range services {
		if ns, ok := s.Spec.Labels["com.docker.stack.namespace"]; ok {
			seen[ns] = true
		}
	}
	out := make([]string, 0, len(seen))
	for ns := range seen {
		out = append(out, ns)
	}
	return out, nil
}
