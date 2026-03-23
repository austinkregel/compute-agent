package docker

import (
	"context"
	"fmt"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
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

// StackRemove removes all services belonging to a stack namespace.
func (c *Client) StackRemove(ctx context.Context, stackName string) error {
	if c == nil || c.cli == nil {
		return fmt.Errorf("docker not available")
	}
	if stackName == "" {
		return fmt.Errorf("stack name required")
	}
	// Reject names with path separators or suspicious characters
	if strings.ContainsAny(stackName, "/\\..") {
		return fmt.Errorf("invalid stack name")
	}

	services, err := c.cli.ServiceList(ctx, types.ServiceListOptions{
		Filters: filters.NewArgs(filters.Arg("label", "com.docker.stack.namespace="+stackName)),
	})
	if err != nil {
		return fmt.Errorf("list stack services: %w", err)
	}

	var errs []string
	for _, s := range services {
		if err := c.cli.ServiceRemove(ctx, s.ID); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", s.Spec.Name, err))
		}
	}

	// Also remove stack networks
	nets, err := c.cli.NetworkList(ctx, network.ListOptions{
		Filters: filters.NewArgs(filters.Arg("label", "com.docker.stack.namespace="+stackName)),
	})
	if err == nil {
		for _, n := range nets {
			if err := c.cli.NetworkRemove(ctx, n.ID); err != nil {
				errs = append(errs, fmt.Sprintf("network %s: %v", n.Name, err))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("partial removal: %s", strings.Join(errs, "; "))
	}
	return nil
}
