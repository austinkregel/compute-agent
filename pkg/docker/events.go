package docker

import (
	"context"
	"time"

	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

// ContainerEvent represents a Docker container lifecycle event.
type ContainerEvent struct {
	ContainerID   string `json:"containerId"`
	ContainerName string `json:"containerName"`
	Action        string `json:"action"`
	StackName     string `json:"stackName,omitempty"`
	Service       string `json:"service,omitempty"`
	Timestamp     int64  `json:"ts"`
}

// WatchEvents subscribes to Docker container events and invokes cb for each one.
// Blocks until ctx is cancelled; automatically reconnects on stream errors.
func WatchEvents(ctx context.Context, cli *client.Client, cb func(ContainerEvent)) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msgCh, errCh := cli.Events(ctx, events.ListOptions{
			Filters: filters.NewArgs(filters.Arg("type", "container")),
		})

		for {
			select {
			case <-ctx.Done():
				return
			case err := <-errCh:
				if err != nil && ctx.Err() == nil {
					time.Sleep(5 * time.Second)
				}
				goto reconnect
			case msg := <-msgCh:
				ev := ContainerEvent{
					ContainerID: msg.Actor.ID,
					Action:      string(msg.Action),
					Timestamp:   msg.Time,
				}
				if name, ok := msg.Actor.Attributes["name"]; ok {
					ev.ContainerName = name
				}
				if stack, ok := msg.Actor.Attributes["com.docker.compose.project"]; ok {
					ev.StackName = stack
				}
				if svc, ok := msg.Actor.Attributes["com.docker.compose.service"]; ok {
					ev.Service = svc
				}
				cb(ev)
			}
		}
	reconnect:
	}
}
