package docker

import (
	"context"

	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	dockerclient "github.com/docker/docker/client"
)

// ContainerEvent is a simplified Docker container event.
type ContainerEvent struct {
	ContainerID   string `json:"containerId"`
	ContainerName string `json:"containerName"`
	Action        string `json:"action"`
	StackName     string `json:"stackName,omitempty"`
	Service       string `json:"service,omitempty"`
	Timestamp     int64  `json:"ts"`
}

// EventCallback is called for each container event.
type EventCallback func(ContainerEvent)

// WatchEvents subscribes to Docker events for managed containers and calls
// the callback for each relevant event. It blocks until ctx is cancelled.
func WatchEvents(ctx context.Context, cli *dockerclient.Client, callback EventCallback) {
	f := filters.NewArgs(
		filters.Arg("type", string(events.ContainerEventType)),
		filters.Arg("label", "managed-by=backup-server"),
	)

	msgCh, errCh := cli.Events(ctx, events.ListOptions{Filters: f})

	for {
		select {
		case <-ctx.Done():
			return
		case err := <-errCh:
			if err != nil {
				return
			}
		case msg := <-msgCh:
			ev := ContainerEvent{
				ContainerID:   msg.Actor.ID,
				ContainerName: msg.Actor.Attributes["name"],
				Action:        string(msg.Action),
				StackName:     msg.Actor.Attributes["stack.name"],
				Service:       msg.Actor.Attributes["stack.service"],
				Timestamp:     msg.Time,
			}
			callback(ev)
		}
	}
}
