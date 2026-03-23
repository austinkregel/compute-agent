package docker

import (
	"github.com/docker/docker/api/types"
)

func nodesListOptions() types.NodeListOptions {
	return types.NodeListOptions{}
}
