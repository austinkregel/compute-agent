package docker

// DockerStatus represents the Docker daemon state on a node.
type DockerStatus struct {
	Available  bool              `json:"available"`
	Version    string            `json:"version,omitempty"`
	Swarm      *SwarmStatus      `json:"swarm,omitempty"`
	Containers *ContainerSummary `json:"containers,omitempty"`
}

// SwarmStatus represents the Swarm state of the node.
type SwarmStatus struct {
	Active       bool   `json:"active"`
	NodeID       string `json:"nodeId,omitempty"`
	ClusterID    string `json:"clusterId,omitempty"`
	IsManager    bool   `json:"isManager"`
	NodeState    string `json:"nodeState,omitempty"`
	Availability string `json:"availability,omitempty"`
	ManagerAddr  string `json:"managerAddr,omitempty"`
	Nodes        int    `json:"nodes,omitempty"`
	Managers     int    `json:"managers,omitempty"`
}

// ContainerSummary holds aggregate container counts.
type ContainerSummary struct {
	Running int `json:"running"`
	Stopped int `json:"stopped"`
	Total   int `json:"total"`
}

// ServiceSummary is a condensed view of a swarm service.
type ServiceSummary struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Image    string            `json:"image"`
	Mode     string            `json:"mode"`
	Replicas string            `json:"replicas"`
	Ports    []PortMapping     `json:"ports,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
}

// PortMapping describes a published port.
type PortMapping struct {
	TargetPort    uint32 `json:"targetPort"`
	PublishedPort uint32 `json:"publishedPort"`
	Protocol      string `json:"protocol"`
}

// NetworkSummary is a condensed view of a Docker network.
type NetworkSummary struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Driver string `json:"driver"`
	Scope  string `json:"scope"`
}

// NodeSummary is a condensed view of a swarm node.
type NodeSummary struct {
	ID            string `json:"id"`
	Hostname      string `json:"hostname"`
	Role          string `json:"role"`
	Availability  string `json:"availability"`
	Status        string `json:"status"`
	Addr          string `json:"addr"`
	EngineVersion string `json:"engineVersion,omitempty"`
}
