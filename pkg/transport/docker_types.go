package transport

import "encoding/json"

// SwarmInfoRequest requests Docker/Swarm status from the agent.
type SwarmInfoRequest struct {
	ClientID string `json:"clientId"`
}

// SwarmInitRequest asks the agent to initialize a new swarm.
type SwarmInitRequest struct {
	ClientID      string `json:"clientId"`
	AdvertiseAddr string `json:"advertiseAddr,omitempty"`
	ListenAddr    string `json:"listenAddr,omitempty"`
}

// SwarmJoinRequest asks the agent to join an existing swarm.
type SwarmJoinRequest struct {
	ClientID      string   `json:"clientId"`
	JoinToken     string   `json:"joinToken"`
	RemoteAddrs   []string `json:"remoteAddrs"`
	AdvertiseAddr string   `json:"advertiseAddr,omitempty"`
}

// SwarmLeaveRequest asks the agent to leave its current swarm.
type SwarmLeaveRequest struct {
	ClientID string `json:"clientId"`
	Force    bool   `json:"force,omitempty"`
}

// SwarmServiceListRequest asks for a list of swarm services.
type SwarmServiceListRequest struct {
	ClientID string `json:"clientId"`
}

// SwarmServiceLogsRequest asks for logs from a swarm service.
type SwarmServiceLogsRequest struct {
	ClientID  string `json:"clientId"`
	ServiceID string `json:"serviceId"`
	Tail      string `json:"tail,omitempty"`
}

// SwarmNetworkListRequest asks for a list of Docker networks.
type SwarmNetworkListRequest struct {
	ClientID string `json:"clientId"`
}

// SwarmStackListRequest asks for a list of deployed stacks.
type SwarmStackListRequest struct {
	ClientID string `json:"clientId"`
}

// SwarmNodeListRequest asks for a list of swarm nodes.
type SwarmNodeListRequest struct {
	ClientID string `json:"clientId"`
}

// ContainerInventoryRequest asks the agent to list all containers.
type ContainerInventoryRequest struct {
	ClientID string `json:"clientId"`
	Token    string `json:"token"`
}

// StackStatusRequest asks the agent for the status of a stack.
type StackStatusRequest struct {
	ClientID  string `json:"clientId"`
	Token     string `json:"token"`
	StackName string `json:"stackName"`
}

// ComposeScanRequest asks the agent to scan a directory for compose files.
type ComposeScanRequest struct {
	ClientID  string `json:"clientId"`
	Token     string `json:"token"`
	Directory string `json:"directory"`
}

// ComposeParseRequest asks the agent to parse specific compose files.
type ComposeParseRequest struct {
	ClientID string          `json:"clientId"`
	Token    string          `json:"token"`
	Files    json.RawMessage `json:"files"`
}

// ContainerLogsRequest asks the agent for container logs.
type ContainerLogsRequest struct {
	ClientID    string `json:"clientId"`
	Token       string `json:"token"`
	ContainerID string `json:"containerId"`
	Tail        string `json:"tail,omitempty"`
}
