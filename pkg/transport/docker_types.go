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

// SwarmNodeUpdateRequest asks the agent to update a swarm node's role or availability.
type SwarmNodeUpdateRequest struct {
	ClientID     string `json:"clientId"`
	NodeID       string `json:"nodeId"`
	Role         string `json:"role,omitempty"`
	Availability string `json:"availability,omitempty"`
}

// SwarmServiceListRequest asks for a list of swarm services.
type SwarmServiceListRequest struct {
	ClientID string `json:"clientId"`
}

// SwarmServiceCreateRequest asks the agent to create a new swarm service.
type SwarmServiceCreateRequest struct {
	ClientID string         `json:"clientId"`
	Spec     map[string]any `json:"spec"`
}

// SwarmServiceUpdateRequest asks the agent to update an existing swarm service.
type SwarmServiceUpdateRequest struct {
	ClientID  string         `json:"clientId"`
	ServiceID string         `json:"serviceId"`
	Spec      map[string]any `json:"spec"`
}

// SwarmServiceRemoveRequest asks the agent to remove a swarm service.
type SwarmServiceRemoveRequest struct {
	ClientID  string `json:"clientId"`
	ServiceID string `json:"serviceId"`
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

// SwarmNetworkCreateRequest asks the agent to create a Docker network.
type SwarmNetworkCreateRequest struct {
	ClientID string            `json:"clientId"`
	Name     string            `json:"name"`
	Driver   string            `json:"driver,omitempty"`
	Options  map[string]string `json:"options,omitempty"`
}

// SwarmNetworkRemoveRequest asks the agent to remove a Docker network.
type SwarmNetworkRemoveRequest struct {
	ClientID  string `json:"clientId"`
	NetworkID string `json:"networkId"`
}

// SwarmStackListRequest asks for a list of deployed stacks.
type SwarmStackListRequest struct {
	ClientID string `json:"clientId"`
}

// SwarmStackRemoveRequest asks the agent to remove a stack.
type SwarmStackRemoveRequest struct {
	ClientID  string `json:"clientId"`
	StackName string `json:"stackName"`
}

// SwarmNodeListRequest asks for a list of swarm nodes.
type SwarmNodeListRequest struct {
	ClientID string `json:"clientId"`
}

// ComposeScanRequest asks agent to scan a directory for compose files.
type ComposeScanRequest struct {
	ClientID  string `json:"clientId"`
	Token     string `json:"token,omitempty"`
	Directory string `json:"directory"`
}

// ComposeParseRequest asks agent to parse a specific compose file.
type ComposeParseRequest struct {
	ClientID string `json:"clientId"`
	Token    string `json:"token,omitempty"`
	File     string `json:"file"`
}

type StackDeployRequest struct {
	ClientID string          `json:"clientId"`
	Token    string          `json:"token,omitempty"`
	Spec     json.RawMessage `json:"spec"`
}

type StackStopRequest struct {
	ClientID  string `json:"clientId"`
	Token     string `json:"token,omitempty"`
	StackName string `json:"stackName"`
}

type StackStatusRequest struct {
	ClientID  string `json:"clientId"`
	Token     string `json:"token,omitempty"`
	StackName string `json:"stackName"`
}

type ContainerLogsRequest struct {
	ClientID    string `json:"clientId"`
	Token       string `json:"token,omitempty"`
	ContainerID string `json:"containerId"`
	Tail        string `json:"tail,omitempty"`
}

type ContainerInventoryRequest struct {
	ClientID string `json:"clientId"`
	Token    string `json:"token,omitempty"`
}
