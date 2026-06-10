package app

import (
	"context"
	"io"
	"time"

	"github.com/austinkregel/compute-agent/pkg/docker"
	"github.com/austinkregel/compute-agent/pkg/transport"
)

// dockerClient returns the Docker client from the telemetry publisher, or nil.
func (a *Agent) dockerClient() *docker.Client {
	if a.telemetry == nil {
		return nil
	}
	return a.telemetry.DockerClient()
}

func (a *Agent) emitDockerError(event string, clientID string, err error) {
	a.transport.Emit(event, map[string]any{
		"clientId": clientID,
		"error":    err.Error(),
	})
}

// requireDocker returns the Docker client, emitting an error event if unavailable.
// Returns nil when Docker is not available; callers should return early.
func (a *Agent) requireDocker(errEvent, clientID string) *docker.Client {
	dc := a.dockerClient()
	if dc == nil {
		a.emitDockerError(errEvent, clientID, errDockerUnavailable)
	}
	return dc
}

// requireDockerManager returns the Docker client if it's both available and a
// swarm manager. Returns nil (with error emitted) otherwise.
func (a *Agent) requireDockerManager(errEvent, clientID string) *docker.Client {
	dc := a.requireDocker(errEvent, clientID)
	if dc != nil && !dc.IsManager() {
		a.emitDockerError(errEvent, clientID, errNotManager)
		return nil
	}
	return dc
}

func (a *Agent) handleSwarmInfo(msg transport.SwarmInfoRequest) {
	dc := a.dockerClient()
	if dc == nil {
		a.emitDockerError("swarm_info_response", msg.ClientID, errDockerUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(a.ctxOrBackground(), 10*time.Second)
	defer cancel()
	status := dc.CollectStatus(ctx)
	a.transport.Emit("swarm_info_response", map[string]any{
		"clientId": msg.ClientID,
		"data":     status,
	})
}

func (a *Agent) handleSwarmInit(msg transport.SwarmInitRequest) {
	dc := a.dockerClient()
	if dc == nil {
		a.emitDockerError("swarm_init_result", msg.ClientID, errDockerUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(a.ctxOrBackground(), 30*time.Second)
	defer cancel()
	nodeID, err := dc.SwarmInit(ctx, msg.AdvertiseAddr, msg.ListenAddr)
	if err != nil {
		a.emitDockerError("swarm_init_result", msg.ClientID, err)
		return
	}
	a.transport.Emit("swarm_init_result", map[string]any{
		"clientId": msg.ClientID,
		"nodeId":   nodeID,
		"success":  true,
	})
}

func (a *Agent) handleSwarmJoin(msg transport.SwarmJoinRequest) {
	dc := a.dockerClient()
	if dc == nil {
		a.emitDockerError("swarm_join_result", msg.ClientID, errDockerUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(a.ctxOrBackground(), 30*time.Second)
	defer cancel()
	err := dc.SwarmJoin(ctx, msg.JoinToken, msg.RemoteAddrs, msg.AdvertiseAddr)
	if err != nil {
		a.emitDockerError("swarm_join_result", msg.ClientID, err)
		return
	}
	a.transport.Emit("swarm_join_result", map[string]any{
		"clientId": msg.ClientID,
		"success":  true,
	})
}

func (a *Agent) handleSwarmLeave(msg transport.SwarmLeaveRequest) {
	dc := a.dockerClient()
	if dc == nil {
		a.emitDockerError("swarm_leave_result", msg.ClientID, errDockerUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(a.ctxOrBackground(), 15*time.Second)
	defer cancel()
	err := dc.SwarmLeave(ctx, msg.Force)
	if err != nil {
		a.emitDockerError("swarm_leave_result", msg.ClientID, err)
		return
	}
	a.transport.Emit("swarm_leave_result", map[string]any{
		"clientId": msg.ClientID,
		"success":  true,
	})
}

func (a *Agent) handleSwarmNodeUpdate(msg transport.SwarmNodeUpdateRequest) {
	dc := a.dockerClient()
	if dc == nil {
		a.emitDockerError("swarm_node_update_result", msg.ClientID, errDockerUnavailable)
		return
	}
	if !dc.IsManager() {
		a.emitDockerError("swarm_node_update_result", msg.ClientID, errNotManager)
		return
	}
	ctx, cancel := context.WithTimeout(a.ctxOrBackground(), 15*time.Second)
	defer cancel()
	err := dc.NodeUpdate(ctx, msg.NodeID, msg.Role, msg.Availability)
	if err != nil {
		a.emitDockerError("swarm_node_update_result", msg.ClientID, err)
		return
	}
	a.transport.Emit("swarm_node_update_result", map[string]any{
		"clientId": msg.ClientID,
		"success":  true,
	})
}

func (a *Agent) handleSwarmNodeList(msg transport.SwarmNodeListRequest) {
	dc := a.dockerClient()
	if dc == nil {
		a.emitDockerError("swarm_node_list_response", msg.ClientID, errDockerUnavailable)
		return
	}
	if !dc.IsManager() {
		a.emitDockerError("swarm_node_list_response", msg.ClientID, errNotManager)
		return
	}
	ctx, cancel := context.WithTimeout(a.ctxOrBackground(), 10*time.Second)
	defer cancel()
	nodes, err := dc.NodeList(ctx)
	if err != nil {
		a.emitDockerError("swarm_node_list_response", msg.ClientID, err)
		return
	}
	a.transport.Emit("swarm_node_list_response", map[string]any{
		"clientId": msg.ClientID,
		"nodes":    nodes,
	})
}

func (a *Agent) handleSwarmServiceList(msg transport.SwarmServiceListRequest) {
	dc := a.dockerClient()
	if dc == nil {
		a.emitDockerError("swarm_service_list_response", msg.ClientID, errDockerUnavailable)
		return
	}
	if !dc.IsManager() {
		a.emitDockerError("swarm_service_list_response", msg.ClientID, errNotManager)
		return
	}
	ctx, cancel := context.WithTimeout(a.ctxOrBackground(), 10*time.Second)
	defer cancel()
	services, err := dc.ServiceList(ctx)
	if err != nil {
		a.emitDockerError("swarm_service_list_response", msg.ClientID, err)
		return
	}
	a.transport.Emit("swarm_service_list_response", map[string]any{
		"clientId": msg.ClientID,
		"services": services,
	})
}

func (a *Agent) handleSwarmServiceRemove(msg transport.SwarmServiceRemoveRequest) {
	dc := a.dockerClient()
	if dc == nil {
		a.emitDockerError("swarm_service_remove_result", msg.ClientID, errDockerUnavailable)
		return
	}
	if !dc.IsManager() {
		a.emitDockerError("swarm_service_remove_result", msg.ClientID, errNotManager)
		return
	}
	ctx, cancel := context.WithTimeout(a.ctxOrBackground(), 15*time.Second)
	defer cancel()
	err := dc.ServiceRemove(ctx, msg.ServiceID)
	if err != nil {
		a.emitDockerError("swarm_service_remove_result", msg.ClientID, err)
		return
	}
	a.transport.Emit("swarm_service_remove_result", map[string]any{
		"clientId": msg.ClientID,
		"success":  true,
	})
}

func (a *Agent) handleSwarmServiceLogs(msg transport.SwarmServiceLogsRequest) {
	dc := a.dockerClient()
	if dc == nil {
		a.emitDockerError("swarm_service_logs_response", msg.ClientID, errDockerUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(a.ctxOrBackground(), 10*time.Second)
	defer cancel()
	reader, err := dc.ServiceLogs(ctx, msg.ServiceID, msg.Tail)
	if err != nil {
		a.emitDockerError("swarm_service_logs_response", msg.ClientID, err)
		return
	}
	defer reader.Close()

	const maxLogBytes = 256 * 1024 // 256 KB cap
	data, _ := io.ReadAll(io.LimitReader(reader, maxLogBytes))
	a.transport.Emit("swarm_service_logs_response", map[string]any{
		"clientId":  msg.ClientID,
		"serviceId": msg.ServiceID,
		"logs":      string(data),
	})
}

func (a *Agent) handleSwarmNetworkList(msg transport.SwarmNetworkListRequest) {
	dc := a.dockerClient()
	if dc == nil {
		a.emitDockerError("swarm_network_list_response", msg.ClientID, errDockerUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(a.ctxOrBackground(), 10*time.Second)
	defer cancel()
	nets, err := dc.NetworkList(ctx)
	if err != nil {
		a.emitDockerError("swarm_network_list_response", msg.ClientID, err)
		return
	}
	a.transport.Emit("swarm_network_list_response", map[string]any{
		"clientId": msg.ClientID,
		"networks": nets,
	})
}

func (a *Agent) handleSwarmNetworkCreate(msg transport.SwarmNetworkCreateRequest) {
	dc := a.dockerClient()
	if dc == nil {
		a.emitDockerError("swarm_network_create_result", msg.ClientID, errDockerUnavailable)
		return
	}
	if !dc.IsManager() {
		a.emitDockerError("swarm_network_create_result", msg.ClientID, errNotManager)
		return
	}
	ctx, cancel := context.WithTimeout(a.ctxOrBackground(), 15*time.Second)
	defer cancel()
	id, err := dc.NetworkCreate(ctx, msg.Name, msg.Driver, msg.Options)
	if err != nil {
		a.emitDockerError("swarm_network_create_result", msg.ClientID, err)
		return
	}
	a.transport.Emit("swarm_network_create_result", map[string]any{
		"clientId":  msg.ClientID,
		"networkId": id,
		"success":   true,
	})
}

func (a *Agent) handleSwarmNetworkRemove(msg transport.SwarmNetworkRemoveRequest) {
	dc := a.dockerClient()
	if dc == nil {
		a.emitDockerError("swarm_network_remove_result", msg.ClientID, errDockerUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(a.ctxOrBackground(), 15*time.Second)
	defer cancel()
	err := dc.NetworkRemove(ctx, msg.NetworkID)
	if err != nil {
		a.emitDockerError("swarm_network_remove_result", msg.ClientID, err)
		return
	}
	a.transport.Emit("swarm_network_remove_result", map[string]any{
		"clientId": msg.ClientID,
		"success":  true,
	})
}

func (a *Agent) handleSwarmStackList(msg transport.SwarmStackListRequest) {
	dc := a.dockerClient()
	if dc == nil {
		a.emitDockerError("swarm_stack_list_response", msg.ClientID, errDockerUnavailable)
		return
	}
	if !dc.IsManager() {
		a.emitDockerError("swarm_stack_list_response", msg.ClientID, errNotManager)
		return
	}
	ctx, cancel := context.WithTimeout(a.ctxOrBackground(), 10*time.Second)
	defer cancel()
	stacks, err := dc.StackList(ctx)
	if err != nil {
		a.emitDockerError("swarm_stack_list_response", msg.ClientID, err)
		return
	}
	a.transport.Emit("swarm_stack_list_response", map[string]any{
		"clientId": msg.ClientID,
		"stacks":   stacks,
	})
}

func (a *Agent) handleSwarmStackRemove(msg transport.SwarmStackRemoveRequest) {
	dc := a.dockerClient()
	if dc == nil {
		a.emitDockerError("swarm_stack_remove_result", msg.ClientID, errDockerUnavailable)
		return
	}
	if !dc.IsManager() {
		a.emitDockerError("swarm_stack_remove_result", msg.ClientID, errNotManager)
		return
	}
	ctx, cancel := context.WithTimeout(a.ctxOrBackground(), 30*time.Second)
	defer cancel()
	err := dc.StackRemove(ctx, msg.StackName)
	if err != nil {
		a.emitDockerError("swarm_stack_remove_result", msg.ClientID, err)
		return
	}
	a.transport.Emit("swarm_stack_remove_result", map[string]any{
		"clientId": msg.ClientID,
		"success":  true,
	})
}

// Stub handlers for service create/update (requires full ServiceSpec parsing)
func (a *Agent) handleSwarmServiceCreate(_ transport.SwarmServiceCreateRequest) {
	a.log.Warn("swarm_service_create not yet implemented")
}

func (a *Agent) handleSwarmServiceUpdate(_ transport.SwarmServiceUpdateRequest) {
	a.log.Warn("swarm_service_update not yet implemented")
}

var (
	errDockerUnavailable = errStr("docker not available on this agent")
	errNotManager        = errStr("this node is not a swarm manager")
)

type errStr string

func (e errStr) Error() string { return string(e) }
