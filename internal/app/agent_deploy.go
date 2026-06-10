package app

import (
	"context"
	"encoding/json"
	"time"

	"github.com/austinkregel/compute-agent/pkg/compose"
	"github.com/austinkregel/compute-agent/pkg/docker"
	"github.com/austinkregel/compute-agent/pkg/transport"
)

func (a *Agent) handleContainerInventory(req transport.ContainerInventoryRequest) {
	dc := a.dockerClient()
	if dc == nil {
		_ = a.transport.Emit("container_inventory_response", map[string]any{
			"clientId": req.ClientID, "token": req.Token,
			"error": errDockerUnavailable.Error(), "containers": []any{},
		})
		return
	}
	ctx, cancel := context.WithTimeout(a.ctxOrBackground(), 15*time.Second)
	defer cancel()

	inv, err := dc.ListAllContainers(ctx)
	if err != nil {
		_ = a.transport.Emit("container_inventory_response", map[string]any{
			"clientId": req.ClientID, "token": req.Token,
			"error": err.Error(), "containers": []any{},
		})
		return
	}
	_ = a.transport.Emit("container_inventory_response", map[string]any{
		"clientId":   req.ClientID,
		"token":      req.Token,
		"containers": inv.Containers,
		"total":      inv.Total,
		"managed":    inv.Managed,
		"swarm":      inv.Swarm,
		"unmanaged":  inv.Unmanaged,
	})
}

func (a *Agent) handleStackDeploy(req transport.StackDeployRequest) {
	dc := a.requireDocker("stack_deploy_result", req.ClientID)
	if dc == nil {
		return
	}

	var spec compose.DeploySpec
	if err := json.Unmarshal(req.Spec, &spec); err != nil {
		_ = a.transport.Emit("stack_deploy_result", map[string]any{
			"clientId": req.ClientID,
			"token":    req.Token,
			"ok":       false,
			"error":    "invalid spec: " + err.Error(),
		})
		return
	}

	executor := compose.NewExecutor(dc.Raw())
	ctx, cancel := context.WithTimeout(a.ctxOrBackground(), 5*time.Minute)
	defer cancel()

	result := executor.Deploy(ctx, &spec)
	_ = a.transport.Emit("stack_deploy_result", map[string]any{
		"clientId":   req.ClientID,
		"token":      req.Token,
		"ok":         result.OK,
		"error":      result.Error,
		"containers": result.Containers,
	})
}

func (a *Agent) handleStackStop(req transport.StackStopRequest) {
	dc := a.requireDocker("stack_stop_result", req.ClientID)
	if dc == nil {
		return
	}

	executor := compose.NewExecutor(dc.Raw())
	ctx, cancel := context.WithTimeout(a.ctxOrBackground(), 2*time.Minute)
	defer cancel()

	err := executor.Stop(ctx, req.StackName)
	if err != nil {
		_ = a.transport.Emit("stack_stop_result", map[string]any{
			"clientId":  req.ClientID,
			"token":     req.Token,
			"ok":        false,
			"error":     err.Error(),
			"stackName": req.StackName,
		})
		return
	}
	_ = a.transport.Emit("stack_stop_result", map[string]any{
		"clientId":  req.ClientID,
		"token":     req.Token,
		"ok":        true,
		"stackName": req.StackName,
	})
}

func (a *Agent) handleStackStatus(req transport.StackStatusRequest) {
	dc := a.requireDocker("stack_status_response", req.ClientID)
	if dc == nil {
		return
	}

	ctx, cancel := context.WithTimeout(a.ctxOrBackground(), 15*time.Second)
	defer cancel()

	status, err := compose.CheckStackStatus(ctx, dc.Raw(), req.StackName)
	if err != nil {
		a.emitDockerError("stack_status_response", req.ClientID, err)
		return
	}
	_ = a.transport.Emit("stack_status_response", map[string]any{
		"clientId": req.ClientID,
		"token":    req.Token,
		"data":     status,
	})
}

func (a *Agent) runDockerEventWatcher() {
	dc := a.dockerClient()
	if dc == nil || dc.Raw() == nil {
		return
	}
	a.log.Info("starting docker event watcher")
	docker.WatchEvents(a.ctx, dc.Raw(), func(ev docker.ContainerEvent) {
		_ = a.transport.Emit("container_event", map[string]any{
			"containerId":   ev.ContainerID,
			"containerName": ev.ContainerName,
			"action":        ev.Action,
			"stackName":     ev.StackName,
			"service":       ev.Service,
			"ts":            ev.Timestamp,
		})
	})
}
