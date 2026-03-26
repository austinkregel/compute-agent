package app

import (
	"github.com/austinkregel/compute-agent/pkg/compose"
	"github.com/austinkregel/compute-agent/pkg/transport"
)

func (a *Agent) handleComposeScan(req transport.ComposeScanRequest) {
	scanner := compose.NewScanner(a.cfg.Docker.ComposeAllowedRoots)
	result, err := scanner.ScanDirectory(req.Directory)
	if err != nil {
		_ = a.transport.Emit("compose_scan_response", map[string]any{
			"clientId": req.ClientID,
			"token":    req.Token,
			"error":    err.Error(),
		})
		return
	}
	_ = a.transport.Emit("compose_scan_response", map[string]any{
		"clientId": req.ClientID,
		"token":    req.Token,
		"data":     result,
	})
}

func (a *Agent) handleComposeParse(req transport.ComposeParseRequest) {
	scanner := compose.NewScanner(a.cfg.Docker.ComposeAllowedRoots)
	result, err := scanner.ParseFile(req.File)
	if err != nil {
		_ = a.transport.Emit("compose_parse_response", map[string]any{
			"clientId": req.ClientID,
			"token":    req.Token,
			"error":    err.Error(),
		})
		return
	}
	_ = a.transport.Emit("compose_parse_response", map[string]any{
		"clientId": req.ClientID,
		"token":    req.Token,
		"data":     result,
	})
}
