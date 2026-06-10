package app

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/austinkregel/compute-agent/pkg/transport"
)

func (a *Agent) handleComposeScan(req transport.ComposeScanRequest) {
	dir := req.Directory
	if dir == "" {
		_ = a.transport.Emit("compose_scan_response", map[string]any{
			"clientId": req.ClientID,
			"token":    req.Token,
			"error":    "directory is required",
		})
		return
	}

	var files []map[string]any
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		base := strings.ToLower(d.Name())
		if isComposeFile(base) {
			rel, _ := filepath.Rel(dir, path)
			info, _ := d.Info()
			size := int64(0)
			if info != nil {
				size = info.Size()
			}
			files = append(files, map[string]any{
				"file": rel,
				"path": path,
				"size": size,
			})
		}
		return nil
	})

	if err != nil {
		_ = a.transport.Emit("compose_scan_response", map[string]any{
			"clientId": req.ClientID,
			"token":    req.Token,
			"error":    err.Error(),
		})
		return
	}

	_ = a.transport.Emit("compose_scan_response", map[string]any{
		"clientId":  req.ClientID,
		"token":     req.Token,
		"directory": dir,
		"files":     files,
	})
}

func (a *Agent) handleComposeParse(req transport.ComposeParseRequest) {
	_ = a.transport.Emit("compose_parse_response", map[string]any{
		"clientId": req.ClientID,
		"token":    req.Token,
		"error":    "compose parsing not yet implemented on this agent version",
	})
}

func isComposeFile(name string) bool {
	composeNames := []string{
		"docker-compose.yml", "docker-compose.yaml",
		"compose.yml", "compose.yaml",
	}
	for _, cn := range composeNames {
		if name == cn {
			return true
		}
	}
	if strings.HasPrefix(name, "docker-compose.") && (strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")) {
		return true
	}
	return false
}
