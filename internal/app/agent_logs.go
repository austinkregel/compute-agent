package app

import (
	"context"
	"io"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/austinkregel/compute-agent/pkg/transport"
)

func (a *Agent) handleContainerLogs(req transport.ContainerLogsRequest) {
	dc := a.getDockerClient()
	if dc == nil || dc.Raw() == nil {
		a.emitDockerError("container_logs_response", req.ClientID, errDockerUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(a.ctxOrBackground(), 15*time.Second)
	defer cancel()

	tail := req.Tail
	if tail == "" {
		tail = "100"
	}

	reader, err := dc.Raw().ContainerLogs(ctx, req.ContainerID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       tail,
	})
	if err != nil {
		a.emitDockerError("container_logs_response", req.ClientID, err)
		return
	}
	defer reader.Close()

	const maxLogBytes = 256 * 1024
	data, _ := io.ReadAll(io.LimitReader(reader, maxLogBytes))

	_ = a.transport.Emit("container_logs_response", map[string]any{
		"clientId":    req.ClientID,
		"containerId": req.ContainerID,
		"logs":        stripDockerLogHeaders(data),
	})
}

// stripDockerLogHeaders removes the 8-byte Docker multiplexing header from
// each log line. Docker log stream format: [8-byte header][payload].
// Header: [stream_type, 0, 0, 0, size(4 bytes big-endian)].
func stripDockerLogHeaders(data []byte) string {
	var result []byte
	for len(data) >= 8 {
		// Read payload size from bytes 4-7 (big-endian uint32)
		size := uint32(data[4])<<24 | uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7])
		data = data[8:]
		if uint32(len(data)) < size {
			result = append(result, data...)
			break
		}
		result = append(result, data[:size]...)
		data = data[size:]
	}
	if len(data) > 0 && len(result) == 0 {
		return string(data)
	}
	return string(result)
}
