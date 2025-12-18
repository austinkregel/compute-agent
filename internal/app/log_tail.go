package app

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/austinkregel/compute-agent/pkg/transport"
)

type tailHandle struct {
	cancel context.CancelFunc
}

func (a *Agent) handleLogTailStart(msg transport.LogTailStart) {
	session := strings.TrimSpace(msg.Session)
	if session == "" {
		a.log.Warn("log_tail_start missing session")
		return
	}
	lines := msg.Lines
	if lines <= 0 || lines > 200 {
		lines = 10
	}

	ctx, cancel := context.WithCancel(a.ctxOrBackground())
	handle := &tailHandle{cancel: cancel}

	a.logTailMu.Lock()
	if prev := a.logTail[session]; prev != nil && prev.cancel != nil {
		prev.cancel()
	}
	a.logTail[session] = handle
	a.logTailMu.Unlock()

	go a.runLogTail(ctx, session, lines, handle)
}

func (a *Agent) handleLogTailStop(msg transport.LogTailStop) {
	session := strings.TrimSpace(msg.Session)
	if session == "" {
		return
	}

	a.logTailMu.Lock()
	handle := a.logTail[session]
	delete(a.logTail, session)
	a.logTailMu.Unlock()

	if handle != nil && handle.cancel != nil {
		handle.cancel()
	}
}

func (a *Agent) runLogTail(ctx context.Context, session string, lines int, handle *tailHandle) {
	defer func() {
		a.logTailMu.Lock()
		// Only delete if we're still the active tailer for this session.
		if a.logTail[session] == handle {
			delete(a.logTail, session)
		}
		a.logTailMu.Unlock()
	}()

	logPath := strings.TrimSpace(a.cfg.Logging.FilePath)
	if logPath == "" {
		a.emitLogTailClosed(session, "log file path not configured")
		return
	}

	f, err := os.Open(logPath)
	if err != nil {
		a.emitLogTailClosed(session, fmt.Sprintf("open log file: %v", err))
		return
	}
	defer func() { _ = f.Close() }()

	offset, err := a.emitLastLines(f, session, lines)
	if err != nil {
		a.emitLogTailClosed(session, fmt.Sprintf("read log: %v", err))
		return
	}

	ticker := time.NewTicker(350 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.emitLogTailClosed(session, "stopped")
			return
		case <-ticker.C:
			info, statErr := f.Stat()
			if statErr != nil {
				// Best-effort; keep trying.
				continue
			}
			size := info.Size()
			if size < offset {
				// Truncated/rotated. Re-open to reset to new file.
				_ = f.Close()
				f, err = os.Open(logPath)
				if err != nil {
					a.emitLogTailClosed(session, fmt.Sprintf("reopen log: %v", err))
					return
				}
				offset = 0
				_ = a.transport.Emit("log_tail_output", map[string]any{
					"session": session,
					"data":    "\n[log rotated]\n",
					"ts":      time.Now().UTC().Format(time.RFC3339Nano),
				})
				continue
			}
			if size == offset {
				continue
			}

			// Read up to 64KB per tick to avoid giant bursts.
			toRead := size - offset
			if toRead > 64*1024 {
				toRead = 64 * 1024
			}
			buf := make([]byte, toRead)
			if _, err := f.Seek(offset, io.SeekStart); err != nil {
				continue
			}
			n, err := io.ReadFull(f, buf)
			if err != nil && err != io.ErrUnexpectedEOF {
				continue
			}
			if n > 0 {
				offset += int64(n)
				a.emitLogTailOutput(session, string(buf[:n]))
			}
		}
	}
}

func (a *Agent) emitLastLines(f *os.File, session string, lines int) (int64, error) {
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	size := info.Size()
	if size <= 0 {
		return 0, nil
	}

	// Read a tail window that should comfortably include the last 10-ish lines
	// without slurping large logs. If lines is bigger, we still cap the read.
	const maxTailWindow = 256 * 1024
	const defaultTailWindow = 64 * 1024
	window := int64(defaultTailWindow)
	if lines > 50 {
		window = int64(maxTailWindow)
	}
	start := size - window
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return 0, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return 0, err
	}

	// Split and take last N non-empty lines (but preserve original line endings by re-adding '\n').
	raw := strings.Split(string(data), "\n")
	// Drop possible trailing empty line if file ends with newline.
	for len(raw) > 0 && raw[len(raw)-1] == "" {
		raw = raw[:len(raw)-1]
	}
	if len(raw) == 0 {
		return size, nil
	}
	if lines > len(raw) {
		lines = len(raw)
	}
	chunk := strings.Join(raw[len(raw)-lines:], "\n") + "\n"
	a.emitLogTailOutput(session, chunk)
	return size, nil
}

func (a *Agent) emitLogTailOutput(session string, data string) {
	_ = a.transport.Emit("log_tail_output", map[string]any{
		"session": session,
		"data":    data,
		"ts":      time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (a *Agent) emitLogTailClosed(session string, reason string) {
	_ = a.transport.Emit("log_tail_closed", map[string]any{
		"session": session,
		"reason":  reason,
		"ts":      time.Now().UTC().Format(time.RFC3339Nano),
	})
}

// ctxOrBackground is defined in agent.go; keep this file self-contained regarding tailing.
var _ = bufio.NewReader
