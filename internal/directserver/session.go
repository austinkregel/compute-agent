package directserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"nhooyr.io/websocket"

	"github.com/austinkregel/compute-agent/pkg/admin"
	"github.com/austinkregel/compute-agent/pkg/config"
	"github.com/austinkregel/compute-agent/pkg/dirbrowse"
	"github.com/austinkregel/compute-agent/pkg/fileops"
	"github.com/austinkregel/compute-agent/pkg/logging"
	"github.com/austinkregel/compute-agent/pkg/transport"
)

const (
	writeTimeout = 10 * time.Second
	getChunkSize = 256 * 1024
)

// Session is one authenticated direct connection. It owns a private emitter, an
// upload manager, and a shell runner so responses and PTY output route only to
// this connection — never fanned out to the control plane or other clients.
//
// The handled event set is a deliberate, minimal allow-list: file and shell
// operations only. Anything else (admin exec, fleet management, key sync,
// self-update, log tail) is intentionally absent.
type Session struct {
	conn     *websocket.Conn
	ctx      context.Context
	log      *logging.Logger
	clientID string
	roots    []string
	maxBytes int64

	uploads *fileops.UploadManager
	shell   *admin.Runner

	writeMu sync.Mutex

	shellMu sync.Mutex
	shells  map[string]bool
}

func newSession(ctx context.Context, conn *websocket.Conn, cfg *config.Config, log *logging.Logger, roots []string, maxBytes int64) *Session {
	s := &Session{
		conn:     conn,
		ctx:      ctx,
		log:      log,
		clientID: cfg.ClientID,
		roots:    roots,
		maxBytes: maxBytes,
		uploads:  fileops.NewUploadManager(),
		shells:   map[string]bool{},
	}
	// A per-connection shell runner whose output is bound to this session's
	// emitter, so PTY bytes can't leak to another connection.
	s.shell = admin.NewRunner(cfg, log, admin.ShellCallbacks{
		OnOutput: s.emitShellOutput,
		OnClosed: s.emitShellClosed,
	})
	return s
}

// dispatch routes one inbound frame. Unknown/forbidden events are ignored.
func (s *Session) dispatch(event string, data json.RawMessage) {
	switch event {
	case "pong", "ping":
		// keepalive; ignore (server-initiated pings are handled by the lib)
	case "dir_list_request":
		s.handleDirList(data)
	case "file_get_request":
		s.handleFileGet(data)
	case "file_put_start":
		s.handleFilePutStart(data)
	case "file_put_chunk":
		s.handleFilePutChunk(data)
	case "file_put_finish":
		s.handleFilePutFinish(data)
	case "file_delete_request":
		s.handleFileDelete(data)
	case "file_chmod_request":
		s.handleFileChmod(data)
	case "shell_start":
		s.handleShellStart(data)
	case "shell_input":
		s.handleShellInput(data)
	case "shell_resize":
		s.handleShellResize(data)
	case "shell_close":
		s.handleShellClose(data)
	default:
		s.log.Debug("direct: ignoring out-of-scope event", "event", event)
	}
}

func (s *Session) close() {
	s.shellMu.Lock()
	ids := make([]string, 0, len(s.shells))
	for id := range s.shells {
		ids = append(ids, id)
	}
	s.shellMu.Unlock()
	for _, id := range ids {
		_ = s.shell.CloseShell(id)
	}
}

// --- emit ---

func (s *Session) emit(event string, payload any) {
	frame := map[string]any{"event": event, "data": payload}
	b, err := json.Marshal(frame)
	if err != nil {
		return
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	ctx, cancel := context.WithTimeout(s.ctx, writeTimeout)
	defer cancel()
	if err := s.conn.Write(ctx, websocket.MessageText, b); err != nil {
		s.log.Debug("direct: emit failed", "event", event, "error", err)
	}
}

func (s *Session) emitShellOutput(session string, data []byte) {
	s.emit("shell_output", map[string]any{"session": session, "data": string(data)})
}

func (s *Session) emitShellClosed(session string, code int, reason string) {
	s.shellMu.Lock()
	delete(s.shells, session)
	s.shellMu.Unlock()
	s.emit("shell_closed", map[string]any{"session": session, "code": code, "reason": reason})
}

// --- path confinement ---

// confine validates that an absolute path falls within the allowed roots. Every
// file/dir operation goes through this; combined with force=false it keeps the
// dangerous-path guards in fileops live.
func (s *Session) confine(p string) (string, error) {
	if !filepath.IsAbs(p) {
		return "", errors.New("path must be absolute")
	}
	clean := filepath.Clean(p)
	if err := dirbrowse.EnforceAllowedRoots(clean, s.roots); err != nil {
		return "", err
	}
	return clean, nil
}

// --- file handlers ---

func (s *Session) handleDirList(data json.RawMessage) {
	var msg transport.DirListRequest
	if err := json.Unmarshal(data, &msg); err != nil {
		return
	}
	resp := transport.DirListResponse{
		ClientID:  s.clientID,
		RequestID: msg.RequestID,
		Mode:      "local",
		Path:      msg.Path,
		Entries:   []transport.DirListEntry{},
	}
	// Direct mode is local-only: no SSH/SMB pivot through the agent.
	if msg.Mode != "" && msg.Mode != "local" {
		resp.Error = "direct mode supports local listing only"
		s.emit("dir_list_response", resp)
		return
	}
	clean, err := dirbrowse.ValidateAbsoluteDirPath(msg.Path)
	if err != nil {
		resp.Error = err.Error()
		s.emit("dir_list_response", resp)
		return
	}
	if err := dirbrowse.EnforceAllowedRoots(clean, s.roots); err != nil {
		resp.Error = err.Error()
		s.emit("dir_list_response", resp)
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 15*time.Second)
	defer cancel()
	res, err := dirbrowse.ListLocal(ctx, clean, 0, 0)
	if err != nil {
		resp.Error = err.Error()
		s.emit("dir_list_response", resp)
		return
	}
	resp.Path = clean
	resp.Entries = toEntries(res.Entries)
	s.emit("dir_list_response", resp)
}

// fileGetRequest / chunk / result implement the read half of the file API,
// which the control-plane protocol lacks (see docs/PROTOCOL.md "PROTOCOL GAP").
type fileGetRequest struct {
	RequestID string `json:"requestId"`
	Path      string `json:"path"`
	MaxSize   int64  `json:"maxSize"`
}

func (s *Session) handleFileGet(data json.RawMessage) {
	var msg fileGetRequest
	if err := json.Unmarshal(data, &msg); err != nil {
		return
	}
	result := map[string]any{"clientId": s.clientID, "requestId": msg.RequestID, "path": msg.Path}
	fail := func(reason string) {
		result["ok"] = false
		result["error"] = reason
		s.emit("file_get_result", result)
	}

	clean, err := s.confine(msg.Path)
	if err != nil {
		fail(err.Error())
		return
	}
	info, err := os.Stat(clean)
	if err != nil {
		fail(err.Error())
		return
	}
	if info.IsDir() {
		fail("path is a directory")
		return
	}
	limit := s.maxBytes
	if msg.MaxSize > 0 && msg.MaxSize < limit {
		limit = msg.MaxSize
	}
	if limit > 0 && info.Size() > limit {
		fail(fmt.Sprintf("file is %d bytes, over the %d-byte limit", info.Size(), limit))
		return
	}

	f, err := os.Open(clean)
	if err != nil {
		fail(err.Error())
		return
	}
	defer f.Close()

	buf := make([]byte, getChunkSize)
	var offset int64
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			s.emit("file_get_chunk", map[string]any{
				"clientId":  s.clientID,
				"requestId": msg.RequestID,
				"offset":    offset,
				"data":      base64.StdEncoding.EncodeToString(buf[:n]),
			})
			offset += int64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			fail(readErr.Error())
			return
		}
	}
	result["ok"] = true
	result["size"] = offset
	s.emit("file_get_result", result)
}

func (s *Session) handleFilePutStart(data json.RawMessage) {
	var msg transport.FilePutStartRequest
	if err := json.Unmarshal(data, &msg); err != nil {
		return
	}
	result := transport.FilePutResult{ClientID: s.clientID, RequestID: msg.RequestID}
	clean, err := s.confine(msg.Path)
	if err != nil {
		result.Error = err.Error()
		s.emit("file_put_result", result)
		return
	}
	if s.maxBytes > 0 && msg.Size > s.maxBytes {
		result.Error = fmt.Sprintf("upload size %d exceeds limit %d", msg.Size, s.maxBytes)
		s.emit("file_put_result", result)
		return
	}
	// force is forced off — never escalate past the dangerous-path guards.
	if err := s.uploads.StartUpload(msg.RequestID, clean, msg.Size, msg.Mode, false, msg.Overwrite); err != nil {
		result.Error = err.Error()
		s.emit("file_put_result", result)
		return
	}
	result.OK = true
	result.Path = clean
	s.emit("file_put_result", result)
}

func (s *Session) handleFilePutChunk(data json.RawMessage) {
	var msg transport.FilePutChunk
	if err := json.Unmarshal(data, &msg); err != nil {
		return
	}
	if err := s.uploads.WriteChunk(msg.RequestID, msg.Offset, msg.Data); err != nil {
		s.uploads.CancelUpload(msg.RequestID)
		s.emit("file_put_result", transport.FilePutResult{
			ClientID:  s.clientID,
			RequestID: msg.RequestID,
			OK:        false,
			Error:     err.Error(),
		})
	}
}

func (s *Session) handleFilePutFinish(data json.RawMessage) {
	var msg transport.FilePutFinishRequest
	if err := json.Unmarshal(data, &msg); err != nil {
		return
	}
	result := transport.FilePutResult{ClientID: s.clientID, RequestID: msg.RequestID}
	path, size, err := s.uploads.FinishUpload(msg.RequestID, msg.Checksum)
	if err != nil {
		result.Error = err.Error()
		s.emit("file_put_result", result)
		return
	}
	result.OK = true
	result.Path = path
	result.Size = size
	s.emit("file_put_result", result)
}

func (s *Session) handleFileDelete(data json.RawMessage) {
	var msg transport.FileDeleteRequest
	if err := json.Unmarshal(data, &msg); err != nil {
		return
	}
	result := transport.FileDeleteResult{ClientID: s.clientID, RequestID: msg.RequestID, Path: msg.Path}
	clean, err := s.confine(msg.Path)
	if err != nil {
		result.Error = err.Error()
		s.emit("file_delete_result", result)
		return
	}
	if err := fileops.DeleteFile(clean, false, msg.Recursive); err != nil {
		result.Error = err.Error()
		s.emit("file_delete_result", result)
		return
	}
	result.OK = true
	s.emit("file_delete_result", result)
}

func (s *Session) handleFileChmod(data json.RawMessage) {
	var msg transport.FileChmodRequest
	if err := json.Unmarshal(data, &msg); err != nil {
		return
	}
	result := transport.FileChmodResult{ClientID: s.clientID, RequestID: msg.RequestID}
	clean, err := s.confine(msg.Path)
	if err != nil {
		result.Error = err.Error()
		s.emit("file_chmod_result", result)
		return
	}
	path, err := fileops.ChmodFile(clean, msg.Mode, false)
	if err != nil {
		result.Error = err.Error()
		s.emit("file_chmod_result", result)
		return
	}
	result.OK = true
	result.Path = path
	result.Mode = msg.Mode
	s.emit("file_chmod_result", result)
}

// --- shell handlers ---

func (s *Session) handleShellStart(data json.RawMessage) {
	var msg transport.ShellStart
	if err := json.Unmarshal(data, &msg); err != nil {
		return
	}
	s.shellMu.Lock()
	s.shells[msg.Session] = true
	s.shellMu.Unlock()
	if err := s.shell.StartShell(s.ctx, msg.Session); err != nil {
		s.emitShellClosed(msg.Session, 1, err.Error())
	}
}

func (s *Session) handleShellInput(data json.RawMessage) {
	var msg transport.ShellInput
	if err := json.Unmarshal(data, &msg); err != nil {
		return
	}
	if err := s.shell.SendInput(msg.Session, msg.Data); err != nil {
		s.log.Debug("direct: shell input failed", "session", msg.Session, "error", err)
	}
}

func (s *Session) handleShellResize(data json.RawMessage) {
	var msg transport.ShellResize
	if err := json.Unmarshal(data, &msg); err != nil {
		return
	}
	if err := s.shell.Resize(msg.Session, msg.Cols, msg.Rows); err != nil {
		s.log.Debug("direct: shell resize failed", "session", msg.Session, "error", err)
	}
}

func (s *Session) handleShellClose(data json.RawMessage) {
	var msg transport.ShellClose
	if err := json.Unmarshal(data, &msg); err != nil {
		return
	}
	if err := s.shell.CloseShell(msg.Session); err != nil {
		s.log.Debug("direct: shell close failed", "session", msg.Session, "error", err)
	}
}

func toEntries(in []dirbrowse.Entry) []transport.DirListEntry {
	out := make([]transport.DirListEntry, 0, len(in))
	for _, e := range in {
		out = append(out, transport.DirListEntry{
			Name:       e.Name,
			Type:       e.Type,
			Size:       e.Size,
			Mode:       e.Mode,
			ModTime:    e.ModTime,
			IsSymlink:  e.IsSymlink,
			LinkTarget: e.LinkTarget,
		})
	}
	return out
}
