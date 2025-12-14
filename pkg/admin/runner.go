package admin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"

	"github.com/austinkregel/compute-agent/pkg/config"
	"github.com/austinkregel/compute-agent/pkg/logging"
)

// ErrShellDisabled is returned when shell access is disabled in config.
var ErrShellDisabled = errors.New("shell access disabled")

var cronUpdatePipelineRe = regexp.MustCompile(`^\s*echo\s+['"]?([A-Za-z0-9+/=]+)['"]?\s*\|\s*base64\s+-d\s*\|\s*crontab\s+-\s*$`)

// Runner executes ad-hoc commands (`admin_run`) and interactive shells.
type Runner struct {
	cfg       *config.Config
	log       *logging.Logger
	callbacks ShellCallbacks

	slots chan struct{}

	sessionsMu sync.RWMutex
	sessions   map[string]*shellSession

	allowed [][]string

	rateMu          sync.Mutex
	rateWindowStart time.Time
	rateCount       int
}

// ShellCallbacks capture PTY output + lifecycle hooks.
type ShellCallbacks struct {
	OnOutput func(session string, data []byte)
	OnClosed func(session string, exitCode int, reason string)
}

// CommandRequest represents a server-issued admin command.
type CommandRequest struct {
	Token   string
	Command string
	Timeout time.Duration
	Cwd     string
}

// CommandResult mirrors the payload expected by the control plane.
type CommandResult struct {
	Stdout  string         `json:"stdout"`
	Stderr  string         `json:"stderr"`
	Summary CommandSummary `json:"summary"`
	Error   string         `json:"error,omitempty"`
}

// CommandSummary captures exit metadata.
type CommandSummary struct {
	Code       int   `json:"code"`
	DurationMs int64 `json:"durationMs"`
}

type shellSession struct {
	id      string
	cmd     *exec.Cmd
	cancel  context.CancelFunc
	stdin   io.Writer
	resize  func(int, int) error
	closer  io.Closer
	done    chan struct{}
	started time.Time
}

// NewRunner constructs an admin runner.
func NewRunner(cfg *config.Config, log *logging.Logger, callbacks ShellCallbacks) *Runner {
	if callbacks.OnOutput == nil {
		callbacks.OnOutput = func(string, []byte) {}
	}
	if callbacks.OnClosed == nil {
		callbacks.OnClosed = func(string, int, string) {}
	}

	var allowed [][]string
	for _, entry := range cfg.Admin.Allowed {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		toks, err := tokenizeCommandLine(entry)
		if err != nil || len(toks) == 0 {
			log.Debug("invalid allowed command entry; ignoring", "entry", entry, "error", err)
			continue
		}
		allowed = append(allowed, toks)
	}

	return &Runner{
		cfg:       cfg,
		log:       log,
		callbacks: callbacks,
		slots:     make(chan struct{}, max(1, cfg.Admin.MaxConcurrent)),
		sessions:  make(map[string]*shellSession),
		allowed:   allowed,
	}
}

// RunCommand executes a non-interactive command and returns stdout/stderr plus exit metadata.
func (r *Runner) RunCommand(ctx context.Context, req CommandRequest) CommandResult {
	if strings.TrimSpace(req.Command) == "" {
		return CommandResult{Error: "empty command", Summary: CommandSummary{Code: 1}}
	}

	if !r.allowRequest() {
		return CommandResult{
			Error:  "rate limited",
			Stderr: "rate limited",
			Summary: CommandSummary{
				Code: 429,
			},
		}
	}

	// Special-case: cron update pipeline used by the server today:
	// `echo <b64> | base64 -d | crontab -`
	//
	// We implement this natively to preserve behavior without allowing arbitrary pipes.
	if decoded, ok := parseCronUpdatePipeline(req.Command); ok {
		return r.runCrontabApply(ctx, req, decoded)
	}

	if hasForbiddenShellChars(req.Command) {
		return CommandResult{
			Error:  "command contains forbidden characters",
			Stderr: "command blocked: forbidden characters",
			Summary: CommandSummary{
				Code: 126,
			},
		}
	}

	cmdTokens, err := tokenizeCommandLine(req.Command)
	if err != nil || len(cmdTokens) == 0 {
		return CommandResult{
			Error:  fmt.Sprintf("invalid command: %v", err),
			Stderr: "command blocked: invalid command",
			Summary: CommandSummary{
				Code: 126,
			},
		}
	}

	if !r.isAllowed(cmdTokens) {
		return CommandResult{
			Error:  "command not allowed",
			Stderr: "command blocked by allowlist",
			Summary: CommandSummary{
				Code: 126,
			},
		}
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = time.Duration(r.cfg.Admin.DefaultTimeoutSec) * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := r.acquire(ctx); err != nil {
		return CommandResult{Error: err.Error(), Summary: CommandSummary{Code: 1}}
	}
	defer r.release()

	cmd := exec.CommandContext(ctx, cmdTokens[0], cmdTokens[1:]...)
	cmd.Env = sanitizedEnv()
	if strings.TrimSpace(req.Cwd) != "" {
		abs, err := filepath.Abs(req.Cwd)
		if err != nil {
			return CommandResult{
				Error:  fmt.Sprintf("invalid cwd: %v", err),
				Stderr: "command blocked: invalid cwd",
				Summary: CommandSummary{
					Code: 126,
				},
			}
		}
		abs = filepath.Clean(abs)
		if !r.isAllowedCwd(abs) {
			return CommandResult{
				Error:  "cwd not allowed",
				Stderr: "command blocked: cwd not allowed",
				Summary: CommandSummary{
					Code: 126,
				},
			}
		}
		cmd.Dir = abs
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	runErr := cmd.Run()
	duration := time.Since(start)

	code := 0
	if runErr != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			code = 124
		} else if exitErr, ok := runErr.(*exec.ExitError); ok {
			code = exitStatus(exitErr)
		} else if errors.Is(runErr, context.DeadlineExceeded) {
			code = 124
		} else {
			code = 1
		}
	}

	res := CommandResult{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
		Summary: CommandSummary{
			Code:       code,
			DurationMs: duration.Milliseconds(),
		},
	}
	if runErr != nil {
		res.Error = runErr.Error()
	}
	return res
}

func parseCronUpdatePipeline(cmd string) ([]byte, bool) {
	m := cronUpdatePipelineRe.FindStringSubmatch(cmd)
	if m == nil || len(m) < 2 {
		return nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(m[1])
	if err != nil {
		return nil, false
	}
	return decoded, true
}

func (r *Runner) runCrontabApply(ctx context.Context, req CommandRequest, cronText []byte) CommandResult {
	// Enforce allowlist policy (mirrors required command-allow behavior).
	if !r.isAllowed([]string{"crontab", "-"}) {
		return CommandResult{
			Error:  "command not allowed",
			Stderr: "command blocked by allowlist",
			Summary: CommandSummary{
				Code: 126,
			},
		}
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = time.Duration(r.cfg.Admin.DefaultTimeoutSec) * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := r.acquire(ctx); err != nil {
		return CommandResult{Error: err.Error(), Summary: CommandSummary{Code: 1}}
	}
	defer r.release()

	cmd := exec.CommandContext(ctx, "crontab", "-")
	cmd.Env = sanitizedEnv()

	if strings.TrimSpace(req.Cwd) != "" {
		abs, err := filepath.Abs(req.Cwd)
		if err != nil {
			return CommandResult{
				Error:  fmt.Sprintf("invalid cwd: %v", err),
				Stderr: "command blocked: invalid cwd",
				Summary: CommandSummary{
					Code: 126,
				},
			}
		}
		abs = filepath.Clean(abs)
		if !r.isAllowedCwd(abs) {
			return CommandResult{
				Error:  "cwd not allowed",
				Stderr: "command blocked: cwd not allowed",
				Summary: CommandSummary{
					Code: 126,
				},
			}
		}
		cmd.Dir = abs
	}

	cmd.Stdin = bytes.NewReader(cronText)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	runErr := cmd.Run()
	duration := time.Since(start)

	code := 0
	if runErr != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			code = 124
		} else if exitErr, ok := runErr.(*exec.ExitError); ok {
			code = exitStatus(exitErr)
		} else if errors.Is(runErr, context.DeadlineExceeded) {
			code = 124
		} else {
			code = 1
		}
	}

	res := CommandResult{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
		Summary: CommandSummary{
			Code:       code,
			DurationMs: duration.Milliseconds(),
		},
	}
	if runErr != nil {
		res.Error = runErr.Error()
	}
	return res
}

// StartShell launches an interactive shell session.
func (r *Runner) StartShell(ctx context.Context, sessionID string) error {
	if !r.cfg.Admin.EnableShell {
		return ErrShellDisabled
	}
	if !r.allowRequest() {
		return errors.New("rate limited")
	}
	if sessionID == "" {
		return errors.New("session id required")
	}
	if err := r.acquire(ctx); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(ctx, r.cfg.Shell.Command, r.cfg.Shell.Args...)
	cmd.Env = sanitizedEnv()

	sess := &shellSession{
		id:      sessionID,
		cmd:     cmd,
		cancel:  cancel,
		done:    make(chan struct{}),
		started: time.Now(),
	}

	var (
		stdio io.ReadWriteCloser
		err   error
	)
	if runtime.GOOS == "windows" {
		// Fallback to pipes; still functional for most shells.
		stdin, serr := cmd.StdinPipe()
		if serr != nil {
			r.release()
			return serr
		}
		stdout, serr := cmd.StdoutPipe()
		if serr != nil {
			r.release()
			return serr
		}
		cmd.Stderr = cmd.Stdout
		if err = cmd.Start(); err != nil {
			r.release()
			return err
		}
		sess.stdin = stdin
		sess.resize = func(int, int) error { return nil }
		go r.pipeOutput(sessionID, stdout, sess)
	} else {
		stdio, err = pty.Start(cmd)
		if err != nil {
			r.release()
			return err
		}
		ptmx, ok := stdio.(*os.File)
		if !ok {
			r.release()
			return errors.New("unexpected pty type")
		}
		sess.stdin = ptmx
		sess.closer = ptmx
		sess.resize = func(cols, rows int) error {
			if cols <= 0 || rows <= 0 {
				return nil
			}
			return pty.Setsize(ptmx, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
		}
		go r.pipeOutput(sessionID, ptmx, sess)
	}

	r.sessionsMu.Lock()
	r.sessions[sessionID] = sess
	r.sessionsMu.Unlock()

	go r.waitForShell(sessionID, sess)
	return nil
}

// SendInput writes bytes to the PTY stdin.
func (r *Runner) SendInput(sessionID, data string) error {
	sess := r.getSession(sessionID)
	if sess == nil {
		return errors.New("unknown session")
	}
	if _, err := io.WriteString(sess.stdin, data); err != nil {
		return err
	}
	return nil
}

// Resize adjusts the PTY window (best effort).
func (r *Runner) Resize(sessionID string, cols, rows int) error {
	sess := r.getSession(sessionID)
	if sess == nil {
		return errors.New("unknown session")
	}
	if sess.resize != nil {
		return sess.resize(cols, rows)
	}
	return nil
}

// CloseShell terminates the PTY session.
func (r *Runner) CloseShell(sessionID string) error {
	sess := r.removeSession(sessionID)
	if sess == nil {
		return nil
	}
	defer r.release()
	sess.cancel()
	if sess.closer != nil {
		_ = sess.closer.Close()
	}
	return nil
}

func (r *Runner) waitForShell(sessionID string, sess *shellSession) {
	err := sess.cmd.Wait()
	code := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitStatus(exitErr)
		} else {
			code = 1
		}
	}
	r.removeSession(sessionID)
	r.release()
	close(sess.done)

	reason := "exit"
	if err != nil {
		reason = err.Error()
	}
	r.callbacks.OnClosed(sessionID, code, reason)
}

func (r *Runner) pipeOutput(sessionID string, reader io.Reader, sess *shellSession) {
	buf := bufio.NewReader(reader)
	tmp := make([]byte, 4096)
	for {
		n, err := buf.Read(tmp)
		if n > 0 {
			data := make([]byte, n)
			copy(data, tmp[:n])
			r.callbacks.OnOutput(sessionID, data)
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				r.log.Debug("shell output stream closed", "session", sessionID, "error", err)
			}
			return
		}
	}
}

func (r *Runner) acquire(ctx context.Context) error {
	select {
	case r.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Runner) release() {
	select {
	case <-r.slots:
	default:
	}
}

func (r *Runner) getSession(sessionID string) *shellSession {
	r.sessionsMu.RLock()
	defer r.sessionsMu.RUnlock()
	return r.sessions[sessionID]
}

func (r *Runner) removeSession(sessionID string) *shellSession {
	r.sessionsMu.Lock()
	defer r.sessionsMu.Unlock()
	sess, ok := r.sessions[sessionID]
	if ok {
		delete(r.sessions, sessionID)
	}
	return sess
}

func (r *Runner) isAllowed(tokens []string) bool {
	if len(r.allowed) == 0 {
		return true
	}
	cmdNorm := normalizeTokens(tokens)
	for _, allowed := range r.allowed {
		allowedNorm := normalizeTokens(allowed)
		if len(cmdNorm) < len(allowedNorm) {
			continue
		}
		match := true
		for i := range allowedNorm {
			if cmdNorm[i] != allowedNorm[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func normalizeTokens(tokens []string) []string {
	out := make([]string, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, strings.ToLower(strings.TrimSpace(t)))
	}
	return out
}

func hasForbiddenShellChars(s string) bool {
	// Very conservative: disallow the typical shell metacharacters used for
	// chaining/expansion/redirection, even if quoted.
	//
	// This is defense-in-depth; the primary safety improvement is moving away from
	// `/bin/sh -c` entirely (done in the next hardening step).
	if strings.Contains(s, "&&") || strings.Contains(s, "||") {
		return true
	}
	for _, r := range s {
		switch r {
		case ';', '|', '`', '$', '\n', '\r':
			return true
		}
	}
	return false
}

// tokenizeCommandLine splits a command line into argv tokens with basic support
// for single/double quotes and backslash escapes. It does not perform variable
// expansion or globbing.
func tokenizeCommandLine(s string) ([]string, error) {
	var (
		out      []string
		cur      strings.Builder
		inSingle bool
		inDouble bool
		escaped  bool
	)

	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}

	for _, ch := range s {
		if escaped {
			cur.WriteRune(ch)
			escaped = false
			continue
		}
		if ch == '\\' && !inSingle {
			escaped = true
			continue
		}
		if ch == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if ch == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}

		if !inSingle && !inDouble {
			if ch == ' ' || ch == '\t' {
				flush()
				continue
			}
		}
		cur.WriteRune(ch)
	}

	if escaped {
		return nil, errors.New("dangling escape")
	}
	if inSingle || inDouble {
		return nil, errors.New("unclosed quote")
	}
	flush()

	return out, nil
}

func sanitizedEnv() []string {
	// Intentionally minimal, to reduce leakage of secrets into child processes.
	// Add variables here only when needed for basic command behavior.
	allow := []string{
		"PATH",
		"HOME",
		"USER",
		"LANG",
		"LC_ALL",
		"TERM",
		"TMPDIR",
		"TEMP",
		"SystemRoot", // Windows
		"ComSpec",    // Windows
	}
	out := make([]string, 0, len(allow))
	for _, key := range allow {
		if val, ok := os.LookupEnv(key); ok {
			out = append(out, key+"="+val)
		}
	}
	return out
}

func (r *Runner) allowRequest() bool {
	max := r.cfg.Admin.RateLimitMax
	if max <= 0 {
		return true
	}
	window := time.Duration(r.cfg.Admin.RateLimitWindowSec) * time.Second
	if window <= 0 {
		window = time.Minute
	}

	now := time.Now()
	r.rateMu.Lock()
	defer r.rateMu.Unlock()

	if r.rateWindowStart.IsZero() || now.Sub(r.rateWindowStart) >= window {
		r.rateWindowStart = now
		r.rateCount = 0
	}
	if r.rateCount >= max {
		return false
	}
	r.rateCount++
	return true
}

func (r *Runner) isAllowedCwd(absCwd string) bool {
	if len(r.cfg.Admin.AllowedCwds) == 0 {
		return false
	}
	for _, root := range r.cfg.Admin.AllowedCwds {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		absRoot, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		absRoot = filepath.Clean(absRoot)
		if isWithin(absRoot, absCwd) {
			return true
		}
	}
	return false
}

func isWithin(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	rel = filepath.Clean(rel)
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")
}

func exitStatus(err *exec.ExitError) int {
	if status, ok := err.Sys().(syscall.WaitStatus); ok {
		return status.ExitStatus()
	}
	return 1
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
