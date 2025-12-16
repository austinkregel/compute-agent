package app

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/austinkregel/compute-agent/pkg/admin"
	"github.com/austinkregel/compute-agent/pkg/backup"
	"github.com/austinkregel/compute-agent/pkg/config"
	"github.com/austinkregel/compute-agent/pkg/dirbrowse"
	"github.com/austinkregel/compute-agent/pkg/logging"
	"github.com/austinkregel/compute-agent/pkg/telemetry"
	"github.com/austinkregel/compute-agent/pkg/transport"
	"github.com/austinkregel/compute-agent/pkg/version"
)

var githubUserRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,39}$`)

var allowedSSHKeyTypes = map[string]struct{}{
	"ssh-ed25519":                        {},
	"ssh-rsa":                            {},
	"ecdsa-sha2-nistp256":                {},
	"ecdsa-sha2-nistp384":                {},
	"ecdsa-sha2-nistp521":                {},
	"sk-ssh-ed25519@openssh.com":         {},
	"sk-ecdsa-sha2-nistp256@openssh.com": {},
}

func isValidAuthorizedKeyLine(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}
	// Prevent DoS / log injection.
	if len(line) > 8192 {
		return false
	}
	// authorized_keys is line-oriented; reject embedded newlines/control chars.
	if strings.ContainsAny(line, "\r\n") {
		return false
	}

	fields := strings.Fields(line)
	if len(fields) < 2 {
		return false
	}
	if _, ok := allowedSSHKeyTypes[fields[0]]; !ok {
		return false
	}
	// Second field must be base64.
	if _, err := base64.StdEncoding.DecodeString(fields[1]); err != nil {
		return false
	}
	return true
}

// Agent wires together the Go subsystems that replace the legacy Node.js agent.
type Agent struct {
	cfg       *config.Config
	log       *logging.Logger
	transport *transport.Client
	telemetry *telemetry.Publisher
	admin     *admin.Runner
	backups   *backup.Coordinator

	ctx context.Context

	logTailMu sync.Mutex
	logTail   map[string]*tailHandle // session -> tail handle
}

// New assembles the agent subsystems from config.
func New(cfg *config.Config, log *logging.Logger) (*Agent, error) {
	agent := &Agent{
		cfg:     cfg,
		log:     log,
		logTail: map[string]*tailHandle{},
	}

	// Best-effort cleanup of old Windows executables left after an update.
	if exePath, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exePath); err == nil {
			cleanupOldExecutables(resolved)
		} else {
			cleanupOldExecutables(exePath)
		}
	} else {
		log.Debug("unable to resolve executable for cleanup", "error", err)
	}

	adminRunner := admin.NewRunner(cfg, log.With("component", "admin"), admin.ShellCallbacks{
		OnOutput: agent.emitShellOutput,
		OnClosed: agent.emitShellClosed,
	})

	handlers := transport.Handlers{
		Hello:        agent.handleHello,
		AdminRun:     agent.handleAdminRun,
		ShellStart:   agent.handleShellStart,
		ShellInput:   agent.handleShellInput,
		ShellResize:  agent.handleShellResize,
		ShellClose:   agent.handleShellClose,
		LogTailStart: agent.handleLogTailStart,
		LogTailStop:  agent.handleLogTailStop,
		BackupPlan:   agent.handleBackupPlan,
		BackupStart:  agent.handleBackupStart,
		SyncKeys:     agent.handleSyncKeys,
		UpdateAgent:  agent.handleAgentUpdate,
		CheckUpdates: agent.handleCheckUpdates,
		DirList:      agent.handleDirListRequest,
	}

	t, err := transport.New(transport.Config{
		ServerURL:         cfg.ServerURL,
		ClientID:          cfg.ClientID,
		AuthToken:         cfg.AuthToken,
		Namespace:         "/agents",
		SocketPath:        cfg.Transport.Path,
		SkipTLSVerify:     cfg.Transport.SkipTLSVerify,
		ReconnectMin:      time.Second,
		ReconnectMax:      30 * time.Second,
		HeartbeatInterval: time.Duration(cfg.HeartbeatIntervalSec) * time.Second,
		PongTimeout:       time.Duration(cfg.PongTimeoutSec) * time.Second,
	}, log.With("component", "transport"), handlers)
	if err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}

	backupCoord := backup.NewCoordinator(cfg, log.With("component", "backup"), t)
	pub := telemetry.NewPublisher(cfg, log.With("component", "telemetry"), t)

	agent.transport = t
	agent.telemetry = pub
	agent.admin = adminRunner
	agent.backups = backupCoord
	return agent, nil
}

// Run launches the long-lived agent event loop.
func (a *Agent) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	a.ctx = ctx

	errCh := make(chan error, 2)

	go func() { errCh <- a.transport.Run(ctx) }()
	go func() { errCh <- a.telemetry.Run(ctx) }()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		return ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *Agent) handleHello() {
	a.log.Info("connected to control plane", "clientId", a.cfg.ClientID)
	// Emit version/metadata immediately after hello_ack so dashboards don't wait for the next
	// telemetry tick to learn the agent version.
	if a.telemetry != nil {
		a.telemetry.EmitNow()
	}
	// Check for updates immediately if internet is available.
	go a.checkForUpdatesOnConnect()
}

// checkForUpdatesOnConnect checks for agent updates when connecting to the server.
// It only runs if internet connectivity is available and the agent is outdated.
func (a *Agent) checkForUpdatesOnConnect() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	currentVersion := version.Version
	// Skip update check for dev builds unless explicitly needed
	if currentVersion == "0.1.0-dev" || strings.Contains(currentVersion, "dev") {
		a.log.Debug("skipping update check for dev build", "version", currentVersion)
		return
	}

	// Default repo for agent updates
	repo := "austinkregel/compute-agent"

	// Use resolveLatestAsset to check for latest version (it handles GitHub API calls)
	// We pass empty desiredTag to get the latest release
	// Note: resolveLatestAsset is in update.go (same package, so we can call it directly)
	latestTag, _, _, _, err := resolveLatestAsset(ctx, repo, "")
	if err != nil {
		// No internet or GitHub unavailable - silently skip
		a.log.Debug("update check skipped", "reason", "no internet or GitHub unavailable", "error", err)
		return
	}

	if latestTag == "" {
		return
	}

	// Compare versions - if latest tag is different (and likely newer), trigger update
	if latestTag != currentVersion {
		a.log.Info("update available", "current", currentVersion, "latest", latestTag)
		// Trigger self-update
		result := a.trySelfUpdate(ctx, repo, latestTag)
		if !result.OK {
			a.log.Warn("auto-update failed", "tag", latestTag, "error", result.Error, "detail", result.Detail)
		}
	} else {
		a.log.Debug("agent is up to date", "version", currentVersion)
	}
}

func (a *Agent) handleAdminRun(msg transport.AdminCommand) {
	reqID := fmt.Sprintf("admin-%d", time.Now().UnixNano())
	cmdBase, cmdPreview, cmdTruncated := summarizeCommandForLog(msg.Cmd.Command)
	tokenSummary := summarizeTokenForLog(msg.Token)
	timeoutSec := msg.Cmd.TimeoutSec
	if timeoutSec <= 0 {
		timeoutSec = a.cfg.Admin.DefaultTimeoutSec
	}
	a.log.Info("admin_run received",
		"reqId", reqID,
		"commandBase", cmdBase,
		"commandPreview", cmdPreview,
		"commandTruncated", cmdTruncated,
		"cwd", strings.TrimSpace(msg.Cmd.Cwd),
		"timeoutSec", timeoutSec,
		"token", tokenSummary,
	)

	if a.cfg.Admin.RequireToken {
		expected := a.cfg.Admin.CommandToken
		if expected == "" || subtle.ConstantTimeCompare([]byte(msg.Token), []byte(expected)) != 1 {
			res := admin.CommandResult{
				Stderr: "unauthorized",
				Summary: admin.CommandSummary{
					Code: 401,
				},
				Error: "unauthorized",
			}
			if err := a.transport.Emit("admin_result", map[string]any{
				"token":   msg.Token,
				"command": msg.Cmd.Command,
				"result":  res,
			}); err != nil {
				a.log.Error("failed to emit admin_result for unauthorized admin_run", "reqId", reqID, "error", err)
			}
			a.log.Warn("blocked unauthorized admin_run", "reqId", reqID, "commandBase", cmdBase, "token", tokenSummary)
			return
		}
	}
	req := admin.CommandRequest{
		Token:   msg.Token,
		Command: msg.Cmd.Command,
		Cwd:     msg.Cmd.Cwd,
		Timeout: time.Duration(msg.Cmd.TimeoutSec) * time.Second,
	}
	res := a.admin.RunCommand(a.ctxOrBackground(), req)
	a.log.Info("admin_run completed",
		"reqId", reqID,
		"commandBase", cmdBase,
		"exitCode", res.Summary.Code,
		"durationMs", res.Summary.DurationMs,
		"stdoutBytes", len(res.Stdout),
		"stderrBytes", len(res.Stderr),
		"error", res.Error,
	)
	payload := map[string]any{
		"token":   msg.Token,
		"command": msg.Cmd.Command,
		"result":  res,
	}
	if err := a.transport.Emit("admin_result", payload); err != nil {
		a.log.Error("failed to emit admin_result", "reqId", reqID, "error", err)
	}
}

func (a *Agent) handleShellStart(msg transport.ShellStart) {
	if err := a.admin.StartShell(a.ctxOrBackground(), msg.Session); err != nil {
		a.emitShellClosed(msg.Session, 1, err.Error())
	}
}

func (a *Agent) handleShellInput(msg transport.ShellInput) {
	if err := a.admin.SendInput(msg.Session, msg.Data); err != nil {
		a.log.Error("shell input failed", "session", msg.Session, "error", err)
	}
}

func (a *Agent) handleShellResize(msg transport.ShellResize) {
	if err := a.admin.Resize(msg.Session, msg.Cols, msg.Rows); err != nil {
		a.log.Debug("shell resize failed", "session", msg.Session, "error", err)
	}
}

func (a *Agent) handleShellClose(msg transport.ShellClose) {
	if err := a.admin.CloseShell(msg.Session); err != nil {
		a.log.Debug("shell close failed", "session", msg.Session, "error", err)
	}
}

func (a *Agent) handleBackupPlan(msg transport.BackupRequest) {
	if err := a.backups.Plan(a.ctxOrBackground(), msg); err != nil {
		a.log.Error("backup plan failed", "planId", msg.PlanID, "error", err)
	}
}

func (a *Agent) handleBackupStart(msg transport.BackupRequest) {
	if err := a.backups.Run(a.ctxOrBackground(), msg); err != nil {
		a.log.Error("backup start failed", "planId", msg.PlanID, "error", err)
	}
}

func (a *Agent) handleSyncKeys(msg transport.SyncKeysRequest) {
	start := time.Now()
	result := map[string]any{
		"user": msg.User,
	}
	added, err := a.syncAuthorizedKeys(msg.User)
	if err != nil {
		result["ok"] = false
		result["error"] = err.Error()
	} else {
		result["ok"] = true
		result["added"] = added
		result["ms"] = time.Since(start).Milliseconds()
	}
	if err := a.transport.Emit("keys_sync_result", result); err != nil {
		a.log.Error("failed to emit keys_sync_result", "error", err)
	}
}

func (a *Agent) handleAgentUpdate(msg transport.UpdateAgentRequest) {
	// Run update asynchronously; downloading/extracting can take time.
	go func() {
		repo := strings.TrimSpace(msg.Repo)
		if repo == "" {
			repo = "austinkregel/compute-agent"
		}
		tag := strings.TrimSpace(msg.Tag)

		a.log.Info("agent update requested", "repo", repo, "tag", tag)
		result := a.trySelfUpdate(a.ctxOrBackground(), repo, tag)

		// Best-effort result emit. If we successfully exec() on unix, this won't run.
		_ = a.transport.Emit("agent_update_result", map[string]any{
			"ok":     result.OK,
			"repo":   repo,
			"tag":    result.Tag,
			"error":  result.Error,
			"detail": result.Detail,
			"ts":     time.Now().UTC().Format(time.RFC3339Nano),
		})
	}()
}

func (a *Agent) handleCheckUpdates(_ transport.CheckUpdatesRequest) {
	// Run asynchronously; update checks may touch package managers / Windows Update.
	go func() {
		if a.telemetry == nil {
			return
		}
		a.log.Info("manual update check requested")
		a.telemetry.CheckUpdatesNow()
	}()
}

func (a *Agent) handleDirListRequest(msg transport.DirListRequest) {
	ctx, cancel := context.WithTimeout(a.ctxOrBackground(), 15*time.Second)
	defer cancel()

	resp := a.buildDirListResponse(ctx, msg)
	if err := a.transport.Emit("dir_list_response", resp); err != nil {
		a.log.Error("failed to emit dir_list_response", "requestId", msg.RequestID, "error", err)
	}
}

func (a *Agent) buildDirListResponse(ctx context.Context, msg transport.DirListRequest) transport.DirListResponse {
	mode := strings.TrimSpace(msg.Mode)
	if mode == "" {
		mode = "local"
	}
	// Always respond with our configured client id; tolerate older payloads that omit it.
	clientID := a.cfg.ClientID

	resp := transport.DirListResponse{
		ClientID:  clientID,
		RequestID: msg.RequestID,
		Mode:      mode,
		Path:      strings.TrimSpace(msg.Path),
		Entries:   []transport.DirListEntry{},
	}

	switch mode {
	case "local":
		clean, err := dirbrowse.ValidateAbsoluteDirPath(msg.Path)
		if err != nil {
			resp.Error = err.Error()
			return resp
		}
		if err := dirbrowse.EnforceAllowedRoots(clean, a.cfg.DirBrowse.AllowedRoots); err != nil {
			resp.Error = err.Error()
			return resp
		}
		res, err := dirbrowse.ListLocal(ctx, clean, 0, 0)
		resp.Path = clean
		if err != nil {
			resp.Error = err.Error()
			return resp
		}
		resp.Path = res.Path
		resp.Entries = toTransportDirEntries(res.Entries)
		return resp

	case "remote":
		if strings.TrimSpace(msg.Host) == "" {
			resp.Error = "host is required for remote listing"
			return resp
		}
		proto := strings.TrimSpace(msg.Protocol)
		if proto == "" {
			proto = "ssh"
		}

		switch proto {
		case "ssh":
			res, err := dirbrowse.ListSSH(ctx, dirbrowse.SSHRequest{
				Host: msg.Host,
				User: msg.User,
				Port: msg.Port,
				Path: msg.Path,
			}, dirbrowse.SSHOptions{
				HostKeyPolicy: a.cfg.DirBrowse.SSHHostKeyPolicy,
			})
			if err != nil {
				resp.Error = err.Error()
				return resp
			}
			resp.Path = res.Path
			resp.Entries = toTransportDirEntries(res.Entries)
			return resp

		case "smb":
			share := strings.TrimSpace(msg.Share)
			if share == "" {
				resp.Error = "share is required for smb listing"
				return resp
			}
			profile := strings.TrimSpace(msg.Profile)
			if profile == "" {
				resp.Error = "profile is required for smb listing"
				return resp
			}
			p, ok := a.cfg.DirBrowse.SMBProfiles[profile]
			if !ok {
				resp.Error = "unknown smb profile"
				return resp
			}

			res, err := dirbrowse.ListSMB(ctx, dirbrowse.SMBRequest{
				Host:    msg.Host,
				Port:    msg.Port,
				Share:   share,
				Path:    msg.Path,
				Profile: profile,
			}, dirbrowse.SMBCredentials{
				Username: p.Username,
				Password: p.Password,
				Domain:   p.Domain,
			}, dirbrowse.SMBOptions{})
			if err != nil {
				resp.Error = err.Error()
				return resp
			}
			resp.Path = res.Path
			resp.Entries = toTransportDirEntries(res.Entries)
			return resp

		default:
			resp.Error = fmt.Sprintf("unsupported remote protocol %q", proto)
			return resp
		}

	default:
		resp.Error = fmt.Sprintf("invalid mode %q", mode)
		return resp
	}
}

func toTransportDirEntries(in []dirbrowse.Entry) []transport.DirListEntry {
	out := make([]transport.DirListEntry, 0, len(in))
	for _, e := range in {
		out = append(out, transport.DirListEntry{
			Name: e.Name,
			Type: e.Type,
			Size: e.Size,
		})
	}
	return out
}

func (a *Agent) emitShellOutput(session string, data []byte) {
	_ = a.transport.Emit("shell_output", map[string]any{
		"session": session,
		"data":    string(data),
	})
}

func (a *Agent) emitShellClosed(session string, code int, reason string) {
	_ = a.transport.Emit("shell_closed", map[string]any{
		"session": session,
		"code":    code,
		"reason":  reason,
	})
}

func (a *Agent) ctxOrBackground() context.Context {
	if a.ctx != nil {
		return a.ctx
	}
	return context.Background()
}

func summarizeTokenForLog(token string) string {
	t := strings.TrimSpace(token)
	if t == "" {
		return ""
	}
	if len(t) <= 10 {
		return t
	}
	// Avoid leaking full tokens into logs; keep enough for correlation.
	return t[:4] + "…" + t[len(t)-4:]
}

func summarizeCommandForLog(cmd string) (base string, preview string, truncated bool) {
	s := strings.TrimSpace(cmd)
	if s == "" {
		return "", "", false
	}

	// Special-case the cron update pipeline to avoid logging b64 payloads.
	if strings.Contains(s, "base64") && strings.Contains(s, "crontab") && strings.Contains(s, "echo") && strings.Contains(s, "|") {
		fields := strings.Fields(s)
		if len(fields) > 0 {
			base = fields[0]
		}
		return base, "cron update pipeline (redacted)", true
	}

	fields := strings.Fields(s)
	if len(fields) > 0 {
		base = fields[0]
	}

	const maxPreview = 120
	if len(s) > maxPreview {
		return base, s[:maxPreview] + "…", true
	}
	return base, s, false
}

func (a *Agent) syncAuthorizedKeys(user string) (int, error) {
	user = strings.TrimSpace(user)
	if !githubUserRe.MatchString(user) {
		return 0, fmt.Errorf("invalid github user %q", user)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	url := fmt.Sprintf("https://github.com/%s.keys", user)
	resp, err := client.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return 0, fmt.Errorf("github responded %s", resp.Status)
	}

	var keys []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		key := strings.TrimSpace(scanner.Text())
		if key != "" && isValidAuthorizedKeyLine(key) {
			keys = append(keys, key)
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	if len(keys) == 0 {
		return 0, errors.New("no valid keys found for user")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return 0, err
	}
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return 0, err
	}
	authFile := filepath.Join(sshDir, "authorized_keys")
	existing := make(map[string]struct{})
	var existingLines []string
	if data, err := os.ReadFile(authFile); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				existing[line] = struct{}{}
				existingLines = append(existingLines, line)
			}
		}
	}

	added := 0
	finalLines := append([]string{}, existingLines...)
	for _, key := range keys {
		if _, ok := existing[key]; ok {
			continue
		}
		finalLines = append(finalLines, key)
		added++
	}
	if added == 0 {
		return 0, nil
	}
	if err := writeAuthorizedKeysAtomically(authFile, finalLines); err != nil {
		return added, err
	}
	return added, nil
}

func writeAuthorizedKeysAtomically(path string, lines []string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "authorized_keys.tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	// Ensure restrictive perms even if umask is permissive.
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}

	content := strings.Join(lines, "\n") + "\n"
	if _, err := tmp.WriteString(content); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// Best-effort atomic replacement.
	if err := os.Rename(tmpName, path); err != nil {
		// Windows doesn't allow rename-over-existing; remove and retry.
		_ = os.Remove(path)
		if err2 := os.Rename(tmpName, path); err2 != nil {
			return err
		}
	}
	_ = os.Chmod(path, 0o600)
	return nil
}
