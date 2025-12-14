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
	"time"

	"github.com/austinkregel/compute-agent/pkg/admin"
	"github.com/austinkregel/compute-agent/pkg/backup"
	"github.com/austinkregel/compute-agent/pkg/config"
	"github.com/austinkregel/compute-agent/pkg/logging"
	"github.com/austinkregel/compute-agent/pkg/telemetry"
	"github.com/austinkregel/compute-agent/pkg/transport"
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
}

// New assembles the agent subsystems from config.
func New(cfg *config.Config, log *logging.Logger) (*Agent, error) {
	agent := &Agent{
		cfg: cfg,
		log: log,
	}

	adminRunner := admin.NewRunner(cfg, log.With("component", "admin"), admin.ShellCallbacks{
		OnOutput: agent.emitShellOutput,
		OnClosed: agent.emitShellClosed,
	})

	handlers := transport.Handlers{
		Hello:       agent.handleHello,
		AdminRun:    agent.handleAdminRun,
		ShellStart:  agent.handleShellStart,
		ShellInput:  agent.handleShellInput,
		ShellResize: agent.handleShellResize,
		ShellClose:  agent.handleShellClose,
		BackupPlan:  agent.handleBackupPlan,
		BackupStart: agent.handleBackupStart,
		SyncKeys:    agent.handleSyncKeys,
	}

	t, err := transport.New(transport.Config{
		ServerURL:     cfg.ServerURL,
		ClientID:      cfg.ClientID,
		AuthToken:     cfg.AuthToken,
		Namespace:     "/agents",
		SocketPath:    cfg.Transport.Path,
		SkipTLSVerify: cfg.Transport.SkipTLSVerify,
		ReconnectMin:  time.Second,
		ReconnectMax:  30 * time.Second,
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
}

func (a *Agent) handleAdminRun(msg transport.AdminCommand) {
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
			_ = a.transport.Emit("admin_result", map[string]any{
				"token":   msg.Token,
				"command": msg.Cmd.Command,
				"result":  res,
			})
			a.log.Warn("blocked unauthorized admin_run", "command", msg.Cmd.Command)
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
	payload := map[string]any{
		"token":   msg.Token,
		"command": msg.Cmd.Command,
		"result":  res,
	}
	if err := a.transport.Emit("admin_result", payload); err != nil {
		a.log.Error("failed to emit admin_result", "error", err)
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
	if data, err := os.ReadFile(authFile); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				existing[line] = struct{}{}
			}
		}
	}

	file, err := os.OpenFile(authFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	added := 0
	for _, key := range keys {
		if _, ok := existing[key]; ok {
			continue
		}
		if _, err := file.WriteString(key + "\n"); err != nil {
			return added, err
		}
		added++
	}
	return added, nil
}
