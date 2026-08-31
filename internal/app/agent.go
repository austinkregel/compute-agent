package app

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/austinkregel/compute-agent/internal/directserver"
	"github.com/austinkregel/compute-agent/internal/kiosk"
	"github.com/austinkregel/compute-agent/pkg/admin"
	"github.com/austinkregel/compute-agent/pkg/backup"
	"github.com/austinkregel/compute-agent/pkg/capability"
	"github.com/austinkregel/compute-agent/pkg/config"
	"github.com/austinkregel/compute-agent/pkg/dirbrowse"
	"github.com/austinkregel/compute-agent/pkg/docker"
	"github.com/austinkregel/compute-agent/pkg/fileops"
	"github.com/austinkregel/compute-agent/pkg/logging"
	"github.com/austinkregel/compute-agent/pkg/telemetry"
	"github.com/austinkregel/compute-agent/pkg/telephony"
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
	uploads   *fileops.UploadManager
	kiosk     kiosk.Manager
	direct    *directserver.Server
	caps      *capability.Registry
	telephony *telephony.Manager

	ctx context.Context

	logTailMu sync.Mutex
	logTail   map[string]*tailHandle // session -> tail handle

	// execMu guards execCancels: in-flight exec_request id -> cancel func, so an
	// exec_cancel can kill a running command (the IDE agent loop's Stop).
	execMu      sync.Mutex
	execCancels map[string]context.CancelFunc
}

// New assembles the agent subsystems from config.
func New(cfg *config.Config, log *logging.Logger) (*Agent, error) {
	agent := &Agent{
		cfg:         cfg,
		log:         log,
		logTail:     map[string]*tailHandle{},
		uploads:     fileops.NewUploadManager(),
		execCancels: map[string]context.CancelFunc{},
		caps:        capability.New(),
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
		Hello:           agent.handleHello,
		AdminRun:        agent.handleAdminRun,
		ShellStart:      agent.handleShellStart,
		ShellInput:      agent.handleShellInput,
		ShellResize:     agent.handleShellResize,
		ShellClose:      agent.handleShellClose,
		LogTailStart:    agent.handleLogTailStart,
		LogTailStop:     agent.handleLogTailStop,
		BackupPlan:      agent.handleBackupPlan,
		BackupStart:     agent.handleBackupStart,
		SyncKeys:        agent.handleSyncKeys,
		UpdateAgent:     agent.handleAgentUpdate,
		SwitchVariant:   agent.handleSwitchVariant,
		CheckUpdates:    agent.handleCheckUpdates,
		DirList:         agent.handleDirListRequest,
		Exec:            agent.handleExecRequest,
		ExecCancel:      agent.handleExecCancel,
		ExecAllowlist:   agent.handleExecAllowlist,
		FileGet:         agent.handleFileGetRequest,
		FilePutStart:    agent.handleFilePutStart,
		FilePutChunk:    agent.handleFilePutChunk,
		FilePutFinish:   agent.handleFilePutFinish,
		FileDelete:      agent.handleFileDelete,
		FileChmod:       agent.handleFileChmod,
		FileMkdir:       agent.handleFileMkdir,
		FileRename:      agent.handleFileRename,
		KioskSet:        agent.handleKioskSet,
		KioskSaveLayout: agent.handleKioskSaveLayout,
		KioskGetLayouts: agent.handleKioskGetLayouts,

		SwarmInfo:        agent.handleSwarmInfo,
		SwarmInit:        agent.handleSwarmInit,
		SwarmJoin:        agent.handleSwarmJoin,
		SwarmLeave:       agent.handleSwarmLeave,
		SwarmNodeList:    agent.handleSwarmNodeList,
		SwarmServiceList: agent.handleSwarmServiceList,
		SwarmServiceLogs: agent.handleSwarmServiceLogs,
		SwarmNetworkList: agent.handleSwarmNetworkList,
		SwarmStackList:   agent.handleSwarmStackList,

		ContainerInventory: agent.handleContainerInventory,
		StackStatus:        agent.handleStackStatus,
		ComposeScan:        agent.handleComposeScan,
		ComposeParse:       agent.handleComposeParse,
		ContainerLogs:      agent.handleContainerLogs,

		SMSSend:            agent.handleSMSSend,
		SMSThreadRequest:   agent.handleSMSThreadRequest,
		SMSMessagesRequest: agent.handleSMSMessagesRequest,
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
		MaxClockSkew:      time.Duration(cfg.Transport.MaxClockSkewSec) * time.Second,
	}, log.With("component", "transport"), handlers)
	if err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}
	t.CapabilityGate = agent.caps.Has

	backupCoord := backup.NewCoordinator(cfg, log.With("component", "backup"), t)
	pub := telemetry.NewPublisher(cfg, log.With("component", "telemetry"), t)

	// Wire Docker client if enabled
	var dc *docker.Client
	if cfg.Docker.Enabled {
		dc = docker.NewClient(cfg.Docker.SocketPath)
		if dc != nil {
			log.Info("docker integration enabled", "available", dc.Available())
			pub.SetDockerClient(dc)
		} else {
			log.Info("docker integration enabled but daemon unavailable; degrading gracefully")
		}
	}
	agent.caps.Register(dockerCap{enabled: cfg.Docker.Enabled, client: dc})
	agent.caps.Register(batteryCap{})
	agent.caps.Register(thermalCap{})
	agent.caps.Register(fileCap{})

	// Wire the Android companion app bridge if enabled (phone-class agents only).
	if cfg.Telephony.Enabled {
		agent.telephony = telephony.NewManager(
			telephony.Config{
				CompanionAddr:  cfg.Telephony.CompanionAddr,
				CompanionToken: cfg.Telephony.CompanionToken,
			},
			log.With("component", "telephony"),
			t.Emit,
		)
	}
	agent.caps.Register(telephonyCap{enabled: cfg.Telephony.Enabled, mgr: agent.telephony})

	agent.transport = t
	agent.telemetry = pub
	agent.admin = adminRunner
	agent.backups = backupCoord

	// Initialize kiosk subsystem if enabled
	if cfg.Kiosk.Enabled {
		if !kiosk.IsAvailable() {
			log.Warn("kiosk mode requested but not available in this binary",
				"hint", "use the kiosk variant binary (-kiosk) or rebuild with CGO_ENABLED=1")
		} else {
			kioskMgr, err := kiosk.New(kiosk.Config{
				ListenAddr: cfg.Kiosk.ListenAddr,
				Fullscreen: cfg.Kiosk.Fullscreen,
			}, log.With("component", "kiosk"), agent.handleKioskStatus, ".")
			if err != nil {
				log.Error("kiosk initialization failed", "error", err,
					"hint", "check that required GUI libraries are installed")
			} else {
				agent.kiosk = kioskMgr
			}
		}
	}

	agent.caps.Register(kioskCap{mgr: agent.kiosk})

	// Wire telemetry stats to kiosk dashboard view
	if agent.kiosk != nil {
		pub.OnSample = func(raw []byte) {
			agent.kiosk.PushStats(raw)
		}
	}

	// Optional inbound listener for direct IDE connections. Misconfiguration is
	// non-fatal: log and leave it disabled so the control-plane path still runs.
	var directStartErr error
	if cfg.DirectMode.Enabled {
		ds, err := directserver.New(cfg, log.With("component", "directmode"))
		if err != nil {
			log.Error("direct mode enabled but misconfigured; not starting", "error", err)
			directStartErr = err
		} else {
			agent.direct = ds
			// Advertise the direct endpoint in telemetry so the IDE can attempt a
			// P2P connection (control plane copies it into client_list).
			pub.DirectAdvert = func() *telemetry.DirectAdvert {
				adv, err := ds.Advert()
				if err != nil {
					log.Debug("direct advert unavailable", "error", err)
					return nil
				}
				return &telemetry.DirectAdvert{
					Addr:        adv.Addr,
					CertSha256:  adv.CertSha256,
					PinRequired: adv.PinRequired,
					Scheme:      adv.Scheme,
				}
			}
		}
	}
	agent.caps.Register(directCap{enabled: cfg.DirectMode.Enabled, server: agent.direct, startErr: directStartErr})

	// Initial capability probe so the first stats tick already reflects host
	// state, then wire the ongoing hook telemetry calls each tick.
	probeCtx, cancelProbe := context.WithTimeout(context.Background(), 10*time.Second)
	agent.caps.ProbeAll(probeCtx)
	cancelProbe()
	pub.Capabilities = func() map[string]capability.Info {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		agent.caps.RefreshDynamic(ctx)
		return agent.caps.Snapshot()
	}

	return agent, nil
}

// Run launches the long-lived agent event loop.
func (a *Agent) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	a.ctx = ctx

	errCh := make(chan error, 4)

	go func() { errCh <- a.transport.Run(ctx) }()
	go func() { errCh <- a.telemetry.Run(ctx) }()

	go a.runDockerEventWatcher()
	go a.runContainerMetricsEmitter()

	if a.direct != nil {
		go func() {
			if err := a.direct.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				a.log.Error("direct mode listener error", "error", err)
				errCh <- err
			}
		}()
	}

	// Start kiosk subsystem if enabled
	if a.kiosk != nil {
		go func() {
			if err := a.kiosk.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				a.log.Error("kiosk subsystem error", "error", err)
				errCh <- err
			}
		}()
	}

	// Companion app connection is best-effort: a lost/never-established
	// connection degrades the "telephony" capability, it never brings down
	// the agent (matches direct-mode/kiosk's non-fatal convention).
	if a.telephony != nil {
		go func() {
			if err := a.telephony.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				a.log.Debug("telephony companion connection ended", "error", err)
			}
		}()
	}

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
	// Emit variant status so dashboard knows what this agent is capable of
	a.emitVariantStatus()
	// Check for updates immediately if internet is available.
	go a.checkForUpdatesOnConnect()
}

// emitVariantStatus sends the current variant information to the server.
func (a *Agent) emitVariantStatus() {
	currentVariant := "headless"
	if kiosk.IsAvailable() {
		currentVariant = "kiosk"
	}

	status := transport.VariantStatus{
		Current:           currentVariant,
		Desired:           string(a.cfg.Variant.Desired),
		KioskAvailable:    kiosk.IsAvailable(),
		LastSwitchError:   a.cfg.Variant.LastSwitchError,
		LastSwitchAttempt: a.cfg.Variant.LastSwitchAttempt,
	}

	if err := a.transport.Emit("variant_status", status); err != nil {
		a.log.Debug("failed to emit variant_status", "error", err)
	}
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
	// We pass empty desiredTag and variant to get the latest release for the current variant
	// Note: resolveLatestAsset is in update.go (same package, so we can call it directly)
	latestTag, _, _, _, err := resolveLatestAsset(ctx, repo, "", "")
	if err != nil {
		// No internet or GitHub unavailable - silently skip
		a.log.Debug("update check skipped", "reason", "no internet or GitHub unavailable", "error", err)
		return
	}

	if latestTag == "" {
		return
	}

	if !version.IsNewer(latestTag, currentVersion) {
		a.log.Debug("agent is up to date", "version", currentVersion)
		return
	}

	a.log.Info("update available", "current", currentVersion, "latest", latestTag)
	result := a.trySelfUpdate(ctx, repo, latestTag, "")
	if !result.OK {
		a.log.Warn("auto-update failed", "tag", latestTag, "error", result.Error, "detail", result.Detail)
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
		variant := strings.TrimSpace(msg.Variant)

		a.log.Info("agent update requested", "repo", repo, "tag", tag, "variant", variant)
		result := a.trySelfUpdate(a.ctxOrBackground(), repo, tag, variant)

		// Best-effort result emit. If we successfully exec() on unix, this won't run.
		_ = a.transport.Emit("agent_update_result", map[string]any{
			"ok":      result.OK,
			"repo":    repo,
			"tag":     result.Tag,
			"variant": result.Variant,
			"error":   result.Error,
			"detail":  result.Detail,
			"ts":      time.Now().UTC().Format(time.RFC3339Nano),
		})
	}()
}

func (a *Agent) handleSwitchVariant(msg transport.SwitchVariantRequest) {
	// Run variant switch asynchronously
	go func() {
		repo := strings.TrimSpace(msg.Repo)
		if repo == "" {
			repo = "austinkregel/compute-agent"
		}
		tag := strings.TrimSpace(msg.Tag)
		if tag == "" {
			tag = version.Version // Use current version if not specified
		}
		variant := strings.TrimSpace(msg.Variant)

		if variant != "headless" && variant != "kiosk" {
			a.log.Error("invalid variant requested", "variant", variant)
			_ = a.transport.Emit("variant_switch_result", map[string]any{
				"ok":      false,
				"variant": variant,
				"error":   "invalid_variant",
				"detail":  "variant must be 'headless' or 'kiosk'",
				"ts":      time.Now().UTC().Format(time.RFC3339Nano),
			})
			return
		}

		a.log.Info("variant switch requested", "repo", repo, "tag", tag, "variant", variant)
		result := a.trySwitchVariant(a.ctxOrBackground(), repo, tag, variant)

		// Best-effort result emit. If we successfully exec() on unix, this won't run.
		_ = a.transport.Emit("variant_switch_result", map[string]any{
			"ok":      result.OK,
			"repo":    repo,
			"tag":     result.Tag,
			"variant": result.Variant,
			"error":   result.Error,
			"detail":  result.Detail,
			"ts":      time.Now().UTC().Format(time.RFC3339Nano),
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
		pathToList := strings.TrimSpace(msg.Path)
		// Default to home directory if no path provided
		if pathToList == "" {
			if home, err := os.UserHomeDir(); err == nil {
				pathToList = home
			} else {
				pathToList = "/" // Fallback to root if home dir unavailable
			}
		}
		clean, err := dirbrowse.ValidateAbsoluteDirPath(pathToList)
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
		// Default to root for remote paths if empty
		remotePath := strings.TrimSpace(msg.Path)
		if remotePath == "" {
			remotePath = "/"
		}

		switch proto {
		case "ssh":
			res, err := dirbrowse.ListSSH(ctx, dirbrowse.SSHRequest{
				Host: msg.Host,
				User: msg.User,
				Port: msg.Port,
				Path: remotePath,
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
				Path:    remotePath,
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

// --- Exec handlers ---

// handleExecRequest runs an allowlisted command and returns its output. The
// command policy (allowlist) is enforced by the runner; cwd, when provided, is
// confined to the IDE's allowed roots here before running.
func (a *Agent) handleExecRequest(msg transport.ExecRequest) {
	result := transport.ExecResult{ClientID: a.cfg.ClientID, RequestID: msg.RequestID}
	emit := func() {
		if err := a.transport.Emit("exec_result", result); err != nil {
			a.log.Error("failed to emit exec_result", "requestId", msg.RequestID, "error", err)
		}
	}

	cwd := strings.TrimSpace(msg.Cwd)
	if cwd != "" {
		clean, err := dirbrowse.ValidateAbsoluteDirPath(cwd)
		if err != nil {
			result.Error = err.Error()
			result.Stderr = err.Error()
			result.Code = 126
			emit()
			return
		}
		if err := dirbrowse.EnforceAllowedRoots(clean, a.cfg.DirBrowse.AllowedRoots); err != nil {
			result.Error = err.Error()
			result.Stderr = "cwd not allowed"
			result.Code = 126
			emit()
			return
		}
		cwd = clean
	}

	// Track a cancellable context per request so exec_cancel can kill the process.
	ctx, cancel := context.WithCancel(a.ctxOrBackground())
	if msg.RequestID != "" {
		a.execMu.Lock()
		a.execCancels[msg.RequestID] = cancel
		a.execMu.Unlock()
		defer func() {
			a.execMu.Lock()
			delete(a.execCancels, msg.RequestID)
			a.execMu.Unlock()
		}()
	}
	defer cancel()

	res := a.admin.Exec(ctx, msg.Command, cwd, time.Duration(msg.TimeoutSec)*time.Second)
	result.Code = res.Summary.Code
	result.Stdout = res.Stdout
	result.Stderr = res.Stderr
	result.Error = res.Error
	result.OK = res.Error == "" && res.Summary.Code == 0
	a.log.Info("exec_request completed", "requestId", msg.RequestID, "code", result.Code, "error", result.Error)
	emit()
}

// handleExecCancel kills an in-flight exec_request by id (cancels its context,
// which terminates the running process). No-op if it already finished.
func (a *Agent) handleExecCancel(msg transport.ExecCancelRequest) {
	a.execMu.Lock()
	cancel, ok := a.execCancels[msg.RequestID]
	a.execMu.Unlock()
	if ok {
		a.log.Info("exec_cancel", "requestId", msg.RequestID)
		cancel()
	}
}

// handleExecAllowlist applies a command allowlist pushed by the control plane.
// The combination is governed by admin.allowlistMode:
//   - "merge" (default): the CP list *extends* the agent's local
//     admin.allowedCommands — the operator's local allowlist is always honored
//     and the CP can only add (it can't silently drop local entries).
//   - "cp-authoritative": the CP list *replaces* the local one, letting a
//     locked-down fleet centrally tighten an over-permissive local config.
func (a *Agent) handleExecAllowlist(msg transport.ExecAllowlist) {
	mode, effective := combineAllowlist(a.cfg.Admin.AllowlistMode, a.cfg.Admin.Allowed, msg.Commands)
	a.admin.SetAllowlist(effective)
	a.log.Info("exec allowlist updated",
		"mode", mode, "total", len(effective), "local", len(a.cfg.Admin.Allowed), "controlPlane", len(msg.Commands))
}

// combineAllowlist computes the effective allowlist from the configured trust
// model. cp-authoritative uses the control-plane list verbatim; anything else
// (including empty) merges local + CP. Returns the resolved mode for logging.
func combineAllowlist(mode string, local, cp []string) (string, []string) {
	if mode == config.AllowlistModeCPAuthoritative {
		return config.AllowlistModeCPAuthoritative, cp
	}
	merged := make([]string, 0, len(local)+len(cp))
	merged = append(merged, local...)
	merged = append(merged, cp...)
	return config.AllowlistModeMerge, merged
}

// --- File operation handlers ---

// Read streaming tunables. The chunk size stays well under the 1 MB frame
// limit; the size cap keeps a stray read of a huge file from flooding the
// relay (the IDE can raise it per-request via maxSize).
const (
	fileGetChunkBytes int64 = 256 * 1024
	fileGetMaxBytes   int64 = 32 * 1024 * 1024
)

// handleFileGetRequest reads a file and streams it back as file_get_chunk
// frames followed by a terminal file_get_result. This is the read half of the
// file API over the control-plane relay (previously only the direct P2P
// listener supported it — see docs/PROTOCOL.md "PROTOCOL GAP").
func (a *Agent) handleFileGetRequest(msg transport.FileGetRequest) {
	result := transport.FileGetResult{
		ClientID:  a.cfg.ClientID,
		RequestID: msg.RequestID,
		Path:      msg.Path,
	}
	fail := func(err error) {
		result.OK = false
		result.Error = err.Error()
		result.ErrorCode = fileGetErrorCode(err)
		a.log.Warn("file_get_request failed", "requestId", msg.RequestID, "path", msg.Path, "error", result.Error)
		if emitErr := a.transport.Emit("file_get_result", result); emitErr != nil {
			a.log.Error("failed to emit file_get_result", "requestId", msg.RequestID, "error", emitErr)
		}
	}
	emitChunk := func(offset int64, data []byte) error {
		return a.transport.Emit("file_get_chunk", map[string]any{
			"clientId":  a.cfg.ClientID,
			"requestId": msg.RequestID,
			"offset":    offset,
			"data":      base64.StdEncoding.EncodeToString(data),
		})
	}
	emitResult := func() {
		if emitErr := a.transport.Emit("file_get_result", result); emitErr != nil {
			a.log.Error("failed to emit file_get_result", "requestId", msg.RequestID, "error", emitErr)
		}
	}

	// Windowed read (offset/length): stream only the requested byte range.
	if msg.Offset > 0 || msg.Length > 0 {
		f, size, err := fileops.OpenForReadRange(msg.Path, msg.Offset)
		if err != nil {
			fail(err)
			return
		}
		defer f.Close()
		result.Size = size
		result.Offset = msg.Offset
		serve, eof, truncated := fileops.RangeWindow(size, msg.Offset, msg.Length, msg.MaxSize, fileGetMaxBytes)
		buf := make([]byte, fileGetChunkBytes)
		var sent int64
		for sent < serve {
			chunk := int64(len(buf))
			if r := serve - sent; r < chunk {
				chunk = r
			}
			n, readErr := f.Read(buf[:chunk])
			if n > 0 {
				if emitErr := emitChunk(msg.Offset+sent, buf[:n]); emitErr != nil {
					fail(fmt.Errorf("connection lost mid-read: %w", emitErr))
					return
				}
				sent += int64(n)
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				fail(readErr)
				return
			}
		}
		result.OK = true
		result.Returned = sent
		result.EOF = eof || msg.Offset+sent >= size
		result.Truncated = truncated
		a.log.Info("file_get_request completed", "requestId", msg.RequestID, "path", msg.Path,
			"offset", msg.Offset, "returned", sent, "size", size)
		emitResult()
		return
	}

	// Whole-file read: reject anything over the effective limit.
	limit := fileGetMaxBytes
	if msg.MaxSize > 0 && msg.MaxSize < limit {
		limit = msg.MaxSize
	}
	f, size, err := fileops.OpenForRead(msg.Path, limit)
	if err != nil {
		fail(err)
		return
	}
	defer f.Close()

	buf := make([]byte, fileGetChunkBytes)
	var offset int64
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			if emitErr := emitChunk(offset, buf[:n]); emitErr != nil {
				fail(fmt.Errorf("connection lost mid-read: %w", emitErr))
				return
			}
			offset += int64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			fail(readErr)
			return
		}
	}

	result.OK = true
	result.Size = size
	result.Returned = offset
	result.EOF = true
	a.log.Info("file_get_request completed", "requestId", msg.RequestID, "path", msg.Path, "size", offset)
	emitResult()
}

// fileGetErrorCode maps a read failure to a machine-readable error code.
func fileGetErrorCode(err error) string {
	switch {
	case errors.Is(err, fileops.ErrIsDirectory):
		return "is_dir"
	case errors.Is(err, fileops.ErrFileTooLarge):
		return "too_large"
	case errors.Is(err, fileops.ErrHardDeny), os.IsPermission(err):
		return "permission"
	case os.IsNotExist(err):
		return "not_found"
	default:
		return "io"
	}
}

func (a *Agent) handleFilePutStart(msg transport.FilePutStartRequest) {
	clientID := a.cfg.ClientID
	result := transport.FilePutResult{
		ClientID:  clientID,
		RequestID: msg.RequestID,
	}

	err := a.uploads.StartUpload(msg.RequestID, msg.Path, msg.Size, msg.Mode, msg.Force, msg.Overwrite)
	if err != nil {
		result.OK = false
		result.Error = err.Error()
		a.log.Warn("file_put_start failed", "requestId", msg.RequestID, "path", msg.Path, "error", err)
	} else {
		result.OK = true
		result.Path = msg.Path
		a.log.Info("file_put_start accepted", "requestId", msg.RequestID, "path", msg.Path, "size", msg.Size)
	}

	if err := a.transport.Emit("file_put_result", result); err != nil {
		a.log.Error("failed to emit file_put_result", "requestId", msg.RequestID, "error", err)
	}
}

func (a *Agent) handleFilePutChunk(msg transport.FilePutChunk) {
	err := a.uploads.WriteChunk(msg.RequestID, msg.Offset, msg.Data)
	if err != nil {
		a.log.Warn("file_put_chunk failed", "requestId", msg.RequestID, "offset", msg.Offset, "error", err)
		// Cancel the upload on error
		a.uploads.CancelUpload(msg.RequestID)
		result := transport.FilePutResult{
			ClientID:  a.cfg.ClientID,
			RequestID: msg.RequestID,
			OK:        false,
			Error:     err.Error(),
		}
		_ = a.transport.Emit("file_put_result", result)
	}
}

func (a *Agent) handleFilePutFinish(msg transport.FilePutFinishRequest) {
	clientID := a.cfg.ClientID
	result := transport.FilePutResult{
		ClientID:  clientID,
		RequestID: msg.RequestID,
	}

	path, size, err := a.uploads.FinishUpload(msg.RequestID, msg.Checksum)
	if err != nil {
		result.OK = false
		result.Error = err.Error()
		a.log.Warn("file_put_finish failed", "requestId", msg.RequestID, "error", err)
	} else {
		result.OK = true
		result.Path = path
		result.Size = size
		a.log.Info("file_put_finish completed", "requestId", msg.RequestID, "path", path, "size", size)
	}

	if err := a.transport.Emit("file_put_result", result); err != nil {
		a.log.Error("failed to emit file_put_result", "requestId", msg.RequestID, "error", err)
	}
}

func (a *Agent) handleFileDelete(msg transport.FileDeleteRequest) {
	clientID := a.cfg.ClientID
	result := transport.FileDeleteResult{
		ClientID:  clientID,
		RequestID: msg.RequestID,
		Path:      msg.Path,
	}

	err := fileops.DeleteFile(msg.Path, msg.Force, msg.Recursive)
	if err != nil {
		result.OK = false
		result.Error = err.Error()
		a.log.Warn("file_delete failed", "requestId", msg.RequestID, "path", msg.Path, "error", err)
	} else {
		result.OK = true
		a.log.Info("file_delete completed", "requestId", msg.RequestID, "path", msg.Path)
	}

	if err := a.transport.Emit("file_delete_result", result); err != nil {
		a.log.Error("failed to emit file_delete_result", "requestId", msg.RequestID, "error", err)
	}
}

func (a *Agent) handleFileChmod(msg transport.FileChmodRequest) {
	clientID := a.cfg.ClientID
	result := transport.FileChmodResult{
		ClientID:  clientID,
		RequestID: msg.RequestID,
	}

	path, err := fileops.ChmodFile(msg.Path, msg.Mode, msg.Force)
	if err != nil {
		result.OK = false
		result.Error = err.Error()
		a.log.Warn("file_chmod failed", "requestId", msg.RequestID, "path", msg.Path, "mode", msg.Mode, "error", err)
	} else {
		result.OK = true
		result.Path = path
		result.Mode = msg.Mode
		a.log.Info("file_chmod completed", "requestId", msg.RequestID, "path", path, "mode", msg.Mode)
	}

	if err := a.transport.Emit("file_chmod_result", result); err != nil {
		a.log.Error("failed to emit file_chmod_result", "requestId", msg.RequestID, "error", err)
	}
}

func (a *Agent) handleFileMkdir(msg transport.FileMkdirRequest) {
	result := transport.FileMkdirResult{
		ClientID:  a.cfg.ClientID,
		RequestID: msg.RequestID,
	}
	path, err := fileops.Mkdir(msg.Path, msg.Force)
	if err != nil {
		result.OK = false
		result.Error = err.Error()
		a.log.Warn("file_mkdir failed", "requestId", msg.RequestID, "path", msg.Path, "error", err)
	} else {
		result.OK = true
		result.Path = path
		a.log.Info("file_mkdir completed", "requestId", msg.RequestID, "path", path)
	}
	if err := a.transport.Emit("file_mkdir_result", result); err != nil {
		a.log.Error("failed to emit file_mkdir_result", "requestId", msg.RequestID, "error", err)
	}
}

func (a *Agent) handleFileRename(msg transport.FileRenameRequest) {
	result := transport.FileRenameResult{
		ClientID:  a.cfg.ClientID,
		RequestID: msg.RequestID,
	}
	dst, err := fileops.Rename(msg.Path, msg.NewPath, msg.Force)
	if err != nil {
		result.OK = false
		result.Error = err.Error()
		a.log.Warn("file_rename failed", "requestId", msg.RequestID, "path", msg.Path, "newPath", msg.NewPath, "error", err)
	} else {
		result.OK = true
		result.Path = dst
		a.log.Info("file_rename completed", "requestId", msg.RequestID, "path", msg.Path, "newPath", dst)
	}
	if err := a.transport.Emit("file_rename_result", result); err != nil {
		a.log.Error("failed to emit file_rename_result", "requestId", msg.RequestID, "error", err)
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

// --- Kiosk handlers ---

func (a *Agent) handleKioskSet(msg transport.KioskSetRequest) {
	if a.kiosk == nil {
		a.log.Warn("kiosk_set received but kiosk not enabled")
		a.emitKioskStatus(kiosk.NewStatus(false, false, kiosk.Content{Kind: "blank"}, "kiosk not enabled"))
		return
	}

	content := kiosk.Content{
		Kind:   msg.Content.Kind,
		Title:  msg.Content.Title,
		Text:   msg.Content.Text,
		URL:    msg.Content.URL,
		Layout: msg.Content.Layout,
		Units:  msg.Content.Units,
	}
	for _, w := range msg.Content.Widgets {
		content.Widgets = append(content.Widgets, kiosk.WidgetPlacement{
			Type: w.Type, Col: w.Col, Row: w.Row, W: w.W, H: w.H, Config: w.Config,
		})
	}

	if err := a.kiosk.SetContent(content); err != nil {
		a.log.Error("kiosk set content failed", "error", err, "kind", content.Kind)
		return
	}

	a.log.Info("kiosk content updated", "kind", content.Kind, "requestId", msg.RequestID)
}

func (a *Agent) handleKioskSaveLayout(msg transport.KioskSaveLayoutRequest) {
	if a.kiosk == nil {
		a.log.Warn("kiosk_save_layout received but kiosk not enabled")
		_ = a.transport.Emit("kiosk_layout_saved", map[string]any{
			"layout": msg.Layout, "ok": false, "error": "kiosk not enabled",
		})
		return
	}

	layout := kiosk.PageLayout{Cols: msg.Cols, Rows: msg.Rows, Units: msg.Units}
	for _, w := range msg.Widgets {
		layout.Widgets = append(layout.Widgets, kiosk.WidgetPlacement{
			Type: w.Type, Col: w.Col, Row: w.Row, W: w.W, H: w.H, Config: w.Config,
		})
	}

	if err := a.kiosk.SaveLayout(msg.Layout, layout); err != nil {
		a.log.Error("kiosk save layout failed", "error", err, "layout", msg.Layout)
		_ = a.transport.Emit("kiosk_layout_saved", map[string]any{
			"layout": msg.Layout, "ok": false, "error": err.Error(),
		})
		return
	}

	a.log.Info("kiosk layout saved", "layout", msg.Layout)
	_ = a.transport.Emit("kiosk_layout_saved", map[string]any{
		"layout": msg.Layout, "ok": true,
	})
}

func (a *Agent) handleKioskGetLayouts(_ transport.KioskGetLayoutsRequest) {
	if a.kiosk == nil {
		_ = a.transport.Emit("kiosk_layouts", map[string]any{
			"layouts": map[string]any{},
		})
		return
	}
	_ = a.transport.Emit("kiosk_layouts", map[string]any{
		"layouts": a.kiosk.GetLayouts(),
	})
}

func (a *Agent) handleKioskStatus(status kiosk.Status) {
	a.emitKioskStatus(status)
}

func (a *Agent) emitKioskStatus(status kiosk.Status) {
	contentMap := map[string]any{
		"kind":  status.Content.Kind,
		"title": status.Content.Title,
		"text":  status.Content.Text,
		"url":   status.Content.URL,
	}
	if status.Content.Layout != "" {
		contentMap["layout"] = status.Content.Layout
	}
	payload := map[string]any{
		"kiosk": map[string]any{
			"running":   status.Running,
			"connected": status.Connected,
			"content":   contentMap,
			"lastError": status.LastError,
			"ts":        status.TS,
		},
	}
	if err := a.transport.Emit("kiosk_status", payload); err != nil {
		a.log.Debug("failed to emit kiosk_status", "error", err)
	}
}
