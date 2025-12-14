package backup

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/austinkregel/compute-agent/pkg/config"
	"github.com/austinkregel/compute-agent/pkg/logging"
	"github.com/austinkregel/compute-agent/pkg/transport"
)

// Coordinator owns backup planning/execution logic.
type Coordinator struct {
	cfg     *config.Config
	log     *logging.Logger
	emitter transport.Emitter

	jobs sync.Map // planId -> *jobRecord
}

type jobRecord struct {
	Request    transport.BackupRequest
	Files      []fileEntry
	TotalFiles int
	TotalBytes int64
	Sample     []string
}

type fileEntry struct {
	Source   string
	Relative string
	Size     int64
}

// NewCoordinator builds a backup coordinator.
func NewCoordinator(cfg *config.Config, log *logging.Logger, emitter transport.Emitter) *Coordinator {
	return &Coordinator{cfg: cfg, log: log, emitter: emitter}
}

// Plan handles plan requests from the server.
func (c *Coordinator) Plan(ctx context.Context, req transport.BackupRequest) error {
	rec, err := c.generatePlan(ctx, req)
	if err != nil {
		return c.emitError(req.PlanID, err)
	}

	c.jobs.Store(req.PlanID, rec)
	_ = c.persistPlan(req.PlanID, rec) // best-effort
	payload := map[string]any{
		"planId":     req.PlanID,
		"job":        req,
		"totalFiles": rec.TotalFiles,
		"totalBytes": rec.TotalBytes,
		"files":      rec.Sample,
		"modifies":   []string{},
	}
	if err := c.emitter.Emit("backup_plan", payload); err != nil {
		return err
	}
	return nil
}

// Run executes an approved plan.
func (c *Coordinator) Run(ctx context.Context, req transport.BackupRequest) error {
	val, ok := c.jobs.Load(req.PlanID)
	if !ok {
		if rec, err := c.loadPlan(req.PlanID); err == nil && rec != nil {
			c.jobs.Store(req.PlanID, rec)
			val = rec
			ok = true
		}
	}
	if !ok {
		return c.emitError(req.PlanID, fmt.Errorf("unknown plan %s", req.PlanID))
	}

	rec := val.(*jobRecord)
	if strings.TrimSpace(req.Host) != "" {
		return c.runRemote(ctx, req, rec)
	}
	return c.runLocal(ctx, req, rec)
}

func (c *Coordinator) generatePlan(ctx context.Context, req transport.BackupRequest) (*jobRecord, error) {
	if len(req.SourceDirs) == 0 {
		return nil, errors.New("no source directories provided")
	}
	if strings.TrimSpace(req.DestRoot) == "" {
		return nil, errors.New("destRoot required")
	}
	if strings.TrimSpace(req.Host) == "" {
		destRootAbs, err := filepath.Abs(req.DestRoot)
		if err != nil {
			return nil, fmt.Errorf("invalid destRoot: %w", err)
		}
		destRootAbs = filepath.Clean(destRootAbs)
		if !c.isAllowedDestRoot(destRootAbs) {
			return nil, fmt.Errorf("destRoot %q not allowed", req.DestRoot)
		}
	}

	patterns := normalizeGlobs(req.IgnoreGlobs)

	rec := &jobRecord{Request: req}
	for _, dir := range req.SourceDirs {
		root, err := c.validateSourceDir(dir)
		if err != nil {
			return nil, err
		}
		walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if d.IsDir() {
				return nil
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			sl := filepath.ToSlash(filepath.Join(filepath.Base(root), rel))
			if matchesAny(sl, patterns) {
				return nil
			}
			info, infoErr := d.Info()
			if infoErr != nil {
				return infoErr
			}
			rec.TotalFiles++
			rec.TotalBytes += info.Size()

			if len(rec.Sample) < 25 {
				rec.Sample = append(rec.Sample, sl)
			}

			rec.Files = append(rec.Files, fileEntry{
				Source:   path,
				Relative: sl,
				Size:     info.Size(),
			})
			return nil
		})
		if walkErr != nil {
			return nil, walkErr
		}
	}
	return rec, nil
}

func (c *Coordinator) runLocal(ctx context.Context, req transport.BackupRequest, rec *jobRecord) error {
	start := time.Now()

	if strings.TrimSpace(req.DestRoot) == "" {
		return c.emitError(req.PlanID, errors.New("destRoot required"))
	}
	destRootAbs, err := filepath.Abs(req.DestRoot)
	if err != nil {
		return c.emitError(req.PlanID, fmt.Errorf("invalid destRoot: %w", err))
	}
	destRootAbs = filepath.Clean(destRootAbs)
	if !c.isAllowedDestRoot(destRootAbs) {
		return c.emitError(req.PlanID, fmt.Errorf("destRoot %q not allowed", req.DestRoot))
	}

	var (
		filesCompleted int
		bytesCopied    int64
		lastEmit       time.Time
		lastPersist    time.Time
	)

	for _, file := range rec.Files {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		destPath, derr := safeJoin(destRootAbs, file.Relative)
		if derr != nil {
			return c.emitError(req.PlanID, fmt.Errorf("copy %s: %w", file.Relative, derr))
		}

		baseBytes := bytesCopied
		emitProgress := func(now time.Time, copiedThisFile int64, done bool) {
			bytesCopied = baseBytes + copiedThisFile
			if done || lastEmit.IsZero() || now.Sub(lastEmit) >= time.Second {
				percent := float64(bytesCopied) / float64(max64(1, rec.TotalBytes)) * 100
				progress := map[string]any{
					"planId":           req.PlanID,
					"file":             file.Relative,
					"op":               "copy",
					"percent":          percent,
					"transferredBytes": bytesCopied,
					"filesCompleted":   filesCompleted,
				}
				_ = c.emitter.Emit("backup_progress", progress)
				lastEmit = now
			}
			if done || lastPersist.IsZero() || now.Sub(lastPersist) >= time.Second {
				_ = c.persistProgress(req.PlanID, file.Relative, bytesCopied)
				lastPersist = now
			}
		}

		emitProgress(time.Now(), 0, false)
		if err := copyFileWithProgress(ctx, file.Source, destPath, func(copied int64, done bool) {
			emitProgress(time.Now(), copied, done)
		}); err != nil {
			return c.emitError(req.PlanID, fmt.Errorf("copy %s: %w", file.Relative, err))
		}

		filesCompleted++
		emitProgress(time.Now(), file.Size, true)
	}

	duration := time.Since(start)
	complete := map[string]any{
		"planId":           req.PlanID,
		"ok":               true,
		"ms":               duration.Milliseconds(),
		"transferredBytes": bytesCopied,
	}
	_ = c.persistProgress(req.PlanID, "", bytesCopied)
	return c.emitter.Emit("backup_complete", complete)
}

func (c *Coordinator) runRemote(ctx context.Context, req transport.BackupRequest, rec *jobRecord) error {
	start := time.Now()

	if strings.TrimSpace(req.Host) == "" {
		return c.emitError(req.PlanID, errors.New("host required for remote backup"))
	}
	if strings.TrimSpace(req.DestRoot) == "" {
		return c.emitError(req.PlanID, errors.New("destRoot required"))
	}
	if _, err := exec.LookPath("rsync"); err != nil {
		return c.emitError(req.PlanID, errors.New("rsync not found on PATH"))
	}

	remote := req.Host
	if strings.TrimSpace(req.User) != "" {
		remote = req.User + "@" + req.Host
	}
	destRoot := strings.TrimSuffix(req.DestRoot, "/")

	progressRe := regexp.MustCompile(`^\s*([0-9,]+)\s+(\d+)%`)

	var (
		filesCompleted int
		bytesCopied    int64
		lastEmit       time.Time
		lastPersist    time.Time
		currentFile    string
	)

	for _, srcDir := range req.SourceDirs {
		srcDir = strings.TrimSpace(srcDir)
		if srcDir == "" {
			continue
		}
		// Mirror local layout: destRoot/<baseOfSourceDir>/...
		destPath := filepath.ToSlash(filepath.Join(destRoot, filepath.Base(srcDir))) + "/"
		dest := remote + ":" + destPath

		args := []string{"-a", "--info=progress2", "--out-format=%n"}
		for _, g := range normalizeGlobs(req.IgnoreGlobs) {
			args = append(args, "--exclude", g)
		}
		if req.Port > 0 {
			args = append(args, "-e", fmt.Sprintf("ssh -p %d", req.Port))
		}
		args = append(args, srcDir+string(filepath.Separator), dest)

		cmd := exec.CommandContext(ctx, "rsync", args...)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return c.emitError(req.PlanID, err)
		}
		stderr, err := cmd.StderrPipe()
		if err != nil {
			return c.emitError(req.PlanID, err)
		}

		if err := cmd.Start(); err != nil {
			return c.emitError(req.PlanID, err)
		}

		lines := make(chan string, 256)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			sc := bufio.NewScanner(stdout)
			for sc.Scan() {
				lines <- sc.Text()
			}
		}()
		go func() {
			defer wg.Done()
			sc := bufio.NewScanner(stderr)
			for sc.Scan() {
				lines <- sc.Text()
			}
		}()
		go func() {
			wg.Wait()
			close(lines)
		}()

		waitCh := make(chan error, 1)
		go func() { waitCh <- cmd.Wait() }()

		bytesBase := bytesCopied
		var bytesThis int64

		emit := func(now time.Time, done bool) {
			bytesCopied = bytesBase + bytesThis
			if done || lastEmit.IsZero() || now.Sub(lastEmit) >= time.Second {
				percent := float64(bytesCopied) / float64(max64(1, rec.TotalBytes)) * 100
				if rec.TotalBytes == 0 {
					percent = 0
				}
				progress := map[string]any{
					"planId":           req.PlanID,
					"file":             currentFile,
					"op":               "rsync",
					"percent":          percent,
					"transferredBytes": bytesCopied,
					"filesCompleted":   filesCompleted,
				}
				_ = c.emitter.Emit("backup_progress", progress)
				lastEmit = now
			}
			if done || lastPersist.IsZero() || now.Sub(lastPersist) >= time.Second {
				_ = c.persistProgress(req.PlanID, currentFile, bytesCopied)
				lastPersist = now
			}
		}

		for {
			select {
			case <-ctx.Done():
				_ = cmd.Process.Kill()
				return ctx.Err()
			case err := <-waitCh:
				emit(time.Now(), true)
				if err != nil {
					return c.emitError(req.PlanID, fmt.Errorf("rsync failed: %w", err))
				}
				// Move baseline forward after each rsync run.
				bytesCopied = bytesBase + bytesThis
				filesCompleted++
				goto nextSource
			case line, ok := <-lines:
				if !ok {
					continue
				}
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				if m := progressRe.FindStringSubmatch(line); m != nil {
					n, perr := parseInt64WithCommas(m[1])
					if perr == nil {
						bytesThis = n
					}
					emit(time.Now(), false)
					continue
				}
				// Treat other output lines as the current file name, best-effort.
				currentFile = line
			}
		}

	nextSource:
		continue
	}

	duration := time.Since(start)
	complete := map[string]any{
		"planId":           req.PlanID,
		"ok":               true,
		"ms":               duration.Milliseconds(),
		"transferredBytes": bytesCopied,
	}
	_ = c.persistProgress(req.PlanID, "", bytesCopied)
	return c.emitter.Emit("backup_complete", complete)
}

func (c *Coordinator) validateSourceDir(dir string) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", errors.New("empty source directory")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("invalid source directory %q: %w", dir, err)
	}
	abs = filepath.Clean(abs)

	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("resolve source directory %q: %w", dir, err)
	}
	real = filepath.Clean(real)

	// Defense-in-depth: do not follow a symlinked source root by default.
	if real != abs {
		return "", fmt.Errorf("source directory %q resolves through symlinks; refusing", dir)
	}

	// If an allowlist is configured, enforce it.
	if c.cfg != nil && len(c.cfg.Backup.AllowedSourceRoots) > 0 {
		for _, root := range c.cfg.Backup.AllowedSourceRoots {
			root = strings.TrimSpace(root)
			if root == "" {
				continue
			}
			absRoot, rerr := filepath.Abs(root)
			if rerr != nil {
				continue
			}
			absRoot = filepath.Clean(absRoot)
			if isWithin(absRoot, abs) {
				return abs, nil
			}
		}
		return "", fmt.Errorf("source directory %q not allowed", dir)
	}

	return abs, nil
}

func (c *Coordinator) isAllowedDestRoot(destRootAbs string) bool {
	// Backwards-compatible default: if no allowlist is configured, allow any
	// destination root (but still enforce safeJoin() to prevent traversal).
	if c.cfg == nil || len(c.cfg.Backup.AllowedDestRoots) == 0 {
		return true
	}
	for _, root := range c.cfg.Backup.AllowedDestRoots {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		abs, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		abs = filepath.Clean(abs)
		if isWithin(abs, destRootAbs) {
			return true
		}
	}
	return false
}

func safeJoin(destRootAbs, relative string) (string, error) {
	// relative is stored in slash form ("/"). It must remain a *relative* path.
	//
	// filepath.Join(base, abs) discards base on Unix, so explicitly reject
	// absolute paths (and Windows volume/UNC-style paths) up front.
	if strings.HasPrefix(relative, "/") || strings.HasPrefix(relative, `\`) {
		return "", fmt.Errorf("absolute path not allowed: %q", relative)
	}

	// Convert to platform separators and normalize.
	relOS := filepath.Clean(filepath.FromSlash(relative))
	if filepath.IsAbs(relOS) || filepath.VolumeName(relOS) != "" {
		return "", fmt.Errorf("absolute path not allowed: %q", relative)
	}

	destRootAbs = filepath.Clean(destRootAbs)
	joined := filepath.Join(destRootAbs, relOS)
	joinedAbs, err := filepath.Abs(joined)
	if err != nil {
		return "", err
	}
	joinedAbs = filepath.Clean(joinedAbs)
	if !isWithin(destRootAbs, joinedAbs) {
		return "", fmt.Errorf("path traversal detected: %q", relative)
	}
	return joinedAbs, nil
}

func isWithin(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	rel = filepath.Clean(rel)
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")
}

func (c *Coordinator) emitError(planID string, err error) error {
	c.log.Error("backup error", "planId", planID, "error", err)
	payload := map[string]any{
		"planId": planID,
		"error":  err.Error(),
	}
	_ = c.emitter.Emit("backup_error", payload)
	return err
}

type planOnDisk struct {
	Request    transport.BackupRequest `json:"request"`
	Files      []fileEntry             `json:"files"`
	TotalFiles int                     `json:"totalFiles"`
	TotalBytes int64                   `json:"totalBytes"`
	Sample     []string                `json:"sample"`
}

type progressOnDisk struct {
	PlanID           string `json:"planId"`
	File             string `json:"file,omitempty"`
	TransferredBytes int64  `json:"transferredBytes"`
	Timestamp        string `json:"ts"`
}

var planIDSanitizeRe = regexp.MustCompile(`[^A-Za-z0-9_.-]+`)

func sanitizePlanID(planID string) string {
	planID = strings.TrimSpace(planID)
	if planID == "" {
		planID = "unknown"
	}
	return planIDSanitizeRe.ReplaceAllString(planID, "_")
}

func (c *Coordinator) planFilePath(planID string) string {
	return filepath.Join(os.TempDir(), "compute-agent", "backup-plans", sanitizePlanID(planID)+".json")
}

func (c *Coordinator) progressFilePath(planID string) string {
	return filepath.Join(os.TempDir(), "compute-agent", "backup-plans", sanitizePlanID(planID)+".state.json")
}

func (c *Coordinator) persistPlan(planID string, rec *jobRecord) error {
	path := c.planFilePath(planID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(planOnDisk{
		Request:    rec.Request,
		Files:      rec.Files,
		TotalFiles: rec.TotalFiles,
		TotalBytes: rec.TotalBytes,
		Sample:     rec.Sample,
	})
	if err != nil {
		return err
	}
	return atomicWriteFile(path, data, 0o600)
}

func (c *Coordinator) loadPlan(planID string) (*jobRecord, error) {
	path := c.planFilePath(planID)
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pod planOnDisk
	if err := json.Unmarshal(raw, &pod); err != nil {
		return nil, err
	}
	return &jobRecord{
		Request:    pod.Request,
		Files:      pod.Files,
		TotalFiles: pod.TotalFiles,
		TotalBytes: pod.TotalBytes,
		Sample:     pod.Sample,
	}, nil
}

func (c *Coordinator) persistProgress(planID, file string, transferredBytes int64) error {
	path := c.progressFilePath(planID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(progressOnDisk{
		PlanID:           planID,
		File:             file,
		TransferredBytes: transferredBytes,
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	return atomicWriteFile(path, data, 0o600)
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if _, err := tmp.Write([]byte("\n")); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(path)
		if err2 := os.Rename(tmpName, path); err2 != nil {
			return err
		}
	}
	_ = os.Chmod(path, perm)
	return nil
}

func copyFileWithProgress(ctx context.Context, src, dest string, onProgress func(copied int64, done bool)) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()

	buf := make([]byte, 32*1024)
	var copied int64
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, rerr := in.Read(buf)
		if n > 0 {
			wn, werr := out.Write(buf[:n])
			if werr != nil {
				return werr
			}
			if wn != n {
				return io.ErrShortWrite
			}
			copied += int64(wn)
			if onProgress != nil {
				onProgress(copied, false)
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			return rerr
		}
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if onProgress != nil {
		onProgress(copied, true)
	}
	return nil
}

func parseInt64WithCommas(s string) (int64, error) {
	s = strings.ReplaceAll(strings.TrimSpace(s), ",", "")
	return strconv.ParseInt(s, 10, 64)
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func copyFile(src, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return nil
}

func normalizeGlobs(globs []string) []string {
	var out []string
	for _, g := range globs {
		g = strings.TrimSpace(g)
		if g != "" {
			out = append(out, g)
		}
	}
	return out
}

func matchesAny(path string, globs []string) bool {
	for _, g := range globs {
		match, err := doublestar.Match(g, path)
		if err == nil && match {
			return true
		}
	}
	return false
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
