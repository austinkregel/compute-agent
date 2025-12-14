package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
		return c.emitError(req.PlanID, fmt.Errorf("unknown plan %s", req.PlanID))
	}
	rec := val.(*jobRecord)
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
		if err := copyFile(file.Source, destPath); err != nil {
			return c.emitError(req.PlanID, fmt.Errorf("copy %s: %w", file.Relative, err))
		}
		filesCompleted++
		bytesCopied += file.Size
		percent := float64(filesCompleted) / float64(max(1, rec.TotalFiles)) * 100
		progress := map[string]any{
			"planId":           req.PlanID,
			"file":             file.Relative,
			"op":               "copy",
			"percent":          percent,
			"transferredBytes": bytesCopied,
			"filesCompleted":   filesCompleted,
		}
		_ = c.emitter.Emit("backup_progress", progress)
	}

	duration := time.Since(start)
	complete := map[string]any{
		"planId":           req.PlanID,
		"ok":               true,
		"ms":               duration.Milliseconds(),
		"transferredBytes": bytesCopied,
	}
	return c.emitter.Emit("backup_complete", complete)
}

func (c *Coordinator) generatePlan(ctx context.Context, req transport.BackupRequest) (*jobRecord, error) {
	if len(req.SourceDirs) == 0 {
		return nil, errors.New("no source directories provided")
	}
	if req.Host != "" {
		return nil, errors.New("remote host backups not yet supported")
	}
	if strings.TrimSpace(req.DestRoot) == "" {
		return nil, errors.New("destRoot required")
	}
	destRootAbs, err := filepath.Abs(req.DestRoot)
	if err != nil {
		return nil, fmt.Errorf("invalid destRoot: %w", err)
	}
	destRootAbs = filepath.Clean(destRootAbs)
	if !c.isAllowedDestRoot(destRootAbs) {
		return nil, fmt.Errorf("destRoot %q not allowed", req.DestRoot)
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
