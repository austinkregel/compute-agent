package app

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

type updateResult struct {
	OK     bool
	Tag    string
	Error  string
	Detail string
}

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

func (a *Agent) trySelfUpdate(ctx context.Context, repo string, desiredTag string) updateResult {
	exePath, err := os.Executable()
	if err != nil {
		return updateResult{OK: false, Error: "executable", Detail: err.Error()}
	}
	exePath, _ = filepath.EvalSymlinks(exePath)

	tag, archiveName, archiveURL, checksumsURL, err := resolveLatestAsset(ctx, repo, desiredTag)
	if err != nil {
		return updateResult{OK: false, Tag: desiredTag, Error: "resolve_release", Detail: err.Error()}
	}

	a.log.Info("downloading agent release asset", "tag", tag, "asset", archiveName)
	tmpDir, err := os.MkdirTemp("", "backup-agent-update-*")
	if err != nil {
		return updateResult{OK: false, Tag: tag, Error: "tempdir", Detail: err.Error()}
	}
	defer os.RemoveAll(tmpDir) // best-effort

	archivePath := filepath.Join(tmpDir, archiveName)
	if err := downloadToFile(ctx, archiveURL, archivePath); err != nil {
		return updateResult{OK: false, Tag: tag, Error: "download", Detail: err.Error()}
	}

	if checksumsURL != "" {
		if err := verifyArchiveChecksum(ctx, checksumsURL, archiveName, archivePath); err != nil {
			return updateResult{OK: false, Tag: tag, Error: "checksum", Detail: err.Error()}
		}
	}

	newBinPath := filepath.Join(tmpDir, "backup-agent.new")
	if runtime.GOOS == "windows" {
		newBinPath += ".exe"
	}
	if err := extractExpectedBinary(archivePath, newBinPath); err != nil {
		return updateResult{OK: false, Tag: tag, Error: "extract", Detail: err.Error()}
	}

	// Install alongside current executable.
	installTmp := exePath + ".new"
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(installTmp), ".exe") {
		installTmp += ".exe"
	}
	if err := copyFileAtomic(newBinPath, installTmp, 0o755); err != nil {
		return updateResult{OK: false, Tag: tag, Error: "stage", Detail: err.Error()}
	}

	// Swap into place (best-effort on windows).
	if err := swapExecutable(exePath, installTmp); err != nil {
		return updateResult{OK: false, Tag: tag, Error: "install", Detail: err.Error()}
	}

	a.log.Info("agent binary updated; restarting", "path", exePath, "tag", tag)

	// Re-exec on unix to pick up the new binary.
	if runtime.GOOS != "windows" {
		// Best-effort: flush logs, then exec.
		// Exec never returns if successful.
		_ = syscall.Exec(exePath, os.Args, os.Environ())
		return updateResult{OK: true, Tag: tag, Detail: "exec failed unexpectedly"}
	}

	// Windows: start new process and exit; file swapping may be blocked on some setups.
	cmd := exec.Command(exePath, os.Args[1:]...)
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return updateResult{OK: false, Tag: tag, Error: "restart", Detail: err.Error()}
	}
	
	newPID := cmd.Process.Pid
	a.log.Info("started new process", "pid", newPID)
	
	// Verify the new process started successfully before exiting.
	// Use a goroutine to wait for the process; if it exits quickly, that's a failure.
	processExited := make(chan error, 1)
	go func() {
		processExited <- cmd.Wait()
	}()
	
	// Wait a short time to see if process exits immediately (indicates failure)
	select {
	case err := <-processExited:
		// Process exited quickly - this is bad
		errMsg := "new process exited immediately"
		if err != nil {
			errMsg = fmt.Sprintf("new process exited with error: %v", err)
		}
		return updateResult{OK: false, Tag: tag, Error: "restart", Detail: errMsg}
	case <-time.After(1 * time.Second):
		// Process is still running after 1 second - good!
		a.log.Info("new process verified running", "pid", newPID)
	}
	
	// Small delay to reduce reconnect thrash if the supervisor restarts too.
	// Note: If managed by supervisor, supervisor will restart when this process exits.
	// The new binary is already in place, so supervisor will start the new version.
	// However, we've already started the new process manually, so supervisor may
	// see two processes briefly. This is acceptable as supervisor should handle it.
	time.Sleep(250 * time.Millisecond)
	os.Exit(0)
	return updateResult{OK: true, Tag: tag}
}

func resolveLatestAsset(ctx context.Context, repo string, desiredTag string) (tag string, assetName string, assetURL string, checksumsURL string, err error) {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return "", "", "", "", errors.New("repo required")
	}
	api := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	rel, err := fetchGitHubRelease(ctx, api)
	if err != nil {
		return "", "", "", "", err
	}
	tag = strings.TrimSpace(rel.TagName)
	if tag == "" {
		return "", "", "", "", errors.New("missing tag_name from GitHub release API")
	}
	if desiredTag != "" && desiredTag != tag {
		// If a specific tag was requested and doesn't match latest, we still proceed with latest
		// (this endpoint is intended to be "update to newest").
	}

	platform := fmt.Sprintf("backup-agent-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		assetName = fmt.Sprintf("%s-%s.zip", platform, tag)
	} else {
		assetName = fmt.Sprintf("%s-%s.tar.gz", platform, tag)
	}

	for _, a := range rel.Assets {
		if a.Name == "checksums.txt" {
			checksumsURL = a.BrowserDownloadURL
		}
		if a.Name == assetName {
			assetURL = a.BrowserDownloadURL
		}
	}
	if assetURL == "" {
		return tag, assetName, "", checksumsURL, fmt.Errorf("no matching asset for %s (wanted %q)", platform, assetName)
	}
	return tag, assetName, assetURL, checksumsURL, nil
}

func fetchGitHubRelease(ctx context.Context, url string) (*ghRelease, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "backup-agent-updater")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("github api %s: %s: %s", url, resp.Status, strings.TrimSpace(string(b)))
	}
	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	return &rel, nil
}

func downloadToFile(ctx context.Context, url string, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "backup-agent-updater")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("download %s: %s: %s", url, resp.Status, strings.TrimSpace(string(b)))
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	return f.Sync()
}

func verifyArchiveChecksum(ctx context.Context, checksumsURL, archiveName, archivePath string) error {
	tmp, err := os.CreateTemp("", "checksums-*.txt")
	if err != nil {
		return err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	if err := downloadToFile(ctx, checksumsURL, tmp.Name()); err != nil {
		return err
	}
	data, err := os.ReadFile(tmp.Name())
	if err != nil {
		return err
	}
	want := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		sum := strings.ToLower(strings.TrimSpace(parts[0]))
		name := strings.TrimSpace(parts[len(parts)-1])
		if name == archiveName {
			want = sum
			break
		}
	}
	if want == "" {
		return fmt.Errorf("checksums.txt missing entry for %q", archiveName)
	}

	got, err := sha256FileHex(archivePath)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("sha256 mismatch for %s: got %s want %s", archiveName, got, want)
	}
	return nil
}

func sha256FileHex(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func extractExpectedBinary(archivePath, outPath string) error {
	if strings.HasSuffix(archivePath, ".zip") {
		return extractFromZip(archivePath, outPath)
	}
	if strings.HasSuffix(archivePath, ".tar.gz") {
		return extractFromTarGz(archivePath, outPath)
	}
	return fmt.Errorf("unsupported archive format: %s", archivePath)
}

func expectedBinaryName() string {
	base := fmt.Sprintf("backup-agent-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}
	return base
}

func extractFromTarGz(archivePath, outPath string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	want := expectedBinaryName()
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if h == nil || h.Name == "" {
			continue
		}
		name := filepath.Base(h.Name)
		if name != want {
			continue
		}
		if h.Typeflag != tar.TypeReg {
			return fmt.Errorf("unexpected tar entry type for %s", h.Name)
		}
		if h.Size <= 0 || h.Size > 200*1024*1024 {
			return fmt.Errorf("unexpected binary size %d", h.Size)
		}
		return writeFromReaderAtomic(outPath, tr, 0o755)
	}
	return fmt.Errorf("binary %q not found in tar.gz", want)
}

func extractFromZip(archivePath, outPath string) error {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer zr.Close()
	want := expectedBinaryName()
	for _, f := range zr.File {
		if f == nil {
			continue
		}
		if filepath.Base(f.Name) != want {
			continue
		}
		if f.FileInfo().IsDir() {
			continue
		}
		if f.UncompressedSize64 == 0 || f.UncompressedSize64 > 200*1024*1024 {
			return fmt.Errorf("unexpected binary size %d", f.UncompressedSize64)
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		return writeFromReaderAtomic(outPath, rc, 0o755)
	}
	return fmt.Errorf("binary %q not found in zip", want)
}

func writeFromReaderAtomic(dest string, r io.Reader, mode os.FileMode) error {
	dir := filepath.Dir(dest)
	tmp, err := os.CreateTemp(dir, filepath.Base(dest)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()
	if runtime.GOOS != "windows" {
		_ = tmp.Chmod(mode)
	}
	if _, err := io.Copy(tmp, r); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, dest); err != nil {
		// Windows doesn't allow rename-over-existing; attempt remove+rename.
		_ = os.Remove(dest)
		if err2 := os.Rename(tmpName, dest); err2 != nil {
			return err
		}
	}
	return nil
}

func copyFileAtomic(src, dest string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	return writeFromReaderAtomic(dest, in, mode)
}

func swapExecutable(exePath, stagedPath string) error {
	// Unix: rename current aside then move staged into place.
	// Windows: best-effort rename; may fail if locked by the running process.
	oldPath := exePath + ".old"
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(oldPath), ".exe") {
		oldPath += ".exe"
	}

	// Best-effort: preserve previous binary.
	_ = os.Remove(oldPath)
	_ = os.Rename(exePath, oldPath)

	// Put the new one in place.
	if err := os.Rename(stagedPath, exePath); err != nil {
		// If rename failed, try copy-over then cleanup.
		if err2 := copyFileAtomic(stagedPath, exePath, 0o755); err2 != nil {
			return err
		}
		_ = os.Remove(stagedPath)
	}

	// Ensure executable bit on unix.
	if runtime.GOOS != "windows" {
		_ = os.Chmod(exePath, 0o755)
	}
	return nil
}



