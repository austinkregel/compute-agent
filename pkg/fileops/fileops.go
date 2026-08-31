// Package fileops provides secure file operations (write, delete, chmod) with
// path validation and policy enforcement.
package fileops

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// --- Path validation errors ---

var (
	ErrEmptyPath        = errors.New("path is required")
	ErrNotAbsolute      = errors.New("path must be absolute")
	ErrContainsNUL      = errors.New("path contains NUL byte")
	ErrPathTraversal    = errors.New("path contains traversal segment '..'")
	ErrHardDeny         = errors.New("operation denied: path is in a protected system directory")
	ErrDangerousPath    = errors.New("operation requires force=true for this path")
	ErrDeleteRoot       = errors.New("cannot delete root directory")
	ErrDeleteNonEmpty   = errors.New("cannot delete non-empty directory without recursive=true")
	ErrChmodWindows     = errors.New("chmod is not supported on Windows")
	ErrInvalidMode      = errors.New("invalid permission mode")
	ErrUploadInProgress = errors.New("upload already in progress for this request")
	ErrUploadNotFound   = errors.New("no upload in progress for this request")
	ErrChecksumMismatch = errors.New("checksum mismatch")
)

// --- Path policy ---

// Hard deny prefixes: operations on these paths are ALWAYS blocked.
var hardDenyPrefixes = []string{
	"/dev",
	"/proc",
	"/sys",
	"/run",
}

// Dangerous prefixes: operations require force=true.
var dangerousPrefixes = []string{
	"/bin",
	"/sbin",
	"/usr",
	"/lib",
	"/lib32",
	"/lib64",
	"/libx32",
	"/boot",
	"/snap",
	"/var/lib",
	"/var/cache",
}

// Windows equivalents
var windowsHardDenyPrefixes = []string{
	`\\.\`,       // Device namespace
	`\\?\Volume`, // Volume GUIDs
}

var windowsDangerousPrefixes = []string{
	`C:\Windows`,
	`C:\Program Files`,
	`C:\Program Files (x86)`,
}

// ValidatePath checks that a path is safe for file operations.
// It returns the cleaned absolute path on success.
func ValidatePath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", ErrEmptyPath
	}
	if strings.ContainsRune(p, '\x00') {
		return "", ErrContainsNUL
	}
	if containsDotDotSegment(p) {
		return "", ErrPathTraversal
	}
	clean := filepath.Clean(p)
	if !filepath.IsAbs(clean) {
		return "", ErrNotAbsolute
	}
	return clean, nil
}

func containsDotDotSegment(p string) bool {
	isSep := func(r rune) bool { return r == '/' || r == '\\' }
	segStart := 0
	runes := []rune(p)
	for i := 0; i <= len(runes); i++ {
		if i == len(runes) || isSep(runes[i]) {
			seg := string(runes[segStart:i])
			if seg == ".." {
				return true
			}
			segStart = i + 1
		}
	}
	return false
}

// CheckPathPolicy validates a path against the security policy.
// Returns nil if allowed, ErrHardDeny if blocked, ErrDangerousPath if force is required.
func CheckPathPolicy(absPath string, force bool) error {
	lower := strings.ToLower(absPath)

	// Hard deny checks
	denyPrefixes := hardDenyPrefixes
	if runtime.GOOS == "windows" {
		denyPrefixes = windowsHardDenyPrefixes
	}
	for _, prefix := range denyPrefixes {
		prefixLower := strings.ToLower(prefix)
		if strings.HasPrefix(lower, prefixLower) || lower == prefixLower {
			return ErrHardDeny
		}
	}

	// Dangerous path checks (require force=true)
	dangerPrefixes := dangerousPrefixes
	if runtime.GOOS == "windows" {
		dangerPrefixes = windowsDangerousPrefixes
	}
	for _, prefix := range dangerPrefixes {
		prefixLower := strings.ToLower(prefix)
		if strings.HasPrefix(lower, prefixLower) || lower == prefixLower {
			if !force {
				return ErrDangerousPath
			}
			// force=true, allow but continue to check for hard deny
		}
	}

	return nil
}

// --- Upload session management ---

// UploadSession tracks an in-progress file upload.
type UploadSession struct {
	Path         string
	ExpectedSize int64
	Mode         os.FileMode
	TempPath     string
	File         *os.File
	BytesWritten int64
	mu           sync.Mutex
}

// UploadManager manages concurrent upload sessions.
type UploadManager struct {
	sessions map[string]*UploadSession
	mu       sync.Mutex
}

// NewUploadManager creates a new upload manager.
func NewUploadManager() *UploadManager {
	return &UploadManager{
		sessions: make(map[string]*UploadSession),
	}
}

// StartUpload begins a new upload session.
func (m *UploadManager) StartUpload(requestID, path string, size int64, modeStr string, force, overwrite bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sessions[requestID]; exists {
		return ErrUploadInProgress
	}

	// Validate and check policy
	absPath, err := ValidatePath(path)
	if err != nil {
		return err
	}
	if err := CheckPathPolicy(absPath, force); err != nil {
		return err
	}

	// Check if file exists and overwrite is not set
	if _, err := os.Stat(absPath); err == nil && !overwrite {
		return fmt.Errorf("file exists and overwrite=false: %s", absPath)
	}

	// Parse mode
	mode := os.FileMode(0644)
	if modeStr != "" {
		parsed, err := parseMode(modeStr)
		if err != nil {
			return err
		}
		mode = parsed
	}

	// Ensure parent directory exists
	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create parent directory: %w", err)
	}

	// Create temp file in the same directory for atomic rename
	tempFile, err := os.CreateTemp(dir, ".upload-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}

	session := &UploadSession{
		Path:         absPath,
		ExpectedSize: size,
		Mode:         mode,
		TempPath:     tempFile.Name(),
		File:         tempFile,
		BytesWritten: 0,
	}
	m.sessions[requestID] = session
	return nil
}

// WriteChunk writes a chunk to an upload session.
func (m *UploadManager) WriteChunk(requestID string, offset int64, data []byte) error {
	m.mu.Lock()
	session, exists := m.sessions[requestID]
	m.mu.Unlock()

	if !exists {
		return ErrUploadNotFound
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	// Seek to offset
	if _, err := session.File.Seek(offset, io.SeekStart); err != nil {
		return fmt.Errorf("seek: %w", err)
	}

	// Write data
	n, err := session.File.Write(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}
	session.BytesWritten += int64(n)

	return nil
}

// FinishUpload completes an upload and atomically moves the file to its final location.
func (m *UploadManager) FinishUpload(requestID, checksum string) (string, int64, error) {
	m.mu.Lock()
	session, exists := m.sessions[requestID]
	if exists {
		delete(m.sessions, requestID)
	}
	m.mu.Unlock()

	if !exists {
		return "", 0, ErrUploadNotFound
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	// Sync and close the temp file
	if err := session.File.Sync(); err != nil {
		session.File.Close()
		os.Remove(session.TempPath)
		return "", 0, fmt.Errorf("sync: %w", err)
	}

	// Verify checksum if provided
	if checksum != "" {
		if _, err := session.File.Seek(0, io.SeekStart); err != nil {
			session.File.Close()
			os.Remove(session.TempPath)
			return "", 0, fmt.Errorf("seek for checksum: %w", err)
		}
		hash := sha256.New()
		if _, err := io.Copy(hash, session.File); err != nil {
			session.File.Close()
			os.Remove(session.TempPath)
			return "", 0, fmt.Errorf("checksum read: %w", err)
		}
		computed := hex.EncodeToString(hash.Sum(nil))
		if !strings.EqualFold(computed, checksum) {
			session.File.Close()
			os.Remove(session.TempPath)
			return "", 0, ErrChecksumMismatch
		}
	}

	session.File.Close()

	// Set permissions before rename
	if err := os.Chmod(session.TempPath, session.Mode); err != nil {
		os.Remove(session.TempPath)
		return "", 0, fmt.Errorf("chmod: %w", err)
	}

	// Atomic rename
	if err := os.Rename(session.TempPath, session.Path); err != nil {
		// On Windows, rename over existing file may fail; try remove+rename
		if runtime.GOOS == "windows" {
			os.Remove(session.Path)
			if err2 := os.Rename(session.TempPath, session.Path); err2 != nil {
				os.Remove(session.TempPath)
				return "", 0, fmt.Errorf("rename: %w", err)
			}
		} else {
			os.Remove(session.TempPath)
			return "", 0, fmt.Errorf("rename: %w", err)
		}
	}

	return session.Path, session.BytesWritten, nil
}

// CancelUpload aborts an upload and cleans up.
func (m *UploadManager) CancelUpload(requestID string) {
	m.mu.Lock()
	session, exists := m.sessions[requestID]
	if exists {
		delete(m.sessions, requestID)
	}
	m.mu.Unlock()

	if exists {
		session.mu.Lock()
		defer session.mu.Unlock()
		session.File.Close()
		os.Remove(session.TempPath)
	}
}

// --- Delete operation ---

// DeleteFile deletes a file or empty directory.
func DeleteFile(path string, force, recursive bool) error {
	absPath, err := ValidatePath(path)
	if err != nil {
		return err
	}

	// Prevent deleting root
	if absPath == "/" || absPath == `C:\` || absPath == `C:` {
		return ErrDeleteRoot
	}

	if err := CheckPathPolicy(absPath, force); err != nil {
		return err
	}

	info, err := os.Lstat(absPath)
	if err != nil {
		return err
	}

	if info.IsDir() {
		if recursive {
			// Recursive delete requires force for safety
			if !force {
				return errors.New("recursive delete requires force=true")
			}
			return os.RemoveAll(absPath)
		}
		// Try to remove as empty directory
		if err := os.Remove(absPath); err != nil {
			// Check if it's a non-empty directory error
			if os.IsExist(err) || strings.Contains(err.Error(), "not empty") || strings.Contains(err.Error(), "directory not empty") {
				return ErrDeleteNonEmpty
			}
			return err
		}
		return nil
	}

	// Regular file or symlink
	return os.Remove(absPath)
}

// --- Read operation ---

// ErrIsDirectory is returned when a read targets a directory.
var ErrIsDirectory = errors.New("path is a directory")

// ErrFileTooLarge is returned when a file exceeds the read size limit.
var ErrFileTooLarge = errors.New("file exceeds the maximum read size")

// OpenForRead validates a path and opens it for reading. Reads are
// non-mutating, so "dangerous" prefixes (e.g. /usr, /etc) are permitted —
// viewing system config in the editor is legitimate — but hard-deny prefixes
// (/dev, /proc, /sys, /run) stay blocked to avoid pseudo-files. The cleaned
// absolute path and file size are returned; the caller owns closing the file.
func OpenForRead(path string, maxBytes int64) (*os.File, int64, error) {
	absPath, err := ValidatePath(path)
	if err != nil {
		return nil, 0, err
	}
	// force=true allows dangerous prefixes while still blocking hard-deny ones.
	if err := CheckPathPolicy(absPath, true); err != nil {
		return nil, 0, err
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return nil, 0, err
	}
	if info.IsDir() {
		return nil, 0, ErrIsDirectory
	}
	if maxBytes > 0 && info.Size() > maxBytes {
		return nil, 0, fmt.Errorf("%w: %d bytes > %d-byte limit", ErrFileTooLarge, info.Size(), maxBytes)
	}

	f, err := os.Open(absPath)
	if err != nil {
		return nil, 0, err
	}
	return f, info.Size(), nil
}

// OpenForReadRange opens a file for a windowed read starting at byte `offset`,
// returning the open file (seeked to `offset`) and the file's total size. It
// does not reject on file size; the read length is bounded by the caller.
func OpenForReadRange(path string, offset int64) (*os.File, int64, error) {
	absPath, err := ValidatePath(path)
	if err != nil {
		return nil, 0, err
	}
	if err := CheckPathPolicy(absPath, true); err != nil {
		return nil, 0, err
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return nil, 0, err
	}
	if info.IsDir() {
		return nil, 0, ErrIsDirectory
	}
	f, err := os.Open(absPath)
	if err != nil {
		return nil, 0, err
	}
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			f.Close()
			return nil, 0, err
		}
	}
	return f, info.Size(), nil
}

// RangeWindow computes how many bytes to serve for a windowed read from `offset`
// into a file of `size`, honoring an optional requested `length`, an optional
// `maxSize` cap, and a hard `hardCap`. It reports whether the window reaches EOF
// and whether it was cut short (truncated) by a cap below the requested length.
// An offset at or past EOF serves nothing and reports eof.
func RangeWindow(size, offset, length, maxSize, hardCap int64) (serve int64, eof, truncated bool) {
	if offset >= size {
		return 0, true, false
	}
	remaining := size - offset
	requested := remaining
	if length > 0 && length < requested {
		requested = length
	}
	serve = requested
	if maxSize > 0 && maxSize < serve {
		serve = maxSize
	}
	if hardCap > 0 && hardCap < serve {
		serve = hardCap
	}
	eof = offset+serve >= size
	truncated = !eof && serve < requested
	return serve, eof, truncated
}

// --- Chmod operation ---

// ChmodFile changes the permissions of a file.
func ChmodFile(path, modeStr string, force bool) (string, error) {
	if runtime.GOOS == "windows" {
		return "", ErrChmodWindows
	}

	absPath, err := ValidatePath(path)
	if err != nil {
		return "", err
	}

	if err := CheckPathPolicy(absPath, force); err != nil {
		return "", err
	}

	mode, err := parseMode(modeStr)
	if err != nil {
		return "", err
	}

	if err := os.Chmod(absPath, mode); err != nil {
		return "", err
	}

	return absPath, nil
}

// --- Mkdir / Rename operations ---

// Mkdir creates a directory (and any missing parents), enforcing path policy.
// Returns the cleaned absolute path.
func Mkdir(path string, force bool) (string, error) {
	absPath, err := ValidatePath(path)
	if err != nil {
		return "", err
	}
	if err := CheckPathPolicy(absPath, force); err != nil {
		return "", err
	}
	if err := os.MkdirAll(absPath, 0o755); err != nil {
		return "", err
	}
	return absPath, nil
}

// Rename moves/renames a file or directory. Both endpoints are validated and
// policy-checked. os.Rename handles same-filesystem moves; a cross-device move
// falls back to copy-then-remove. Returns the cleaned destination path.
func Rename(oldPath, newPath string, force bool) (string, error) {
	src, err := ValidatePath(oldPath)
	if err != nil {
		return "", err
	}
	dst, err := ValidatePath(newPath)
	if err != nil {
		return "", err
	}
	if err := CheckPathPolicy(src, force); err != nil {
		return "", err
	}
	if err := CheckPathPolicy(dst, force); err != nil {
		return "", err
	}
	if _, err := os.Stat(src); err != nil {
		return "", err
	}
	// Don't clobber an existing destination unless forced.
	if _, err := os.Stat(dst); err == nil && !force {
		return "", fmt.Errorf("destination exists: %s", dst)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", fmt.Errorf("create destination parent: %w", err)
	}
	if err := os.Rename(src, dst); err != nil {
		// EXDEV (cross-device) → fall back to copy + remove.
		if isCrossDevice(err) {
			if cerr := copyTree(src, dst); cerr != nil {
				return "", cerr
			}
			if rerr := os.RemoveAll(src); rerr != nil {
				return "", rerr
			}
			return dst, nil
		}
		return "", err
	}
	return dst, nil
}

func isCrossDevice(err error) bool {
	return errors.Is(err, syscall.EXDEV)
}

// copyTree recursively copies a file or directory tree from src to dst.
func copyTree(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if info.IsDir() {
		if err := os.MkdirAll(dst, info.Mode().Perm()); err != nil {
			return err
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := copyTree(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// parseMode parses a permission mode string (octal like "0755" or "755").
func parseMode(s string) (os.FileMode, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, ErrInvalidMode
	}

	// Handle octal format (0755, 755, etc.)
	val, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, ErrInvalidMode
	}
	if val > 0777 {
		return 0, ErrInvalidMode
	}
	return os.FileMode(val), nil
}
