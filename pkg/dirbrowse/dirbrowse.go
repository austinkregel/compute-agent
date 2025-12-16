package dirbrowse

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Entry is a single directory child entry.
// Type is either "dir" or "file".
type Entry struct {
	Name string
	Type string
	Size int64
}

// Result is a listing result that may include a truncation warning.
type Result struct {
	Path          string
	Entries       []Entry
	Truncated     bool
	TruncateError string
}

const (
	defaultMaxEntries      = 5000
	defaultMaxResponseSize = 1 << 20 // ~1 MiB (names + overhead)
)

// ValidateAbsoluteDirPath performs RFC-0002 minimum validation:
// - non-empty
// - absolute path
// - no NUL bytes
// - no ".." traversal segments
//
// It returns a cleaned path (filepath.Clean).
func ValidateAbsoluteDirPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", errors.New("path is required")
	}
	if strings.ContainsRune(p, '\x00') {
		return "", errors.New("path contains NUL byte")
	}
	if containsDotDotSegment(p) {
		return "", errors.New("path contains traversal segment '..'")
	}
	clean := filepath.Clean(p)
	if !filepath.IsAbs(clean) {
		return "", errors.New("path must be absolute")
	}
	return clean, nil
}

func containsDotDotSegment(p string) bool {
	// Treat both separators as boundaries to catch Windows paths too.
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

// EnforceAllowedRoots returns an error if the absolute path is not within one of the allowed roots.
// If allowedRoots is empty, the path is accepted.
func EnforceAllowedRoots(absPath string, allowedRoots []string) error {
	if len(allowedRoots) == 0 {
		return nil
	}
	absPath = filepath.Clean(absPath)
	for _, root := range allowedRoots {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		rootClean := filepath.Clean(root)
		if !filepath.IsAbs(rootClean) {
			// Ignore invalid allowlist entries.
			continue
		}
		rel, err := filepath.Rel(rootClean, absPath)
		if err != nil {
			continue
		}
		rel = filepath.Clean(rel)
		if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
			return nil
		}
	}
	return fmt.Errorf("path %q is not within allowedRoots", absPath)
}

// ListLocal lists immediate children of absPath (non-recursive) and returns a sorted result.
// absPath MUST be an absolute path; use ValidateAbsoluteDirPath first.
func ListLocal(ctx context.Context, absPath string, maxEntries int, maxResponseBytes int) (Result, error) {
	if maxEntries <= 0 {
		maxEntries = defaultMaxEntries
	}
	if maxResponseBytes <= 0 {
		maxResponseBytes = defaultMaxResponseSize
	}

	select {
	case <-ctx.Done():
		return Result{}, ctx.Err()
	default:
	}

	entries, err := os.ReadDir(absPath)
	if err != nil {
		return Result{}, err
	}

	var out []Entry
	approxBytes := 0
	truncated := false
	var truncReason string

	for _, e := range entries {
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		default:
		}

		name := e.Name()
		if name == "" {
			continue
		}
		typ := "file"
		size := int64(0)

		info, infoErr := e.Info()
		if infoErr == nil {
			if info.IsDir() {
				typ = "dir"
			}
			if !info.IsDir() {
				size = info.Size()
			}
		} else if e.IsDir() {
			typ = "dir"
		}

		approxBytes += len(name) + 16 // name + overhead
		if len(out) >= maxEntries || approxBytes > maxResponseBytes {
			truncated = true
			truncReason = "listing truncated due to size limits"
			break
		}
		out = append(out, Entry{Name: name, Type: typ, Size: size})
	}

	sortEntries(out)

	return Result{
		Path:          absPath,
		Entries:       out,
		Truncated:     truncated,
		TruncateError: truncReason,
	}, nil
}

func sortEntries(entries []Entry) {
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.Type != b.Type {
			// dirs first
			return a.Type == "dir"
		}
		return a.Name < b.Name
	})
}
