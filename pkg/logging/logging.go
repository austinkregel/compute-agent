package logging

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const defaultRotateMaxBytes int64 = 10 * 1024 * 1024

// Logger wraps slog.Logger so packages do not depend on slog directly.
type Logger struct {
	core   *slog.Logger
	closer io.Closer
	mu     sync.Mutex
}

// Options describe how to construct a logger instance.
type Options struct {
	File  string
	Level string
}

type rotatingFile struct {
	path    string
	maxSize int64

	mu   sync.Mutex
	file *os.File
	size int64
}

func newRotatingFile(path string, maxSize int64) (*rotatingFile, error) {
	if maxSize <= 0 {
		maxSize = defaultRotateMaxBytes
	}
	// Ensure parent directory exists.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	r := &rotatingFile{path: path, maxSize: maxSize}
	if err := r.openOrCreate(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *rotatingFile) openOrCreate() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	info, statErr := f.Stat()
	if statErr == nil {
		r.size = info.Size()
	}
	r.file = f
	return nil
}

func (r *rotatingFile) rotateLocked() error {
	if r.file != nil {
		_ = r.file.Close()
		r.file = nil
	}
	rotated := r.path + ".1"
	_ = os.Remove(rotated)
	// Best-effort: rename current log to .1 if it exists.
	if _, err := os.Stat(r.path); err == nil {
		_ = os.Rename(r.path, rotated)
	}
	r.size = 0
	return r.openOrCreate()
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.file == nil {
		if err := r.openOrCreate(); err != nil {
			return 0, err
		}
	}
	if r.size+int64(len(p)) > r.maxSize {
		if err := r.rotateLocked(); err != nil {
			return 0, err
		}
	}
	n, err := r.file.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *rotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return nil
	}
	err := r.file.Close()
	r.file = nil
	return err
}

// New builds a slog-backed logger writing JSON to stdout and, optionally, to a file.
func New(opts Options) (*Logger, error) {
	level := parseLevel(opts.Level)
	writer := io.Writer(os.Stdout)
	var closer io.Closer

	if opts.File != "" {
		rot, err := newRotatingFile(opts.File, defaultRotateMaxBytes)
		if err != nil {
			return nil, err
		}
		writer = io.MultiWriter(os.Stdout, rot)
		closer = rot
	}

	handler := slog.NewJSONHandler(writer, &slog.HandlerOptions{Level: level})
	return &Logger{
		core:   slog.New(handler),
		closer: closer,
	}, nil
}

// Info logs at info level.
func (l *Logger) Info(msg string, args ...any) {
	l.core.Info(msg, args...)
}

// Error logs at error level.
func (l *Logger) Error(msg string, args ...any) {
	l.core.Error(msg, args...)
}

// Debug logs at debug level.
func (l *Logger) Debug(msg string, args ...any) {
	l.core.Debug(msg, args...)
}

// Warn logs at warn level.
func (l *Logger) Warn(msg string, args ...any) {
	l.core.Warn(msg, args...)
}

// Sync flushes and closes any underlying file handles.
func (l *Logger) Sync() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closer != nil {
		_ = l.closer.Close()
		l.closer = nil
	}
}

// With returns a child logger with structured attributes.
func (l *Logger) With(args ...any) *Logger {
	return &Logger{core: l.core.With(args...)}
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
