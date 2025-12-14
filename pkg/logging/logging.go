package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

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

// New builds a slog-backed logger writing JSON to stdout and, optionally, to a file.
func New(opts Options) (*Logger, error) {
	level := parseLevel(opts.Level)
	writer := io.Writer(os.Stdout)
	var closer io.Closer

	if opts.File != "" {
		f, err := os.OpenFile(opts.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, err
		}
		writer = io.MultiWriter(os.Stdout, f)
		closer = f
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
