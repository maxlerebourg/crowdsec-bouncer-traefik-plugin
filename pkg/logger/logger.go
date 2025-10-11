// Package logger implements utility routines to write to stdout and stderr.
// It supports trace, debug, info, warn and error level using Go's standard log/slog
package logger

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
)

// Custom log levels following slog best practices.
const (
	LevelTrace = slog.Level(-8) // More verbose than DEBUG
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

// Log wraps slog.Logger to add a Trace method for consistent logging interface.
type Log struct {
	*slog.Logger
}

// Trace logs at TRACE level using the custom LevelTrace.
func (l *Log) Trace(msg string) {
	l.Logger.Log(context.Background(), LevelTrace, msg)
}

// New creates a Log wrapper with default format (common).
func New(logLevel string, logFilePath string) *Log {
	return NewWithFormat(logLevel, logFilePath, "common")
}

// NewWithFormat creates a Log wrapper with specified format (common or json).
func NewWithFormat(logLevel string, logFilePath string, logFormat string) *Log {
	// Determine log level
	var level slog.Level
	switch logLevel {
	case "ERROR":
		level = LevelError
	case "WARN":
		level = LevelWarn
	case "INFO":
		level = LevelInfo
	case "DEBUG":
		level = LevelDebug
	case "TRACE":
		level = LevelTrace
	default:
		// Default to INFO level
		level = LevelInfo
	}

	// Set output destination
	var output *os.File
	if logFilePath != "" {
		logFile, err := os.OpenFile(filepath.Clean(logFilePath), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			output = logFile
		} else {
			// Fall back to stdout and log the error
			output = os.Stdout
			slog.Warn("LogFilePath is not writable, using stdout", "error", err)
		}
	} else {
		output = os.Stdout
	}

	// Create handler based on format with custom level names
	var handler slog.Handler
	opts := &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			// Customize level names to match our expected format
			if a.Key == slog.LevelKey {
				level, ok := a.Value.Any().(slog.Level)
				if !ok {
					return a
				}
				switch {
				case level < LevelDebug:
					a.Value = slog.StringValue("TRACE")
				case level < LevelInfo:
					a.Value = slog.StringValue("DEBUG")
				case level < LevelWarn:
					a.Value = slog.StringValue("INFO")
				case level < LevelError:
					a.Value = slog.StringValue("WARN")
				default:
					a.Value = slog.StringValue("ERROR")
				}
			}
			return a
		},
	}

	if logFormat == "json" {
		handler = slog.NewJSONHandler(output, opts)
	} else {
		// Common format (default)
		handler = slog.NewTextHandler(output, opts)
	}

	// Create logger with component attribute
	logger := slog.New(handler).With("component", "CrowdsecBouncerTraefikPlugin")

	return &Log{Logger: logger}
}
