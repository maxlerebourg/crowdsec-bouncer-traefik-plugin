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
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

// New creates a Log wrapper with default format (common).
func New(logLevel string, logFilePath string) *slog.Logger {
	return NewWithFormat(logLevel, logFilePath, "common")
}

// NewWithFormat creates a Log wrapper with specified format (common or json).
func NewWithFormat(logLevel string, logFilePath string, logFormat string) *slog.Logger {
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
				lvl, ok := a.Value.Any().(slog.Level)
				if !ok {
					return a
				}
				switch {
				case lvl < LevelInfo:
					a.Value = slog.StringValue("DEBUG")
				case lvl < LevelWarn:
					a.Value = slog.StringValue("INFO")
				case lvl < LevelError:
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
	return slog.New(handler).With("component", "CrowdsecBouncerTraefikPlugin")
}
