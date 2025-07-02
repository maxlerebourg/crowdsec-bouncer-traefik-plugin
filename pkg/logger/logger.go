// Package logger implements utility routines to write to stdout and stderr.
// It supports trace, debug, info and error level
package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

// Log Logger struct.
type Log struct {
	logError *log.Logger
	logInfo  *log.Logger
	logDebug *log.Logger
	logTrace *log.Logger
}

// New Set Default log level to info in case log level to defined.
func New(logLevel string, logFilePath string) *Log {
	// Initialize loggers with discard output
	logError := log.New(io.Discard, "ERROR: CrowdsecBouncerTraefikPlugin: ", log.Ldate|log.Ltime)
	logInfo := log.New(io.Discard, "INFO: CrowdsecBouncerTraefikPlugin: ", log.Ldate|log.Ltime)
	logDebug := log.New(io.Discard, "DEBUG: CrowdsecBouncerTraefikPlugin: ", log.Ldate|log.Ltime)

	// we initialize logger to STDOUT/STDERR first so if the file logger cannot be initialized we can inform the user
	output := os.Stdout
	errorOutput := os.Stderr

	// prepare file logging if specified
	if logFilePath != "" {
		logFile, err := os.OpenFile(filepath.Clean(logFilePath), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			output = logFile
			errorOutput = logFile
		} else {
			_ = fmt.Errorf("LogFilePath is not writable %w", err)
		}
	}

	// Set error logger output
	logError.SetOutput(errorOutput)

	// Configure log levels
	switch logLevel {
	case "ERROR":
		// Only error logging is enabled
	case "INFO":
		logInfo.SetOutput(output)
	case "DEBUG":
		logInfo.SetOutput(output)
		logDebug.SetOutput(output)
	default:
		// Default to INFO level
		logInfo.SetOutput(output)
	}

	return &Log{
		logError: logError,
		logInfo:  logInfo,
		logDebug: logDebug,
	}
}

// Info log to Stdout.
func (l *Log) Info(str string) {
	l.logInfo.Printf("%s", str)
}

// Debug log to Stdout.
func (l *Log) Debug(str string) {
	l.logDebug.Printf("%s", str)
}

// Error log to Stderr.
func (l *Log) Error(str string) {
	l.logError.Printf("%s", str)
}
