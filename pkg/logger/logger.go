// Package logger implements utility routines to write to stdout and stderr.
// It supports debug, info and error level
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
}

// New Set Default log level to info in case log level to defined.
func New(logLevel string, logFilePath string) *Log {
	logError := log.New(io.Discard, "ERROR: CrowdsecBouncerTraefikPlugin: ", log.Ldate|log.Ltime)
	logInfo := log.New(io.Discard, "INFO: CrowdsecBouncerTraefikPlugin: ", log.Ldate|log.Ltime)
	logDebug := log.New(io.Discard, "DEBUG: CrowdsecBouncerTraefikPlugin: ", log.Ldate|log.Ltime)

	logError.SetOutput(os.Stderr)
	logInfo.SetOutput(os.Stdout)
	// we initialize logger to STDOUT/STDERR first so if the file logger cannot be initialized we can inform the user
	if logLevel == "DEBUG" {
		logDebug.SetOutput(os.Stdout)
	}
	if logFilePath != "" {
		logFile, err := os.OpenFile(filepath.Clean(logFilePath), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			_ = fmt.Errorf("LogFilePath is not writable %w", err)
		} else {
			logInfo.SetOutput(logFile)
			logError.SetOutput(logFile)
			if logLevel == "DEBUG" {
				logDebug.SetOutput(logFile)
			}
		}
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
