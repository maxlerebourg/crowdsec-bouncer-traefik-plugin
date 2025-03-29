// Package logger implements utility routines to write to stdout and stderr.
// It supports trace, debug, info and error level
package logger

import (
	"io"
	"log"
	"os"
)

// Log Logger struct.
type Log struct {
	logError *log.Logger
	logInfo  *log.Logger
	logDebug *log.Logger
	logTrace *log.Logger
}

// New Set Default log level to info in case log level to defined.
func New(logLevel string) *Log {
	logError := log.New(io.Discard, "ERROR: CrowdsecBouncerTraefikPlugin: ", log.Ldate|log.Ltime)
	logInfo := log.New(io.Discard, "INFO: CrowdsecBouncerTraefikPlugin: ", log.Ldate|log.Ltime)
	logDebug := log.New(io.Discard, "DEBUG: CrowdsecBouncerTraefikPlugin: ", log.Ldate|log.Ltime)
	logTrace := log.New(io.Discard, "TRACE: CrowdsecBouncerTraefikPlugin: ", log.Ldate|log.Ltime)

	// Set outputs based on log level
	logError.SetOutput(os.Stderr) // Always show errors
	switch logLevel {
	case "ERROR":
		// Only show errors
	case "INFO":
		logInfo.SetOutput(os.Stdout)
	case "DEBUG":
		logInfo.SetOutput(os.Stdout)
		logDebug.SetOutput(os.Stdout)
	case "TRACE":
		logInfo.SetOutput(os.Stdout)
		logDebug.SetOutput(os.Stdout)
		logTrace.SetOutput(os.Stdout)
	default:
		// Default to INFO level
		logInfo.SetOutput(os.Stdout)
	}

	return &Log{
		logError: logError,
		logInfo:  logInfo,
		logDebug: logDebug,
		logTrace: logTrace,
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

// Trace log to Stdout.
func (l *Log) Trace(str string) {
	l.logTrace.Printf("%s", str)
}

// Error log to Stderr.
func (l *Log) Error(str string) {
	l.logError.Printf("%s", str)
}
