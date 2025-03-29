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
	logError.SetOutput(os.Stderr)
	logInfo.SetOutput(os.Stdout)
	if logLevel == "DEBUG" {
		logDebug.SetOutput(os.Stdout)
	} else if logLevel == "TRACE" {
		logDebug.SetOutput(os.Stdout)
		logTrace.SetOutput(os.Stdout)
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
