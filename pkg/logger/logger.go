//
package logger

import (
	"io"
	"log"
	"os"
)

var (
	loggerInfo  = log.New(io.Discard, "INFO: CrowdsecBouncerTraefikPlugin: ", log.Ldate|log.Ltime)
	loggerDebug = log.New(io.Discard, "DEBUG: CrowdsecBouncerTraefikPlugin: ", log.Ldate|log.Ltime)
	loggerError = log.New(io.Discard, "ERROR: CrowdsecBouncerTraefikPlugin: ", log.Ldate|log.Ltime)
)

// Init Set Default log level to info in case log level to defined.
func Init(logLevel string) {
	loggerError.SetOutput(os.Stderr)
	loggerInfo.SetOutput(os.Stdout)
	if logLevel == "DEBUG" {
		loggerDebug.SetOutput(os.Stdout)
	}
}

// Info log to Stdout.
func Info(str string) {
	loggerInfo.Printf(str)
}

// Debug log to Stdout.
func Debug(str string) {
	loggerDebug.Printf(str)
}

// Error log to Stderr.
func Error(str string) {
	loggerError.Printf(str)
}
