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

// Init Set Default log level to info in case log level to defined
func Init(logLevel string) {
	loggerError.SetOutput(os.Stderr)
	loggerInfo.SetOutput(os.Stdout)
	switch logLevel {
	case "DEBUG":
		loggerDebug.SetOutput(os.Stdout)
	}
}

// Log info
func Info(str string) {
	loggerInfo.Printf(str)
}

// Log debug
func Debug(str string) {
	loggerDebug.Printf(str)
}

// Log error
func Error(str string) {
	loggerError.Printf(str)
}
