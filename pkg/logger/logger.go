package logger

import (
	"io"
	"log"
	"os"
)

var (
	loggerInfo  = log.New(io.Discard, "INFO: CrowdsecBouncerTraefikPlugin: ", log.Ldate|log.Ltime)
	loggerDebug = log.New(io.Discard, "DEBUG: CrowdsecBouncerTraefikPlugin: ", log.Ldate|log.Ltime)
)

// Init Set Default log level to info in case log level to defined
func Init(logLevel string) {
	switch logLevel {
	case "INFO":
		loggerInfo.SetOutput(os.Stdout)
	case "DEBUG":
		loggerInfo.SetOutput(os.Stdout)
		loggerDebug.SetOutput(os.Stdout)
	default:
		loggerInfo.SetOutput(os.Stdout)
	}
}

// Info Log info
func Info(str string) {
	loggerInfo.Printf(str)
}

// Info Log debug
func Debug(str string) {
	loggerDebug.Printf(str)
}
