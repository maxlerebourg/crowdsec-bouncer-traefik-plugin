package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name     string
		logLevel string
	}{
		{
			name:     "ERROR level",
			logLevel: "ERROR",
		},
		{
			name:     "WARN level",
			logLevel: "WARN",
		},
		{
			name:     "INFO level",
			logLevel: "INFO",
		},
		{
			name:     "DEBUG level",
			logLevel: "DEBUG",
		},
		{
			name:     "TRACE level",
			logLevel: "TRACE",
		},
		{
			name:     "Default level (INFO)",
			logLevel: "INVALID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := New(tt.logLevel, "")

			// Verify logger is created
			if logger == nil {
				t.Fatal("Expected logger to be created, got nil")
			}

			// Verify it's a slog.Logger (we can call methods on it)
			logger.Info("test initialization")
		})
	}
}

func TestJSONLogFormat(t *testing.T) {
	var buf bytes.Buffer

	// Create a logger with JSON handler to capture output
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(handler).With("component", "CrowdsecBouncerTraefikPlugin")

	testMessage := "json test message"
	logger.Info(testMessage)

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	if len(lines) != 1 {
		t.Fatalf("Expected 1 log line, got %d", len(lines))
	}

	// Verify it's valid JSON
	var logEntry map[string]interface{}
	err := json.Unmarshal([]byte(lines[0]), &logEntry)
	if err != nil {
		t.Fatalf("Expected valid JSON output, got error: %v, output: %s", err, output)
	}

	// Verify JSON structure
	if logEntry["level"] != "INFO" {
		t.Errorf("Expected level 'INFO', got '%v'", logEntry["level"])
	}
	if logEntry["msg"] != testMessage {
		t.Errorf("Expected message '%s', got '%v'", testMessage, logEntry["msg"])
	}
	if logEntry["time"] == nil {
		t.Error("Expected timestamp to be set")
	}
	if logEntry["component"] != "CrowdsecBouncerTraefikPlugin" {
		t.Errorf("Expected component 'CrowdsecBouncerTraefikPlugin', got '%v'", logEntry["component"])
	}
}

func TestCommonLogFormat(t *testing.T) {
	var buf bytes.Buffer

	// Create a logger with text handler to capture output
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(handler).With("component", "CrowdsecBouncerTraefikPlugin")

	testMessage := "common test message"
	logger.Info(testMessage)

	output := buf.String()

	// Verify common format (should contain level and message)
	if !strings.Contains(output, "level=INFO") {
		t.Error("Expected common format with INFO level")
	}
	if !strings.Contains(output, testMessage) {
		t.Error("Expected test message in common format")
	}
	if !strings.Contains(output, "component=CrowdsecBouncerTraefikPlugin") {
		t.Error("Expected component field in common format")
	}

	// Should NOT be JSON (should be slog text format)
	var logEntry map[string]interface{}
	err := json.Unmarshal([]byte(strings.TrimSpace(output)), &logEntry)
	if err == nil {
		t.Error("Expected common format (not JSON), but got valid JSON")
	}
}

func TestLogLevels(t *testing.T) {
	var buf bytes.Buffer

	// Create a logger with TRACE level to capture output
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: LevelTrace, // Use our custom TRACE level
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
	})
	logger := slog.New(handler).With("component", "CrowdsecBouncerTraefikPlugin")

	testMessage := "test message"

	// Test all log methods
	logger.Error(testMessage)
	logger.Warn(testMessage)
	logger.Info(testMessage)
	logger.Debug(testMessage)
	logger.Log(context.Background(), LevelTrace, testMessage) // Use Log method for TRACE

	output := buf.String()

	// Verify expected messages appear (slog format with custom level names)
	if !strings.Contains(output, "level=ERROR") {
		t.Error("Expected ERROR level message to appear")
	}
	if !strings.Contains(output, "level=WARN") {
		t.Error("Expected WARN level message to appear")
	}
	if !strings.Contains(output, "level=INFO") {
		t.Error("Expected INFO level message to appear")
	}
	if !strings.Contains(output, "level=DEBUG") {
		t.Error("Expected DEBUG level message to appear")
	}
	if !strings.Contains(output, "level=TRACE") {
		t.Error("Expected TRACE level message to appear")
	}

	// Verify message content appears
	messageCount := strings.Count(output, testMessage)
	if messageCount != 5 { // ERROR, WARN, INFO, DEBUG, TRACE
		t.Errorf("Expected 5 occurrences of test message, got %d", messageCount)
	}
}

func TestErrorLevel(t *testing.T) {
	var buf bytes.Buffer

	// Create a logger with ERROR level to capture output
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError})
	logger := slog.New(handler).With("component", "CrowdsecBouncerTraefikPlugin")

	testMessage := "error only test"

	// Test all log methods
	logger.Error(testMessage)
	logger.Warn(testMessage)                                  // Should not appear
	logger.Info(testMessage)                                  // Should not appear
	logger.Debug(testMessage)                                 // Should not appear
	logger.Log(context.Background(), LevelTrace, testMessage) // Should not appear

	output := buf.String()

	// Only ERROR should appear
	if !strings.Contains(output, "level=ERROR") {
		t.Error("Expected ERROR message to appear")
	}

	// Other levels should NOT appear
	unwantedLevels := []string{"level=WARN", "level=INFO", "level=DEBUG"}
	for _, level := range unwantedLevels {
		if strings.Contains(output, level) {
			t.Errorf("Unexpected %s message appeared at ERROR level", level)
		}
	}

	// Verify only one message appears
	messageCount := strings.Count(output, testMessage)
	if messageCount != 1 {
		t.Errorf("Expected 1 occurrence of test message at ERROR level, got %d", messageCount)
	}
}

func TestTraceMethod(t *testing.T) {
	var buf bytes.Buffer

	// Create a logger with TRACE level to capture output
	logger := NewWithFormat("TRACE", "", "common")

	// Replace the handler to capture output
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: LevelTrace,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
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
	})
	logger.Logger = slog.New(handler).With("component", "CrowdsecBouncerTraefikPlugin")

	testMessage := "trace method test"
	logger.Trace(testMessage)

	output := buf.String()

	// Verify TRACE level appears
	if !strings.Contains(output, "level=TRACE") {
		t.Error("Expected TRACE level message to appear")
	}

	// Verify message content appears
	if !strings.Contains(output, testMessage) {
		t.Error("Expected trace message content to appear")
	}
}

func TestTraceLevel(t *testing.T) {
	var buf bytes.Buffer

	// Create a logger with TRACE level to capture output
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: LevelTrace,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
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
	})
	logger := slog.New(handler).With("component", "CrowdsecBouncerTraefikPlugin")

	testMessage := "trace test message"

	// Test TRACE level specifically
	logger.Log(context.Background(), LevelTrace, testMessage)

	output := buf.String()

	// Verify TRACE message appears
	if !strings.Contains(output, "level=TRACE") {
		t.Error("Expected TRACE level message to appear")
	}
	if !strings.Contains(output, testMessage) {
		t.Error("Expected test message to appear")
	}
}

func TestInvalidLogFile(t *testing.T) {
	// Try to create logger with invalid file path
	logger := New("INFO", "/invalid/path/that/does/not/exist/test.log")

	// Logger should still be created (falls back to stdout)
	if logger == nil {
		t.Fatal("Expected logger to be created even with invalid file path")
	}

	// Should not panic when logging
	logger.Info("test message")
}
