package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

// getTestConfig returns a minimal valid configuration for testing.
// Override specific fields by modifying the returned config.
func getTestConfig() *configuration.Config {
	return &configuration.Config{
		Enabled:                              true,
		LogLevel:                             "INFO",
		LogFormat:                            "common",
		LogFilePath:                          "",
		CrowdsecMode:                         "none",
		CrowdsecLapiKey:                      "test-key",
		CrowdsecLapiHost:                     "localhost",
		CrowdsecLapiScheme:                   "http",
		UpdateIntervalSeconds:                60,
		DefaultDecisionSeconds:               60,
		HTTPTimeoutSeconds:                   10,
		ForwardedHeadersTrustedIPs:           []string{"127.0.0.1"},
		ForwardedHeadersCustomName:           "",
		RemediationStatusCode:                403,
		BanHTMLFilePath:                      "",
		RemediationHeadersCustomName:         "",
		CaptchaProvider:                      "",
		CaptchaSiteKey:                       "",
		CaptchaSecretKey:                     "",
		CaptchaGracePeriodSeconds:            1,
		CaptchaHTMLFilePath:                  "",
		RedisCacheEnabled:                    false,
		RedisCacheHost:                       "",
		RedisCachePassword:                   "",
		RedisCacheDatabase:                   "",
		RedisCacheUnreachableBlock:           false,
		CrowdsecAppsecEnabled:                false,
		CrowdsecAppsecHost:                   "",
		CrowdsecAppsecPath:                   "",
		CrowdsecAppsecFailureBlock:           false,
		CrowdsecAppsecUnreachableBlock:       false,
		CrowdsecLapiTLSInsecureVerify:        true,
		CrowdsecLapiTLSCertificateBouncer:    "",
		CrowdsecLapiTLSCertificateBouncerKey: "",
		CrowdsecCapiMachineID:                "",
		CrowdsecCapiPassword:                 "",
		CrowdsecCapiScenarios:                []string{},
		UpdateMaxFailure:                     0,
		MetricsUpdateIntervalSeconds:         0,
	}
}

// Helper function to create and execute a bouncer request for testing
func createAndExecuteBouncerRequest(t *testing.T, config *configuration.Config) {
	t.Helper()

	// Create a mock next handler
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	// Create the bouncer plugin (this will initialize the logger with file output)
	bouncerHandler, err := New(context.Background(), nextHandler, config, "test-bouncer")
	if err != nil {
		t.Fatalf("Failed to create bouncer: %v", err)
	}

	// Create a test request to trigger logging
	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	req.RemoteAddr = "192.168.1.100:12345" // Use a non-trusted IP to trigger logging
	rw := httptest.NewRecorder()

	// Process the request (this should generate log entries)
	bouncerHandler.ServeHTTP(rw, req)

	// Give a moment for log writes to complete
	time.Sleep(100 * time.Millisecond)
}

// Helper function to parse log file and extract found levels
func parseLogFileAndExtractLevels(t *testing.T, logFile string) map[string]bool {
	t.Helper()

	// Verify the log file was created and contains entries
	if _, statErr := os.Stat(logFile); os.IsNotExist(statErr) {
		t.Fatalf("Log file was not created: %s", logFile)
	}

	// Read the log file content
	// #nosec G304 - logFile is a test-generated temporary file path
	logContent, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	logString := string(logContent)
	if len(logString) == 0 {
		return make(map[string]bool) // Return empty map for empty log files
	}

	// Parse and verify JSON log entries
	lines := strings.Split(strings.TrimSpace(logString), "\n")
	foundLevels := make(map[string]bool)

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		var logEntry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
			t.Errorf("Invalid JSON log entry: %s, error: %v", line, err)
			continue
		}

		// Verify required fields
		validateLogEntry(t, logEntry)

		// Track log levels we've seen
		if level, ok := logEntry["level"].(string); ok {
			foundLevels[level] = true
		}
	}

	return foundLevels
}

// Helper function to validate log entry structure
func validateLogEntry(t *testing.T, logEntry map[string]interface{}) {
	t.Helper()

	if logEntry["time"] == nil {
		t.Error("Log entry missing 'time' field")
	}
	if logEntry["level"] == nil {
		t.Error("Log entry missing 'level' field")
	}
	if logEntry["msg"] == nil {
		t.Error("Log entry missing 'msg' field")
	}
	if logEntry["component"] != "CrowdsecBouncerTraefikPlugin" {
		t.Errorf("Expected component 'CrowdsecBouncerTraefikPlugin', got %v", logEntry["component"])
	}
}

// Helper function to verify expected and forbidden log levels
func verifyLogLevels(t *testing.T, foundLevels map[string]bool, expectedLevels, forbiddenLevels []string, logLevel string) {
	t.Helper()

	// Handle case where no logs are expected
	if len(expectedLevels) == 0 {
		if len(foundLevels) > 0 {
			t.Errorf("Expected no logs at %s level, but found: %v", logLevel, foundLevels)
		}
	} else {
		// Verify we got some log entries
		if len(foundLevels) == 0 {
			t.Fatal("No valid log entries found")
		}

		// Verify expected levels are present
		for _, expectedLevel := range expectedLevels {
			if !foundLevels[expectedLevel] {
				t.Errorf("Expected to find %s level logs, but didn't. Found levels: %v", expectedLevel, foundLevels)
			}
		}
	}

	// Verify forbidden levels are NOT present
	for _, forbiddenLevel := range forbiddenLevels {
		if foundLevels[forbiddenLevel] {
			t.Errorf("Found forbidden %s level logs at %s level. Found levels: %v", forbiddenLevel, logLevel, foundLevels)
		}
	}
}

func TestBouncerFileLoggingLevels(t *testing.T) {
	tests := []struct {
		name            string
		logLevel        string
		expectedLevels  []string // Levels that should appear
		forbiddenLevels []string // Levels that should NOT appear
	}{
		{
			name:            "TRACE level should show TRACE and DEBUG (bouncer's actual log levels)",
			logLevel:        "TRACE",
			expectedLevels:  []string{"TRACE", "DEBUG"},
			forbiddenLevels: []string{}, // All levels that appear should be allowed
		},
		{
			name:            "DEBUG level should show DEBUG only (no TRACE)",
			logLevel:        "DEBUG",
			expectedLevels:  []string{"DEBUG"},
			forbiddenLevels: []string{"TRACE"},
		},
		{
			name:            "INFO level should show no logs (bouncer doesn't generate INFO during normal operation)",
			logLevel:        "INFO",
			expectedLevels:  []string{}, // No logs expected for normal operation
			forbiddenLevels: []string{"TRACE", "DEBUG"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory for log file
			tmpDir := t.TempDir()
			logFile := filepath.Join(tmpDir, "bouncer.log")

			// Get test config and override specific fields
			config := getTestConfig()
			config.LogLevel = tt.logLevel
			config.LogFormat = "json" // Use JSON format for easier parsing
			config.LogFilePath = logFile

			// Create and execute bouncer request
			createAndExecuteBouncerRequest(t, config)

			// Parse log file and extract found levels
			foundLevels := parseLogFileAndExtractLevels(t, logFile)

			// Handle empty log files for higher log levels (expected behavior)
			if len(foundLevels) == 0 && len(tt.expectedLevels) > 0 {
				t.Fatalf("Expected log entries but log file is empty for level %s", tt.logLevel)
			}
			if len(foundLevels) == 0 {
				// Empty file is expected for this log level
				t.Logf("LogLevel %s: No logs generated (expected behavior)", tt.logLevel)
				return
			}

			// Verify expected and forbidden log levels
			verifyLogLevels(t, foundLevels, tt.expectedLevels, tt.forbiddenLevels, tt.logLevel)

			t.Logf("LogLevel %s: Successfully logged to file with levels: %v", tt.logLevel, foundLevels)
		})
	}
}

func TestBouncerFileLoggingCommonFormat(t *testing.T) {
	// Create temporary directory for log file
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "bouncer-common.log")

	// Get test config and override specific fields
	config := getTestConfig()
	config.LogLevel = "TRACE"   // Use TRACE to test our custom level
	config.LogFormat = "common" // Use common format
	config.LogFilePath = logFile

	// Create a mock next handler
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	// Create the bouncer plugin
	bouncerHandler, err := New(context.Background(), nextHandler, config, "test-bouncer")
	if err != nil {
		t.Fatalf("Failed to create bouncer: %v", err)
	}

	// Create a test request to trigger logging
	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	rw := httptest.NewRecorder()

	// Process the request
	bouncerHandler.ServeHTTP(rw, req)

	// Give a moment for log writes to complete
	time.Sleep(100 * time.Millisecond)

	// Verify the log file was created and contains entries
	if _, statErr := os.Stat(logFile); os.IsNotExist(statErr) {
		t.Fatalf("Log file was not created: %s", logFile)
	}

	// Read the log file content
	// #nosec G304 - logFile is a test-generated temporary file path
	logContent, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	logString := string(logContent)
	if len(logString) == 0 {
		t.Fatal("Log file is empty")
	}

	// Verify common format structure
	lines := strings.Split(strings.TrimSpace(logString), "\n")
	foundTrace := false

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Common format should contain time, level, msg, and component
		if strings.Contains(line, "level=TRACE") {
			foundTrace = true
		}
		if !strings.Contains(line, "component=CrowdsecBouncerTraefikPlugin") {
			t.Errorf("Log line missing component field: %s", line)
		}
	}

	// We should see TRACE level logs since we set LogLevel to TRACE
	if !foundTrace {
		t.Errorf("Expected to find TRACE level logs in common format. Log content:\n%s", logString)
	}

	t.Logf("Successfully logged to file %s in common format with %d lines", logFile, len(lines))
}
