package logger

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		expectLevel logrus.Level
		expectJSON  bool
	}{
		{
			name:        "production environment",
			environment: "production",
			expectLevel: logrus.InfoLevel,
			expectJSON:  true,
		},
		{
			name:        "development environment",
			environment: "development",
			expectLevel: logrus.DebugLevel,
			expectJSON:  false,
		},
		{
			name:        "unknown environment defaults to debug",
			environment: "unknown",
			expectLevel: logrus.DebugLevel,
			expectJSON:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := New(tt.environment)

			if logger.Level != tt.expectLevel {
				t.Errorf("Expected log level %v, got %v", tt.expectLevel, logger.Level)
			}

			// Check formatter type
			_, isJSON := logger.Formatter.(*logrus.JSONFormatter)
			if tt.expectJSON && !isJSON {
				t.Error("Expected JSON formatter in production")
			}
			if !tt.expectJSON && isJSON {
				t.Error("Expected text formatter in development")
			}
		})
	}
}

func TestLogAuthEvent(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	logger := New("development")
	logger.SetOutput(&buf)

	logger.LogAuthEvent("user123", "login", "192.168.1.1", true)

	output := buf.String()
	
	// Check that the log contains expected fields
	expectedFields := []string{"user123", "login", "192.168.1.1", "auth_event"}
	for _, field := range expectedFields {
		if !strings.Contains(output, field) {
			t.Errorf("Expected log output to contain %s, got: %s", field, output)
		}
	}
}

func TestLogKeyOperation(t *testing.T) {
	var buf bytes.Buffer
	logger := New("development")
	logger.SetOutput(&buf)

	logger.LogKeyOperation("rotation", "key-123")

	output := buf.String()
	
	expectedFields := []string{"rotation", "key-123", "key_operation"}
	for _, field := range expectedFields {
		if !strings.Contains(output, field) {
			t.Errorf("Expected log output to contain %s, got: %s", field, output)
		}
	}
}

func TestLogSystemEvent(t *testing.T) {
	var buf bytes.Buffer
	logger := New("development")
	logger.SetOutput(&buf)

	details := map[string]interface{}{
		"component": "auth-server",
		"version":   "1.0.0",
	}
	logger.LogSystemEvent("startup", details)

	output := buf.String()
	
	expectedFields := []string{"startup", "system_event", "auth-server", "1.0.0"}
	for _, field := range expectedFields {
		if !strings.Contains(output, field) {
			t.Errorf("Expected log output to contain %s, got: %s", field, output)
		}
	}
}