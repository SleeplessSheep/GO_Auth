package config

import (
	"os"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	// Test with environment variables
	os.Setenv("AUTH_SERVER_PORT", "9090")
	os.Setenv("AUTH_DATABASE_NAME", "test_db")
	os.Setenv("AUTH_AUTH_MASTER_ENCRYPTION_KEY", "test-key-32-bytes-for-testing!!")
	
	defer func() {
		os.Unsetenv("AUTH_SERVER_PORT")
		os.Unsetenv("AUTH_DATABASE_NAME")
		os.Unsetenv("AUTH_AUTH_MASTER_ENCRYPTION_KEY")
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Test that environment variables override defaults
	if cfg.Server.Port != 9090 {
		t.Errorf("Expected port 9090, got %d", cfg.Server.Port)
	}

	if cfg.Database.Name != "test_db" {
		t.Errorf("Expected database name 'test_db', got %s", cfg.Database.Name)
	}

	if cfg.Auth.MasterEncryptionKey != "test-key-32-bytes-for-testing!!" {
		t.Errorf("Expected master key to be set from environment, got: %s", cfg.Auth.MasterEncryptionKey)
	}
}

func TestConfigDefaults(t *testing.T) {
	// Clear any existing env vars that might interfere
	os.Unsetenv("AUTH_AUTH_MASTER_ENCRYPTION_KEY")
	
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Test defaults
	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("Expected default host '0.0.0.0', got %s", cfg.Server.Host)
	}

	if cfg.Server.Port != 8080 {
		t.Errorf("Expected default port 8080, got %d", cfg.Server.Port)
	}

	if cfg.Database.Name != "auth_db" {
		t.Errorf("Expected default database name 'auth_db', got %s", cfg.Database.Name)
	}

	if cfg.Auth.AccessTokenExpiry != 15*time.Minute {
		t.Errorf("Expected default access token expiry 15m, got %v", cfg.Auth.AccessTokenExpiry)
	}
}

func TestConfigValidation(t *testing.T) {
	// Test validation failure - production without master key
	os.Setenv("AUTH_SERVER_ENVIRONMENT", "production")
	os.Setenv("AUTH_AUTH_MASTER_ENCRYPTION_KEY", "")
	defer func() {
		os.Unsetenv("AUTH_SERVER_ENVIRONMENT")
		os.Unsetenv("AUTH_AUTH_MASTER_ENCRYPTION_KEY")
	}()

	_, err := Load()
	if err == nil {
		t.Error("Expected config validation to fail in production without master encryption key")
	}
}