package models

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStringArray_ScanValue(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected StringArray
		wantErr  bool
	}{
		{
			name:     "nil value",
			input:    nil,
			expected: StringArray{},
			wantErr:  false,
		},
		{
			name:     "json byte array",
			input:    []byte(`["scope1", "scope2"]`),
			expected: StringArray{"scope1", "scope2"},
			wantErr:  false,
		},
		{
			name:     "json string",
			input:    `["openid", "profile"]`,
			expected: StringArray{"openid", "profile"},
			wantErr:  false,
		},
		{
			name:     "empty array",
			input:    `[]`,
			expected: StringArray{},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s StringArray
			err := s.Scan(tt.input)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, s)
			}
		})
	}
}

func TestStringArray_Value(t *testing.T) {
	tests := []struct {
		name     string
		input    StringArray
		expected string
	}{
		{
			name:     "empty array",
			input:    StringArray{},
			expected: "{}",
		},
		{
			name:     "single item",
			input:    StringArray{"openid"},
			expected: `["openid"]`,
		},
		{
			name:     "multiple items",
			input:    StringArray{"openid", "profile", "email"},
			expected: `["openid","profile","email"]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, err := tt.input.Value()
			require.NoError(t, err)

			if tt.name == "empty array" {
				assert.Equal(t, tt.expected, value)
			} else {
				// For JSON arrays, we need to unmarshal and compare
				var expected, actual []string
				require.NoError(t, json.Unmarshal([]byte(tt.expected), &expected))
				
				// Value() returns []byte, not string
				valueBytes, ok := value.([]byte)
				require.True(t, ok, "Value should return []byte")
				require.NoError(t, json.Unmarshal(valueBytes, &actual))
				assert.Equal(t, expected, actual)
			}
		})
	}
}

func TestUser_BeforeCreate(t *testing.T) {
	user := &User{
		Email: "test@example.com",
	}

	// Mock GORM DB (nil is fine for this test)
	err := user.BeforeCreate(nil)

	assert.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, user.ID)
}

func TestOAuthClient_BeforeCreate(t *testing.T) {
	client := &OAuthClient{
		ClientID:   "test-client",
		ClientName: "Test Client",
	}

	err := client.BeforeCreate(nil)

	assert.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, client.ID)
}

func TestRefreshToken_BeforeCreate(t *testing.T) {
	token := &RefreshToken{
		Token:    "test-token",
		ClientID: "test-client",
		UserID:   uuid.New(),
	}

	err := token.BeforeCreate(nil)

	assert.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, token.TokenFamily)
}

func TestTableNames(t *testing.T) {
	tests := []struct {
		model    interface{ TableName() string }
		expected string
	}{
		{&User{}, "users"},
		{&OAuthClient{}, "oauth_clients"},
		{&SigningKey{}, "signing_keys"},
		{&AuthSession{}, "auth_sessions"},
		{&AuthCode{}, "auth_codes"},
		{&RefreshToken{}, "refresh_tokens"},
		{&LoginAttempt{}, "login_attempts"},
		{&PasswordResetToken{}, "password_reset_tokens"},
		{&AuditLog{}, "audit_log"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.model.TableName())
		})
	}
}

func TestModelStructure(t *testing.T) {
	// Test that all models have required fields
	t.Run("User model", func(t *testing.T) {
		user := User{
			Email:      "test@example.com",
			TFAEnabled: false,
			IsActive:   true,
		}
		assert.Equal(t, "test@example.com", user.Email)
		assert.False(t, user.TFAEnabled)
		assert.True(t, user.IsActive)
	})

	t.Run("AuthSession with IP", func(t *testing.T) {
		ip := net.ParseIP("192.168.1.1")
		session := AuthSession{
			SessionID: "test-session",
			UserID:    uuid.New(),
			IPAddress: &ip,
			ExpiresAt: time.Now().Add(time.Hour),
		}
		assert.Equal(t, "test-session", session.SessionID)
		assert.Equal(t, "192.168.1.1", session.IPAddress.String())
	})

	t.Run("LoginAttempt with IP", func(t *testing.T) {
		ip := net.ParseIP("10.0.0.1")
		attempt := LoginAttempt{
			Email:       "test@example.com",
			IPAddress:   ip,
			Successful:  false,
			AttemptedAt: time.Now(),
		}
		assert.Equal(t, "test@example.com", attempt.Email)
		assert.Equal(t, "10.0.0.1", attempt.IPAddress.String())
		assert.False(t, attempt.Successful)
	})
}