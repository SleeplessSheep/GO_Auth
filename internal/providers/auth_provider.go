package providers

import (
	"context"
	"errors"

	"auth/internal/models"
)

// AuthProvider defines the interface for authentication providers
type AuthProvider interface {
	// Authenticate verifies user credentials and returns user info
	Authenticate(ctx context.Context, credentials map[string]string) (*AuthResult, error)
	
	// GetProviderName returns the name of the provider
	GetProviderName() string
	
	// SupportsRegistration indicates if this provider allows user registration
	SupportsRegistration() bool
	
	// ValidateCredentials checks if credentials are in correct format
	ValidateCredentials(credentials map[string]string) error
}

// AuthResult contains the result of authentication
type AuthResult struct {
	User          *models.User  // User information
	Success       bool          // Authentication success
	RequiresTFA   bool          // Whether 2FA is required
	TFAMethod     string        // 2FA method (totp, sms, etc.)
	ErrorCode     string        // Error code if failed
	ErrorMessage  string        // Human-readable error message
	Metadata      map[string]interface{} // Provider-specific metadata
}

// Common authentication errors
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound      = errors.New("user not found")
	ErrUserDisabled      = errors.New("user account disabled")
	ErrTFARequired       = errors.New("two-factor authentication required")
	ErrProviderError     = errors.New("authentication provider error")
	ErrInvalidFormat     = errors.New("invalid credential format")
)

// AuthProviderManager manages multiple authentication providers
type AuthProviderManager struct {
	providers map[string]AuthProvider
	primary   string // Primary provider name
}

// NewAuthProviderManager creates a new provider manager
func NewAuthProviderManager() *AuthProviderManager {
	return &AuthProviderManager{
		providers: make(map[string]AuthProvider),
		primary:   "local", // Default to local authentication
	}
}

// RegisterProvider registers a new authentication provider
func (m *AuthProviderManager) RegisterProvider(name string, provider AuthProvider) {
	m.providers[name] = provider
}

// GetProvider returns a provider by name
func (m *AuthProviderManager) GetProvider(name string) (AuthProvider, bool) {
	provider, exists := m.providers[name]
	return provider, exists
}

// GetProviders returns all registered providers
func (m *AuthProviderManager) GetProviders() map[string]AuthProvider {
	return m.providers
}

// SetPrimaryProvider sets the primary authentication provider
func (m *AuthProviderManager) SetPrimaryProvider(name string) error {
	if _, exists := m.providers[name]; !exists {
		return errors.New("provider not found")
	}
	m.primary = name
	return nil
}

// GetPrimaryProvider returns the primary provider
func (m *AuthProviderManager) GetPrimaryProvider() (AuthProvider, error) {
	if provider, exists := m.providers[m.primary]; exists {
		return provider, nil
	}
	return nil, errors.New("primary provider not found")
}

// AuthenticateWithProvider attempts authentication with a specific provider
func (m *AuthProviderManager) AuthenticateWithProvider(ctx context.Context, providerName string, credentials map[string]string) (*AuthResult, error) {
	provider, exists := m.providers[providerName]
	if !exists {
		return &AuthResult{
			Success:      false,
			ErrorCode:    "provider_not_found",
			ErrorMessage: "Authentication provider not found",
		}, nil
	}

	// Validate credentials format first
	if err := provider.ValidateCredentials(credentials); err != nil {
		return &AuthResult{
			Success:      false,
			ErrorCode:    "invalid_format",
			ErrorMessage: "Invalid credential format",
		}, nil
	}

	return provider.Authenticate(ctx, credentials)
}

// TryAuthenticate attempts authentication with multiple providers in order
func (m *AuthProviderManager) TryAuthenticate(ctx context.Context, credentials map[string]string) (*AuthResult, error) {
	// Determine which provider to use based on credentials or user preference
	providerName := m.determineProvider(credentials)
	
	return m.AuthenticateWithProvider(ctx, providerName, credentials)
}

// determineProvider determines which provider to use based on credentials
func (m *AuthProviderManager) determineProvider(credentials map[string]string) string {
	// Check if provider is explicitly specified
	if provider, exists := credentials["provider"]; exists {
		if _, providerExists := m.providers[provider]; providerExists {
			return provider
		}
	}

	// Check for LDAP indicators (domain in username)
	if username, exists := credentials["username"]; exists {
		// If username contains domain (user@domain.com), try LDAP
		if len(username) > 0 && (contains(username, "@") || contains(username, "\\")) {
			if _, exists := m.providers["ldap"]; exists {
				return "ldap"
			}
		}
	}

	// Default to primary provider (usually local)
	return m.primary
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}