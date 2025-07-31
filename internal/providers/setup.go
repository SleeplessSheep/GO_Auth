package providers

import (
	"auth/internal/config"
	"auth/internal/repository"
	"fmt"
)

// SetupProviders initializes and configures all authentication providers
func SetupProviders(repo repository.Manager, cfg *config.Config) (*AuthProviderManager, error) {
	manager := NewAuthProviderManager()

	// 1. Register Local Provider (always available)
	localProvider := NewLocalProvider(repo)
	manager.RegisterProvider("local", localProvider)

	// 2. Register LDAP Provider (if configured)
	if cfg.LDAP.Host != "" {
		ldapProvider := NewLDAPProvider(repo, &cfg.LDAP)
		
		// Test LDAP connection during setup
		if err := ldapProvider.VerifyLDAPConnection(); err != nil {
			// Log warning but don't fail startup
			fmt.Printf("Warning: LDAP connection failed, provider disabled: %v\n", err)
		} else {
			manager.RegisterProvider("ldap", ldapProvider)
			fmt.Println("LDAP authentication provider enabled")
		}
	}

	// 3. Register Google OAuth Provider (if configured)
	if cfg.Google.ClientID != "" && cfg.Google.ClientSecret != "" {
		// TODO: Implement Google OAuth provider
		fmt.Println("Google OAuth provider configured (implementation pending)")
	}

	// Set primary provider based on configuration
	primaryProvider := "local" // Default
	// TODO: Add PrimaryProvider field to config.AuthConfig when needed
	
	manager.SetPrimaryProvider(primaryProvider)
	fmt.Printf("Primary authentication provider: %s\n", primaryProvider)

	return manager, nil
}

// GetProviderStatus returns status information about all providers
func GetProviderStatus(manager *AuthProviderManager) map[string]interface{} {
	status := make(map[string]interface{})
	
	for name, provider := range manager.GetProviders() {
		providerStatus := map[string]interface{}{
			"name":                 name,
			"available":            true,
			"supports_registration": provider.SupportsRegistration(),
		}

		// Add provider-specific status checks
		switch name {
		case "ldap":
			if ldapProvider, ok := provider.(*LDAPProvider); ok {
				if err := ldapProvider.VerifyLDAPConnection(); err != nil {
					providerStatus["available"] = false
					providerStatus["error"] = err.Error()
				}
			}
		}

		status[name] = providerStatus
	}

	return status
}