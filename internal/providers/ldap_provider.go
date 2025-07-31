package providers

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"auth/internal/config"
	"auth/internal/models"
	"auth/internal/repository"
	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
)

// LDAPProvider handles LDAP authentication
type LDAPProvider struct {
	repo   repository.Manager
	config *config.LDAPConfig
}

// NewLDAPProvider creates a new LDAP authentication provider
func NewLDAPProvider(repo repository.Manager, ldapConfig *config.LDAPConfig) *LDAPProvider {
	return &LDAPProvider{
		repo:   repo,
		config: ldapConfig,
	}
}

// GetProviderName returns the provider name
func (p *LDAPProvider) GetProviderName() string {
	return "ldap"
}

// SupportsRegistration indicates that LDAP provider does not support registration
func (p *LDAPProvider) SupportsRegistration() bool {
	return false // LDAP users are managed externally
}

// ValidateCredentials validates the format of LDAP credentials
func (p *LDAPProvider) ValidateCredentials(credentials map[string]string) error {
	username, hasUsername := credentials["username"]
	password, hasPassword := credentials["password"]

	if !hasUsername || username == "" {
		return ErrInvalidFormat
	}

	if !hasPassword || password == "" {
		return ErrInvalidFormat
	}

	return nil
}

// Authenticate performs LDAP authentication
func (p *LDAPProvider) Authenticate(ctx context.Context, credentials map[string]string) (*AuthResult, error) {
	username := credentials["username"]
	password := credentials["password"]

	// Connect to LDAP server
	conn, err := p.connectLDAP()
	if err != nil {
		return &AuthResult{
			Success:      false,
			ErrorCode:    "ldap_connection_failed",
			ErrorMessage: "Failed to connect to authentication server",
		}, nil
	}
	defer conn.Close()

	// Bind with service account for user lookup
	if err := conn.Bind(p.config.BindDN, p.config.BindPassword); err != nil {
		return &AuthResult{
			Success:      false,
			ErrorCode:    "ldap_bind_failed",
			ErrorMessage: "Authentication server error",
		}, nil
	}

	// Search for user
	userDN, userAttrs, err := p.searchUser(conn, username)
	if err != nil {
		return &AuthResult{
			Success:      false,
			ErrorCode:    "user_not_found",
			ErrorMessage: "Invalid username or password",
		}, nil
	}

	// Try to bind as the user (this validates their password)
	if err := conn.Bind(userDN, password); err != nil {
		return &AuthResult{
			Success:      false,
			ErrorCode:    "invalid_credentials",
			ErrorMessage: "Invalid username or password",
		}, nil
	}

	// Extract user information from LDAP attributes
	email := p.getAttributeValue(userAttrs, "mail")
	displayName := p.getAttributeValue(userAttrs, "displayName")
	if displayName == "" {
		displayName = p.getAttributeValue(userAttrs, "cn")
	}

	// Determine if user is admin based on group membership
	isAdmin := p.isUserAdmin(conn, userDN)
	userType := "user"
	if isAdmin {
		userType = "admin"
	}

	// Get or create user in local database
	user, err := p.getOrCreateUser(ctx, username, email, displayName, userDN, userType)
	if err != nil {
		return &AuthResult{
			Success:      false,
			ErrorCode:    "user_creation_failed",
			ErrorMessage: "Failed to create user account",
		}, nil
	}

	// Update last login time
	now := time.Now()
	user.LastLoginAt = &now
	p.repo.Repository().User.Update(ctx, user)

	// For admin users, 2FA is mandatory
	requiresTFA := isAdmin || user.TFAEnabled
	if requiresTFA {
		return &AuthResult{
			User:         user,
			Success:      false, // Not fully authenticated yet
			RequiresTFA:  true,
			TFAMethod:    "totp",
			ErrorCode:    "tfa_required",
			ErrorMessage: "Two-factor authentication required",
			Metadata: map[string]interface{}{
				"user_id":     user.ID.String(),
				"ldap_dn":     userDN,
				"admin_user":  isAdmin,
			},
		}, nil
	}

	// Successful authentication
	return &AuthResult{
		User:    user,
		Success: true,
		Metadata: map[string]interface{}{
			"provider":    "ldap",
			"auth_method": "ldap_bind",
			"ldap_dn":     userDN,
			"admin_user":  isAdmin,
		},
	}, nil
}

// connectLDAP establishes connection to LDAP server
func (p *LDAPProvider) connectLDAP() (*ldap.Conn, error) {
	address := fmt.Sprintf("%s:%d", p.config.Host, p.config.Port)
	
	// Try LDAPS first (secure), then fallback to LDAP
	conn, err := ldap.DialTLS("tcp", address, &tls.Config{
		ServerName:         p.config.Host,
		InsecureSkipVerify: false, // Set to true for self-signed certs in dev
	})
	
	if err != nil {
		// Fallback to plain LDAP
		conn, err = ldap.Dial("tcp", address)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
		}
	}

	return conn, nil
}

// searchUser searches for a user in LDAP directory
func (p *LDAPProvider) searchUser(conn *ldap.Conn, username string) (string, map[string][]string, error) {
	// Build search filter
	filter := fmt.Sprintf(p.config.UserFilter, ldap.EscapeFilter(username))
	
	// Perform search
	searchRequest := ldap.NewSearchRequest(
		p.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, // Size limit - we only expect one user
		0, // Time limit
		false, // Types only
		filter,
		[]string{"dn", "cn", "mail", "displayName", "memberOf", "userPrincipalName"},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return "", nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(sr.Entries) == 0 {
		return "", nil, fmt.Errorf("user not found in LDAP")
	}

	entry := sr.Entries[0]
	attrs := make(map[string][]string)
	for _, attr := range entry.Attributes {
		attrs[attr.Name] = attr.Values
	}

	return entry.DN, attrs, nil
}

// isUserAdmin checks if user is member of admin group
func (p *LDAPProvider) isUserAdmin(conn *ldap.Conn, userDN string) bool {
	if p.config.AdminGroup == "" {
		return false
	}

	// Search for admin group membership
	filter := fmt.Sprintf("(&(objectClass=group)(cn=%s)(member=%s))", 
		ldap.EscapeFilter(p.config.AdminGroup), 
		ldap.EscapeFilter(userDN))

	searchRequest := ldap.NewSearchRequest(
		p.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		filter,
		[]string{"dn"},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return false
	}

	return len(sr.Entries) > 0
}

// getOrCreateUser gets existing user or creates new one from LDAP info
func (p *LDAPProvider) getOrCreateUser(ctx context.Context, username, email, displayName, ldapDN, userType string) (*models.User, error) {
	// Try to find existing user by email or LDAP DN
	var user *models.User
	var err error

	if email != "" {
		user, err = p.repo.Repository().User.GetByEmail(ctx, email)
	}

	// If not found by email, try to find by LDAP DN
	if err != nil && ldapDN != "" {
		// This would require adding a method to find by LDAP DN
		// For now, we'll create a new user
		user = nil
	}

	if user == nil {
		// Create new user
		user = &models.User{
			ID:           uuid.New(),
			Email:        email,
			UserType:     userType,
			AuthProvider: "ldap",
			LdapDN:       &ldapDN,
			IsActive:     true,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		if err := p.repo.Repository().User.Create(ctx, user); err != nil {
			return nil, fmt.Errorf("failed to create user: %w", err)
		}
	} else {
		// Update existing user with latest LDAP info
		user.UserType = userType
		user.LdapDN = &ldapDN
		user.UpdatedAt = time.Now()
		
		if err := p.repo.Repository().User.Update(ctx, user); err != nil {
			return nil, fmt.Errorf("failed to update user: %w", err)
		}
	}

	return user, nil
}

// getAttributeValue gets the first value of an LDAP attribute
func (p *LDAPProvider) getAttributeValue(attrs map[string][]string, attrName string) string {
	if values, exists := attrs[attrName]; exists && len(values) > 0 {
		return values[0]
	}
	return ""
}

// VerifyLDAPConnection tests the LDAP connection and configuration
func (p *LDAPProvider) VerifyLDAPConnection() error {
	conn, err := p.connectLDAP()
	if err != nil {
		return err
	}
	defer conn.Close()

	// Try to bind with service account
	if err := conn.Bind(p.config.BindDN, p.config.BindPassword); err != nil {
		return fmt.Errorf("LDAP bind failed: %w", err)
	}

	return nil
}