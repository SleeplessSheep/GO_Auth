package providers

import (
	"context"
	"strings"
	"time"

	"auth/internal/models"
	"auth/internal/repository"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// LocalProvider handles local database authentication
type LocalProvider struct {
	repo repository.Manager
}

// NewLocalProvider creates a new local authentication provider
func NewLocalProvider(repo repository.Manager) *LocalProvider {
	return &LocalProvider{
		repo: repo,
	}
}

// GetProviderName returns the provider name
func (p *LocalProvider) GetProviderName() string {
	return "local"
}

// SupportsRegistration indicates that local provider supports registration
func (p *LocalProvider) SupportsRegistration() bool {
	return true
}

// ValidateCredentials validates the format of credentials
func (p *LocalProvider) ValidateCredentials(credentials map[string]string) error {
	email, hasEmail := credentials["email"]
	_, hasUsername := credentials["username"]
	password, hasPassword := credentials["password"]

	// Must have either email or username
	if !hasEmail && !hasUsername {
		return ErrInvalidFormat
	}

	// Must have password
	if !hasPassword || password == "" {
		return ErrInvalidFormat
	}

	// If email is provided, validate format
	if hasEmail && email != "" {
		if !isValidEmail(email) {
			return ErrInvalidFormat
		}
	}

	return nil
}

// Authenticate performs local database authentication
func (p *LocalProvider) Authenticate(ctx context.Context, credentials map[string]string) (*AuthResult, error) {
	email, hasEmail := credentials["email"]
	username, hasUsername := credentials["username"]
	password := credentials["password"]

	// Determine identifier (email takes precedence)
	identifier := email
	if !hasEmail || email == "" {
		identifier = username
	}

	// Get user from database
	var user *models.User
	var err error

	if hasEmail && email != "" {
		user, err = p.repo.Repository().User.GetByEmail(ctx, email)
	} else if hasUsername && username != "" {
		// Assume username is also stored in email field for now
		// In future, you might add a separate username field
		user, err = p.repo.Repository().User.GetByEmail(ctx, username)
	}

	if err != nil {
		// Log failed attempt
		p.logLoginAttempt(ctx, identifier, false, "user_not_found")
		return &AuthResult{
			Success:      false,
			ErrorCode:    "invalid_credentials",
			ErrorMessage: "Invalid email or password",
		}, nil
	}

	// Check if user is active
	if !user.IsActive {
		p.logLoginAttempt(ctx, identifier, false, "account_disabled")
		return &AuthResult{
			Success:      false,
			ErrorCode:    "account_disabled",
			ErrorMessage: "Account has been disabled",
		}, nil
	}

	// Check if user has a password (not OAuth-only user) 
	if user.PasswordHash == nil {
		p.logLoginAttempt(ctx, identifier, false, "no_password")
		return &AuthResult{
			Success:      false,
			ErrorCode:    "external_auth_required",
			ErrorMessage: "This account uses external authentication",
		}, nil
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(*user.PasswordHash), []byte(password)); err != nil {
		p.logLoginAttempt(ctx, identifier, false, "invalid_password")
		return &AuthResult{
			Success:      false,
			ErrorCode:    "invalid_credentials",
			ErrorMessage: "Invalid email or password",
		}, nil
	}

	// Update last login time
	now := time.Now()
	user.LastLoginAt = &now
	p.repo.Repository().User.Update(ctx, user)

	// Log successful attempt
	p.logLoginAttempt(ctx, identifier, true, "")

	// Check if 2FA is enabled
	requiresTFA := user.TFAEnabled
	if requiresTFA {
		return &AuthResult{
			User:         user,
			Success:      false, // Not fully authenticated yet
			RequiresTFA:  true,
			TFAMethod:    "totp", // Assuming TOTP for now
			ErrorCode:    "tfa_required",
			ErrorMessage: "Two-factor authentication required",
			Metadata: map[string]interface{}{
				"user_id": user.ID.String(),
			},
		}, nil
	}

	// Successful authentication
	return &AuthResult{
		User:    user,
		Success: true,
		Metadata: map[string]interface{}{
			"provider":    "local",
			"auth_method": "password",
		},
	}, nil
}

// RegisterUser creates a new local user account
func (p *LocalProvider) RegisterUser(ctx context.Context, userData map[string]string) (*AuthResult, error) {
	email := userData["email"]
	password := userData["password"]

	// Validate input
	if email == "" || password == "" {
		return &AuthResult{
			Success:      false,
			ErrorCode:    "invalid_input",
			ErrorMessage: "Email and password are required",
		}, nil
	}

	if !isValidEmail(email) {
		return &AuthResult{
			Success:      false,
			ErrorCode:    "invalid_email",
			ErrorMessage: "Invalid email format",
		}, nil
	}

	// Check if user already exists
	if _, err := p.repo.Repository().User.GetByEmail(ctx, email); err == nil {
		return &AuthResult{
			Success:      false,
			ErrorCode:    "user_exists",
			ErrorMessage: "User with this email already exists",
		}, nil
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return &AuthResult{
			Success:      false,
			ErrorCode:    "internal_error",
			ErrorMessage: "Failed to process password",
		}, nil
	}

	// Create user
	passwordHashStr := string(hashedPassword)
	user := &models.User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: &passwordHashStr,
		UserType:     "user", // Default to regular user
		AuthProvider: "local",
		IsActive:     true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := p.repo.Repository().User.Create(ctx, user); err != nil {
		return &AuthResult{
			Success:      false,
			ErrorCode:    "internal_error",
			ErrorMessage: "Failed to create user account",
		}, nil
	}

	return &AuthResult{
		User:    user,
		Success: true,
		Metadata: map[string]interface{}{
			"provider": "local",
			"action":   "registration",
		},
	}, nil
}

// logLoginAttempt logs authentication attempts for audit and rate limiting
func (p *LocalProvider) logLoginAttempt(ctx context.Context, identifier string, success bool, failureReason string) {
	// This would typically get client IP from context
	// For now, we'll create a basic log entry
	
	loginAttempt := &models.LoginAttempt{
		ID:            uuid.New(),
		Email:         identifier,
		Successful:    success,
		AttemptedAt:   time.Now(),
	}

	if !success && failureReason != "" {
		loginAttempt.FailureReason = &failureReason
	}

	// Save login attempt (ignore errors for now)
	p.repo.Repository().LoginAttempt.Create(ctx, loginAttempt)
}

// Helper function to validate email format
func isValidEmail(email string) bool {
	// Basic email validation
	if len(email) < 3 {
		return false
	}

	atIndex := strings.LastIndex(email, "@")
	if atIndex < 1 || atIndex == len(email)-1 {
		return false
	}

	dotIndex := strings.LastIndex(email, ".")
	if dotIndex < atIndex+2 || dotIndex == len(email)-1 {
		return false
	}

	return true
}