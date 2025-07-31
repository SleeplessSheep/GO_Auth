package handlers

import (
	"net"
	"net/http"
	"time"

	"auth/internal/models"
	"auth/internal/providers"
	"auth/internal/repository"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// EnhancedAuthHandler handles multi-provider authentication
type EnhancedAuthHandler struct {
	repo      repository.Manager
	providers *providers.AuthProviderManager
}

// NewEnhancedAuthHandler creates a new enhanced auth handler
func NewEnhancedAuthHandler(repo repository.Manager, providerManager *providers.AuthProviderManager) *EnhancedAuthHandler {
	return &EnhancedAuthHandler{
		repo:      repo,
		providers: providerManager,
	}
}

// LoginWithProvider handles authentication with multiple providers
// POST /auth/login
func (h *EnhancedAuthHandler) LoginWithProvider(c *gin.Context) {
	var req struct {
		// Support both email/username
		Email    string `json:"email"`
		Username string `json:"username"`
		Password string `json:"password" binding:"required"`
		Provider string `json:"provider"` // Optional: "local", "ldap", "google"
		TFACode  string `json:"tfa_code"` // For 2FA completion
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid request format",
		})
		return
	}

	// Prepare credentials map
	credentials := map[string]string{
		"password": req.Password,
	}

	// Add identifier (email or username)
	if req.Email != "" {
		credentials["email"] = req.Email
	}
	if req.Username != "" {
		credentials["username"] = req.Username
	}

	// Add provider if specified
	if req.Provider != "" {
		credentials["provider"] = req.Provider
	}

	// Attempt authentication
	result, err := h.providers.TryAuthenticate(c.Request.Context(), credentials)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error", 
			"error_description": "Authentication failed",
		})
		return
	}

	// Handle different authentication results
	switch {
	case result.RequiresTFA:
		// 2FA required
		c.JSON(http.StatusOK, gin.H{
			"success":       false,
			"requires_tfa":  true,
			"tfa_method":    result.TFAMethod,
			"message":       "Two-factor authentication required",
			"session_token": h.createTempSession(result.User.ID), // Temp session for 2FA
		})
		return

	case !result.Success:
		// Authentication failed
		h.logAuthEvent(c, nil, "login_failed", false)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             result.ErrorCode,
			"error_description": result.ErrorMessage,
		})
		return

	default:
		// Authentication successful
		_, err := h.createFullSession(c, result.User)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":             "server_error",
				"error_description": "Failed to create session",
			})
			return
		}

		h.logAuthEvent(c, result.User, "login_success", true)

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Login successful",
			"user": gin.H{
				"id":            result.User.ID,
				"email":         result.User.Email,
				"user_type":     result.User.UserType,
				"auth_provider": result.User.AuthProvider,
			},
			"provider_info": result.Metadata,
		})
	}
}

// GetAvailableProviders returns list of available authentication providers
// GET /auth/providers
func (h *EnhancedAuthHandler) GetAvailableProviders(c *gin.Context) {
	providers := make([]gin.H, 0)

	for name, provider := range h.providers.GetProviders() {
		providers = append(providers, gin.H{
			"name":                 name,
			"display_name":         h.getProviderDisplayName(name),
			"supports_registration": provider.SupportsRegistration(),
			"description":          h.getProviderDescription(name),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"providers": providers,
	})
}

// RegisterWithProvider handles user registration (local provider only)
// POST /auth/register
func (h *EnhancedAuthHandler) RegisterWithProvider(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=8"`
		Provider string `json:"provider"` // Optional, defaults to "local"
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid registration data",
		})
		return
	}

	// Default to local provider
	providerName := "local"
	if req.Provider != "" {
		providerName = req.Provider
	}

	// Get provider
	provider, exists := h.providers.GetProvider(providerName)
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "provider_not_found",
			"error_description": "Authentication provider not found",
		})
		return
	}

	// Check if provider supports registration
	if !provider.SupportsRegistration() {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "registration_not_supported",
			"error_description": "This provider does not support registration",
		})
		return
	}

	// Only local provider currently supports registration
	localProvider, ok := provider.(*providers.LocalProvider)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "registration_not_supported",
			"error_description": "Registration not available for this provider",
		})
		return
	}

	// Perform registration
	userData := map[string]string{
		"email":    req.Email,
		"password": req.Password,
	}

	result, err := localProvider.RegisterUser(c.Request.Context(), userData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Registration failed",
		})
		return
	}

	if !result.Success {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             result.ErrorCode,
			"error_description": result.ErrorMessage,
		})
		return
	}

	// Log registration event
	h.logAuthEvent(c, result.User, "register", true)

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"message": "User registered successfully",
		"user": gin.H{
			"id":            result.User.ID,
			"email":         result.User.Email,
			"user_type":     result.User.UserType,
			"auth_provider": result.User.AuthProvider,
		},
	})
}

// Helper methods

func (h *EnhancedAuthHandler) createFullSession(c *gin.Context, user *models.User) (*models.AuthSession, error) {
	sessionID := "sess_" + uuid.New().String()
	session := &models.AuthSession{
		SessionID: sessionID,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24 hour session
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := h.repo.Repository().AuthSession.Create(c.Request.Context(), session); err != nil {
		return nil, err
	}

	// Set session cookie
	c.SetCookie(
		"session_id",
		sessionID,
		int((24 * time.Hour).Seconds()),
		"/",
		"", // Domain will be set by browser
		true, // Secure (HTTPS only)
		true, // HttpOnly
	)

	return session, nil
}

func (h *EnhancedAuthHandler) createTempSession(userID uuid.UUID) string {
	// Create temporary session for 2FA completion (shorter duration)
	return "temp_" + uuid.New().String()
	// TODO: Store in Redis with 5-10 minute expiry
}

func (h *EnhancedAuthHandler) getProviderDisplayName(name string) string {
	switch name {
	case "local":
		return "Email & Password"
	case "ldap":
		return "Corporate Directory (LDAP)"
	case "google":
		return "Google Account"
	default:
		return name
	}
}

func (h *EnhancedAuthHandler) getProviderDescription(name string) string {
	switch name {
	case "local":
		return "Sign in with your email and password"
	case "ldap":
		return "Sign in with your corporate directory credentials"
	case "google":
		return "Sign in with your Google account"
	default:
		return "External authentication provider"
	}
}

// logAuthEvent logs authentication events for audit
func (h *EnhancedAuthHandler) logAuthEvent(c *gin.Context, user *models.User, eventType string, success bool) {
	userAgent := c.GetHeader("User-Agent")
	
	// Parse IP address
	var ipPtr *net.IP
	if ipStr := c.ClientIP(); ipStr != "" {
		if ip := net.ParseIP(ipStr); ip != nil {
			ipPtr = &ip
		}
	}

	var userEmail string
	var userID *string
	if user != nil {
		userEmail = user.Email
		userIDStr := user.ID.String()
		userID = &userIDStr
	}

	auditLog := &models.AuditLog{
		EventType:     eventType,
		EventCategory: "authentication",
		ActorType:     "user",
		ActorID:       userID,
		Success:       success,
		IPAddress:     ipPtr,
		UserAgent:     &userAgent,
		Metadata: map[string]interface{}{
			"user_email":        userEmail,
			"correlation_id":    c.GetString("correlation_id"),
		},
		OccurredAt: time.Now(),
	}

	h.repo.Repository().AuditLog.Create(c.Request.Context(), auditLog)
}