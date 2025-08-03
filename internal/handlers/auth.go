package handlers

import (
	"net"
	"net/http"
	"time"

	"auth/internal/models"
	"auth/internal/repository"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// AuthHandler handles authentication endpoints
type AuthHandler struct {
	repo repository.Manager
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(repo repository.Manager) *AuthHandler {
	return &AuthHandler{
		repo: repo,
	}
}

// LoginPage renders the login form
// GET /auth/login
func (h *AuthHandler) LoginPage(c *gin.Context) {
	returnURL := c.Query("return_url")
	
	// Check if user is already logged in
	if _, exists := c.Get("user_id"); exists {
		if returnURL != "" {
			c.Redirect(http.StatusFound, returnURL)
		} else {
			c.Redirect(http.StatusFound, "/dashboard")
		}
		return
	}
	
	// Render login page template
	c.HTML(http.StatusOK, "login.html", gin.H{
		"title":         "SleeplessSheep's Auth Server",
		"return_url":    returnURL,
		"google_enabled": true, // TODO: Check if Google OAuth is configured
	})
}

// Login handles user authentication
// POST /auth/login
func (h *AuthHandler) Login(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid_request",
			"error_description": "Invalid email or password format",
		})
		return
	}
	
	// Get user by email
	user, err := h.repo.Repository().User.GetByEmail(c.Request.Context(), req.Email)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid_credentials",
			"error_description": "Invalid email or password",
		})
		return
	}
	
	// Check if user has a password (not OAuth-only user)
	if user.PasswordHash == nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid_credentials",
			"error_description": "This account uses external authentication",
		})
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(*user.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid_credentials",
			"error_description": "Invalid email or password",
		})
		return
	}
	
	// Update last login time
	now := time.Now()
	user.LastLoginAt = &now
	if err := h.repo.Repository().User.Update(c.Request.Context(), user); err != nil {
		// Log error but don't fail login
	}
	
	// Create session
	sessionID := "sess_" + uuid.New().String()
	session := &models.AuthSession{
		SessionID: sessionID,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24 hour session
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	if err := h.repo.Repository().AuthSession.Create(c.Request.Context(), session); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "server_error",
			"error_description": "Failed to create session",
		})
		return
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
	
	// Log successful authentication
	h.logAuthEvent(c, user, "login", true)
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"user": gin.H{
			"id":            user.ID,
			"email":         user.Email,
			"user_type":     user.UserType,
			"auth_provider": user.AuthProvider,
		},
	})
}

// Logout handles user logout
// POST /auth/logout
func (h *AuthHandler) Logout(c *gin.Context) {
	// Get session ID from cookie
	sessionID, err := c.Cookie("session_id")
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"message": "Already logged out",
		})
		return
	}
	
	// Get user info for logging (if session exists)
	var user *models.User
	if sessionID != "" {
		if session, err := h.repo.Repository().AuthSession.GetBySessionID(c.Request.Context(), sessionID); err == nil {
			if u, err := h.repo.Repository().User.GetByID(c.Request.Context(), session.UserID); err == nil {
				user = u
			}
		}
	}
	
	// Delete session from database
	if sessionID != "" {
		h.repo.Repository().AuthSession.DeleteBySessionID(c.Request.Context(), sessionID)
	}
	
	// Clear session cookie
	c.SetCookie(
		"session_id",
		"",
		-1,
		"/",
		"",
		true,
		true,
	)
	
	// Log logout event
	if user != nil {
		h.logAuthEvent(c, user, "logout", true)
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Logout successful",
	})
}

// Register handles user registration
// POST /auth/register
func (h *AuthHandler) Register(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=8"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid_request",
			"error_description": "Invalid registration data",
		})
		return
	}
	
	// Check if user already exists
	if _, err := h.repo.Repository().User.GetByEmail(c.Request.Context(), req.Email); err == nil {
		c.JSON(http.StatusConflict, gin.H{
			"error": "user_exists",
			"error_description": "User with this email already exists",
		})
		return
	}
	
	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "server_error",
			"error_description": "Failed to process password",
		})
		return
	}
	
	// Create user
	passwordHashPtr := string(hashedPassword)
	user := &models.User{
		ID:           uuid.New(),
		Email:        req.Email,
		PasswordHash: &passwordHashPtr,
		UserType:     "user", // Default to regular user
		AuthProvider: "local",
		IsActive:     true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	
	if err := h.repo.Repository().User.Create(c.Request.Context(), user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "server_error",
			"error_description": "Failed to create user",
		})
		return
	}
	
	// Log registration event
	h.logAuthEvent(c, user, "register", true)
	
	c.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully",
		"user": gin.H{
			"id":            user.ID,
			"email":         user.Email,
			"user_type":     user.UserType,
			"auth_provider": user.AuthProvider,
		},
	})
}

// Profile returns user profile information
// GET /auth/profile
func (h *AuthHandler) Profile(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "unauthorized",
			"error_description": "Authentication required",
		})
		return
	}
	
	uid, ok := userID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "server_error",
			"error_description": "Invalid user session",
		})
		return
	}
	
	user, err := h.repo.Repository().User.GetByID(c.Request.Context(), uid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "user_not_found",
			"error_description": "User not found",
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"user": gin.H{
			"id":            user.ID,
			"email":         user.Email,
			"user_type":     user.UserType,
			"auth_provider": user.AuthProvider,
			"is_active":     user.IsActive,
			"tfa_enabled":   user.TFAEnabled,
			"created_at":    user.CreatedAt,
			"last_login_at": user.LastLoginAt,
		},
	})
}

// logAuthEvent logs authentication events for audit
func (h *AuthHandler) logAuthEvent(c *gin.Context, user *models.User, eventType string, success bool) {
	userAgent := c.GetHeader("User-Agent")
	
	// Parse IP address
	var ipPtr *net.IP
	if ipStr := c.ClientIP(); ipStr != "" {
		if ip := net.ParseIP(ipStr); ip != nil {
			ipPtr = &ip
		}
	}
	
	auditLog := &models.AuditLog{
		EventType:     eventType,
		EventCategory: "authentication",
		ActorType:     "user",
		ActorID:       func() *string { s := user.ID.String(); return &s }(),
		Success:       success,
		IPAddress:     ipPtr,
		UserAgent:     &userAgent,
		Metadata: map[string]interface{}{
			"user_email":     user.Email,
			"user_type":      user.UserType,
			"auth_provider":  user.AuthProvider,
		},
		OccurredAt: time.Now(),
	}
	
	h.repo.Repository().AuditLog.Create(c.Request.Context(), auditLog)
}