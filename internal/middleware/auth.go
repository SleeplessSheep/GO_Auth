package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"auth/internal/jwt"
	"auth/internal/models"
	"auth/internal/repository"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// AuthMiddleware provides authentication middleware
type AuthMiddleware struct {
	repo       repository.Manager
	jwtService *jwt.Service
}

// NewAuthMiddleware creates a new auth middleware
func NewAuthMiddleware(repo repository.Manager, jwtService *jwt.Service) *AuthMiddleware {
	return &AuthMiddleware{
		repo:       repo,
		jwtService: jwtService,
	}
}

// SessionAuth middleware for session-based authentication (cookies)
func (m *AuthMiddleware) SessionAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get session ID from cookie
		sessionID, err := c.Cookie("session_id")
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized",
				"error_description": "No session found",
			})
			return
		}
		
		// Get session from database
		session, err := m.repo.Repository().AuthSession.GetBySessionID(c.Request.Context(), sessionID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized",
				"error_description": "Invalid session",
			})
			return
		}
		
		// Check if session is expired
		if session.IsExpired() {
			// Clean up expired session
			m.repo.Repository().AuthSession.DeleteBySessionID(c.Request.Context(), sessionID)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized",
				"error_description": "Session expired",
			})
			return
		}
		
		// Get user
		user, err := m.repo.Repository().User.GetByID(c.Request.Context(), session.UserID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized",
				"error_description": "User not found",
			})
			return
		}
		
		// Check if user is active
		if !user.IsActive {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized",
				"error_description": "User account disabled",
			})
			return
		}
		
		// Set user context
		c.Set("user_id", user.ID)
		c.Set("user", user)
		c.Set("session_id", sessionID)
		
		c.Next()
	}
}

// OptionalSessionAuth middleware for optional session authentication
func (m *AuthMiddleware) OptionalSessionAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get session ID from cookie
		sessionID, err := c.Cookie("session_id")
		if err != nil {
			// No session, continue without auth
			c.Next()
			return
		}
		
		// Get session from database
		session, err := m.repo.Repository().AuthSession.GetBySessionID(c.Request.Context(), sessionID)
		if err != nil {
			// Invalid session, continue without auth
			c.Next()
			return
		}
		
		// Check if session is expired
		if session.IsExpired() {
			// Clean up expired session and continue
			m.repo.Repository().AuthSession.DeleteBySessionID(c.Request.Context(), sessionID)
			c.Next()
			return
		}
		
		// Get user
		user, err := m.repo.Repository().User.GetByID(c.Request.Context(), session.UserID)
		if err != nil || !user.IsActive {
			// User not found or inactive, continue without auth
			c.Next()
			return
		}
		
		// Set user context
		c.Set("user_id", user.ID)
		c.Set("user", user)
		c.Set("session_id", sessionID)
		
		c.Next()
	}
}

// BearerAuth middleware for Bearer token authentication (API access)
func (m *AuthMiddleware) BearerAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract bearer token
		token := extractBearerToken(c)
		if token == "" {
			c.Header("WWW-Authenticate", "Bearer")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized",
				"error_description": "Bearer token required",
			})
			return
		}
		
		// Validate access token
		claims, err := m.jwtService.ValidateAccessToken(token)
		if err != nil {
			c.Header("WWW-Authenticate", "Bearer")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid_token",
				"error_description": "Invalid access token",
			})
			return
		}
		
		// Parse user ID
		userID, err := uuid.Parse(claims.Subject)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid_token",
				"error_description": "Invalid user identifier",
			})
			return
		}
		
		// Get user (optional - for additional validation)
		user, err := m.repo.Repository().User.GetByID(c.Request.Context(), userID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized",
				"error_description": "User not found",
			})
			return
		}
		
		// Check if user is active
		if !user.IsActive {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized",
				"error_description": "User account disabled",
			})
			return
		}
		
		// Set context
		c.Set("user_id", userID)
		c.Set("user", user)
		c.Set("access_token_claims", claims)
		c.Set("scopes", strings.Split(claims.Scope, " "))
		
		c.Next()
	}
}

// RequireScope middleware to check for specific OAuth scopes
func (m *AuthMiddleware) RequireScope(requiredScope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		scopes, exists := c.Get("scopes")
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "insufficient_scope",
				"error_description": "No scopes found in token",
			})
			return
		}
		
		scopeList, ok := scopes.([]string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "server_error",
				"error_description": "Invalid scope format",
			})
			return
		}
		
		// Check if required scope is present
		for _, scope := range scopeList {
			if scope == requiredScope {
				c.Next()
				return
			}
		}
		
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error": "insufficient_scope",
			"error_description": "Required scope: " + requiredScope,
		})
	}
}

// RequireUserType middleware to check user type (admin, user)
func (m *AuthMiddleware) RequireUserType(userType string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized",
				"error_description": "Authentication required",
			})
			return
		}
		
		userObj, ok := user.(*models.User)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "server_error",
				"error_description": "Invalid user context",
			})
			return
		}
		
		if userObj.UserType != userType {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "insufficient_privileges",
				"error_description": "Required user type: " + userType,
			})
			return
		}
		
		c.Next()
	}
}

// CORS middleware for OAuth endpoints
func (m *AuthMiddleware) CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		
		// TODO: Implement proper CORS policy based on registered OAuth clients
		// For now, allowing all origins for development
		if origin != "" {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		}
		
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		
		c.Next()
	}
}

// Helper function to extract bearer token
func extractBearerToken(c *gin.Context) string {
	auth := c.GetHeader("Authorization")
	if auth == "" {
		return ""
	}
	
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}
	
	return parts[1]
}

// RequestLogger middleware for logging HTTP requests
func RequestLogger() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("[%s] %s %s %d %s %s\n",
			param.TimeStamp.Format("2006-01-02 15:04:05"),
			param.Method,
			param.Path,
			param.StatusCode,
			param.Latency,
			param.ClientIP,
		)
	})
}