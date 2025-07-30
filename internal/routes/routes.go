package routes

import (
	"time"

	"auth/internal/handlers"
	"auth/internal/jwt"
	"auth/internal/middleware"
	"auth/internal/oauth"
	"auth/internal/repository"
	"github.com/gin-gonic/gin"
)

// SetupRoutes configures all application routes
func SetupRoutes(
	router *gin.Engine,
	repo repository.Manager,
	jwtService *jwt.Service,
	oauthService *oauth.Service,
) {
	// Initialize handlers
	authHandler := handlers.NewAuthHandler(repo)
	oauthHandler := handlers.NewOAuthHandler(oauthService, jwtService, repo)
	
	// Initialize middleware
	authMiddleware := middleware.NewAuthMiddleware(repo, jwtService)
	
	// Apply global middleware
	router.Use(middleware.RequestLogger())
	router.Use(authMiddleware.CORS())
	router.Use(gin.Recovery())
	
	// Health check endpoint
	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":    "healthy",
			"timestamp": time.Now().Unix(),
		})
	})
	
	// OIDC Discovery endpoints
	router.GET("/.well-known/openid-configuration", oauthHandler.Discovery)
	router.GET("/.well-known/jwks.json", oauthHandler.JWKs)
	
	// OAuth 2.1 / OIDC endpoints
	oauthGroup := router.Group("/oauth")
	{
		// Authorization endpoint (requires session auth)
		oauthGroup.GET("/authorize", authMiddleware.OptionalSessionAuth(), oauthHandler.Authorize)
		
		// Token endpoint (public - client authentication handled in handler)
		oauthGroup.POST("/token", oauthHandler.Token)
		
		// UserInfo endpoint (requires bearer token with openid scope)
		oauthGroup.GET("/userinfo", authMiddleware.BearerAuth(), oauthHandler.UserInfo)
		
		// Token management endpoints
		oauthGroup.POST("/revoke", oauthHandler.Revoke)
		oauthGroup.POST("/introspect", oauthHandler.Introspect)
		
		// Logout endpoint (destroys session)
		oauthGroup.POST("/logout", authMiddleware.OptionalSessionAuth(), authHandler.Logout)
	}
	
	// Authentication endpoints
	authGroup := router.Group("/auth")
	{
		// Public endpoints
		authGroup.GET("/login", authHandler.LoginPage)
		authGroup.POST("/login", authHandler.Login)
		authGroup.POST("/register", authHandler.Register)
		
		// Protected endpoints
		authGroup.POST("/logout", authMiddleware.SessionAuth(), authHandler.Logout)
		authGroup.GET("/profile", authMiddleware.SessionAuth(), authHandler.Profile)
	}
	
	// API endpoints (Bearer token authentication)
	apiV1 := router.Group("/api/v1")
	apiV1.Use(authMiddleware.BearerAuth())
	{
		// User profile via API
		apiV1.GET("/profile", authHandler.Profile)
		
		// Admin endpoints
		adminGroup := apiV1.Group("/admin")
		adminGroup.Use(authMiddleware.RequireUserType("admin"))
		{
			adminGroup.GET("/users", listUsers(repo))
			adminGroup.GET("/audit-logs", listAuditLogs(repo))
			adminGroup.GET("/oauth-clients", listOAuthClients(repo))
		}
	}
	
	// Development/Debug endpoints (only in debug mode)
	if gin.Mode() == gin.DebugMode {
		debugGroup := router.Group("/debug")
		{
			debugGroup.GET("/token-info", authMiddleware.BearerAuth(), func(c *gin.Context) {
				claims, _ := c.Get("access_token_claims")
				scopes, _ := c.Get("scopes")
				user, _ := c.Get("user")
				
				c.JSON(200, gin.H{
					"claims": claims,
					"scopes": scopes,
					"user":   user,
				})
			})
		}
	}
}

// Admin handler functions

func listUsers(repo repository.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Implement user listing with pagination
		c.JSON(200, gin.H{
			"message": "List users endpoint",
			"todo":    "Implement user listing",
		})
	}
}

func listAuditLogs(repo repository.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Implement audit log listing with filtering
		c.JSON(200, gin.H{
			"message": "List audit logs endpoint",
			"todo":    "Implement audit log listing",
		})
	}
}

func listOAuthClients(repo repository.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Implement OAuth client listing
		c.JSON(200, gin.H{
			"message": "List OAuth clients endpoint",
			"todo":    "Implement OAuth client listing",
		})
	}
}