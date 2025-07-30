package handlers

import (
	"net/http"
	"strings"

	"auth/internal/jwt"
	"auth/internal/oauth"
	"auth/internal/repository"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// OAuthHandler handles OAuth 2.1 and OIDC endpoints
type OAuthHandler struct {
	oauthService *oauth.Service
	jwtService   *jwt.Service
	repo         repository.Manager
}

// NewOAuthHandler creates a new OAuth handler
func NewOAuthHandler(oauthService *oauth.Service, jwtService *jwt.Service, repo repository.Manager) *OAuthHandler {
	return &OAuthHandler{
		oauthService: oauthService,
		jwtService:   jwtService,
		repo:         repo,
	}
}

// Discovery handles OIDC discovery endpoint
// GET /.well-known/openid-configuration
func (h *OAuthHandler) Discovery(c *gin.Context) {
	baseURL := getBaseURL(c)
	
	discovery := map[string]interface{}{
		"issuer":                                baseURL,
		"authorization_endpoint":                baseURL + "/oauth/authorize",
		"token_endpoint":                        baseURL + "/oauth/token",
		"userinfo_endpoint":                     baseURL + "/oauth/userinfo",
		"jwks_uri":                             baseURL + "/.well-known/jwks.json",
		"end_session_endpoint":                 baseURL + "/oauth/logout",
		"revocation_endpoint":                  baseURL + "/oauth/revoke",
		"introspection_endpoint":               baseURL + "/oauth/introspect",
		
		// Supported response types
		"response_types_supported": []string{"code"},
		
		// Supported grant types
		"grant_types_supported": []string{
			"authorization_code",
			"refresh_token",
		},
		
		// Supported scopes
		"scopes_supported": []string{
			"openid",
			"profile",
			"email",
			"offline_access",
			"admin",
		},
		
		// Supported claims
		"claims_supported": []string{
			"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce",
			"email", "email_verified", "name", "given_name", "family_name",
			"picture", "locale", "user_type", "auth_provider", "groups",
		},
		
		// Supported signing algorithms
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		
		// PKCE support
		"code_challenge_methods_supported": []string{"S256", "plain"},
		
		// Subject types
		"subject_types_supported": []string{"public"},
		
		// Response modes
		"response_modes_supported": []string{"query", "fragment"},
		
		// Claims parameter supported
		"claims_parameter_supported": false,
		"request_parameter_supported": false,
		"request_uri_parameter_supported": false,
	}
	
	c.Header("Content-Type", "application/json")
	c.JSON(http.StatusOK, discovery)
}

// JWKs handles JWKS endpoint
// GET /.well-known/jwks.json
func (h *OAuthHandler) JWKs(c *gin.Context) {
	// Get active signing keys
	keys, err := h.repo.Repository().SigningKey.ListActive(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "internal_server_error",
			"error_description": "Failed to retrieve signing keys",
		})
		return
	}
	
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{},
	}
	
	for _, key := range keys {
		// Parse public key for JWK format
		jwk := map[string]interface{}{
			"kty": "RSA",
			"use": "sig",
			"alg": key.Algorithm,
			"kid": key.ID,
			// TODO: Convert PEM public key to JWK format (n, e parameters)
			// For now, we'll include the raw key until we implement proper JWK conversion
		}
		
		jwks["keys"] = append(jwks["keys"].([]map[string]interface{}), jwk)
	}
	
	c.Header("Content-Type", "application/json")
	c.Header("Cache-Control", "public, max-age=3600") // Cache for 1 hour
	c.JSON(http.StatusOK, jwks)
}

// Authorize handles OAuth 2.1 authorization endpoint
// GET /oauth/authorize
func (h *OAuthHandler) Authorize(c *gin.Context) {
	var req oauth.AuthorizationRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		redirectError(c, req.RedirectURI, "invalid_request", "Invalid request parameters", req.State)
		return
	}
	
	// Check if user is authenticated
	userID, exists := c.Get("user_id")
	if !exists {
		// Redirect to login with return URL
		loginURL := "/auth/login?return_url=" + c.Request.URL.String()
		c.Redirect(http.StatusFound, loginURL)
		return
	}
	
	// Convert userID to UUID
	uid, ok := userID.(uuid.UUID)
	if !ok {
		redirectError(c, req.RedirectURI, "server_error", "Invalid user session", req.State)
		return
	}
	
	// Process authorization request
	resp, err := h.oauthService.HandleAuthorizationRequest(c.Request.Context(), &req, uid)
	if err != nil {
		redirectError(c, req.RedirectURI, "server_error", "Authorization failed", req.State)
		return
	}
	
	// Check for OAuth errors
	if resp.Error != "" {
		redirectError(c, req.RedirectURI, resp.Error, resp.ErrorDescription, resp.State)
		return
	}
	
	// Redirect back to client with authorization code
	redirectURL := req.RedirectURI + "?code=" + resp.Code + "&state=" + resp.State
	c.Redirect(http.StatusFound, redirectURL)
}

// Token handles OAuth 2.1 token endpoint
// POST /oauth/token
func (h *OAuthHandler) Token(c *gin.Context) {
	var req oauth.TokenRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid_request",
			"error_description": "Invalid request parameters",
		})
		return
	}
	
	// Process token request
	resp, err := h.oauthService.HandleTokenRequest(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "server_error",
			"error_description": "Token generation failed",
		})
		return
	}
	
	// Check for OAuth errors
	if resp.Error != "" {
		status := getTokenErrorStatus(resp.Error)
		c.JSON(status, gin.H{
			"error": resp.Error,
			"error_description": resp.ErrorDescription,
		})
		return
	}
	
	// Return token response
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.JSON(http.StatusOK, gin.H{
		"access_token":  resp.AccessToken,
		"token_type":    resp.TokenType,
		"expires_in":    resp.ExpiresIn,
		"refresh_token": resp.RefreshToken,
		"scope":         resp.Scope,
		"id_token":      resp.IDToken,
	})
}

// UserInfo handles OIDC UserInfo endpoint
// GET /oauth/userinfo
func (h *OAuthHandler) UserInfo(c *gin.Context) {
	// Extract and validate access token
	token := extractBearerToken(c)
	if token == "" {
		c.Header("WWW-Authenticate", "Bearer")
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid_token",
			"error_description": "Access token required",
		})
		return
	}
	
	// Validate access token
	claims, err := h.jwtService.ValidateAccessToken(token)
	if err != nil {
		c.Header("WWW-Authenticate", "Bearer")
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid_token",
			"error_description": "Invalid access token",
		})
		return
	}
	
	// Check if token has openid scope
	if !strings.Contains(claims.Scope, "openid") {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "insufficient_scope",
			"error_description": "Token must have openid scope",
		})
		return
	}
	
	// Get user from database
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "server_error",
			"error_description": "Invalid user identifier",
		})
		return
	}
	
	user, err := h.repo.Repository().User.GetByID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "server_error",
			"error_description": "Failed to retrieve user",
		})
		return
	}
	
	// Build UserInfo response based on scopes
	userInfo := map[string]interface{}{
		"sub": claims.Subject,
	}
	
	if strings.Contains(claims.Scope, "email") {
		userInfo["email"] = user.Email
		userInfo["email_verified"] = true
	}
	
	if strings.Contains(claims.Scope, "profile") {
		userInfo["name"] = user.Email // Using email as name for now
		userInfo["user_type"] = user.UserType
		userInfo["auth_provider"] = user.AuthProvider
	}
	
	c.JSON(http.StatusOK, userInfo)
}

// Revoke handles token revocation endpoint
// POST /oauth/revoke
func (h *OAuthHandler) Revoke(c *gin.Context) {
	var req struct {
		Token         string `form:"token" binding:"required"`
		TokenTypeHint string `form:"token_type_hint"`
		ClientID      string `form:"client_id"`
	}
	
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid_request",
			"error_description": "Invalid request parameters",
		})
		return
	}
	
	// Try to revoke as refresh token first
	err := h.repo.Repository().RefreshToken.Revoke(c.Request.Context(), req.Token)
	if err != nil {
		// If not found as refresh token, that's OK - might be access token
		// Access tokens are stateless JWTs, so we can't revoke them server-side
		// They'll expire naturally
	}
	
	// Always return success for security (don't leak token existence)
	c.Status(http.StatusOK)
}

// Introspect handles token introspection endpoint
// POST /oauth/introspect
func (h *OAuthHandler) Introspect(c *gin.Context) {
	var req struct {
		Token         string `form:"token" binding:"required"`
		TokenTypeHint string `form:"token_type_hint"`
	}
	
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid_request",
			"error_description": "Invalid request parameters",
		})
		return
	}
	
	// Try to validate as access token
	claims, err := h.jwtService.ValidateAccessToken(req.Token)
	if err == nil {
		// Valid access token
		c.JSON(http.StatusOK, gin.H{
			"active":     true,
			"scope":      claims.Scope,
			"client_id":  claims.ClientId,
			"token_type": "access_token",
			"exp":        claims.ExpiresAt.Unix(),
			"iat":        claims.IssuedAt.Unix(),
			"sub":        claims.Subject,
			"aud":        claims.Audience,
			"iss":        claims.Issuer,
		})
		return
	}
	
	// Try as refresh token
	refreshToken, err := h.repo.Repository().RefreshToken.GetByToken(c.Request.Context(), req.Token)
	if err == nil {
		// Valid refresh token
		c.JSON(http.StatusOK, gin.H{
			"active":     true,
			"scope":      strings.Join(refreshToken.Scopes, " "),
			"client_id":  refreshToken.ClientID,
			"token_type": "refresh_token",
			"exp":        refreshToken.ExpiresAt.Unix(),
			"iat":        refreshToken.CreatedAt.Unix(),
			"sub":        refreshToken.UserID.String(),
		})
		return
	}
	
	// Token not found or invalid
	c.JSON(http.StatusOK, gin.H{
		"active": false,
	})
}

// Helper functions

func getBaseURL(c *gin.Context) string {
	scheme := "https"
	if c.Request.Header.Get("X-Forwarded-Proto") != "" {
		scheme = c.Request.Header.Get("X-Forwarded-Proto")
	} else if c.Request.TLS == nil {
		scheme = "http"
	}
	
	host := c.Request.Host
	if forwardedHost := c.Request.Header.Get("X-Forwarded-Host"); forwardedHost != "" {
		host = forwardedHost
	}
	
	return scheme + "://" + host
}

func redirectError(c *gin.Context, redirectURI, error, description, state string) {
	if redirectURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": error,
			"error_description": description,
		})
		return
	}
	
	separator := "?"
	if strings.Contains(redirectURI, "?") {
		separator = "&"
	}
	
	redirectURL := redirectURI + separator + "error=" + error + "&error_description=" + description
	if state != "" {
		redirectURL += "&state=" + state
	}
	
	c.Redirect(http.StatusFound, redirectURL)
}

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

func getTokenErrorStatus(errorCode string) int {
	switch errorCode {
	case "invalid_request", "invalid_client", "invalid_grant", "unauthorized_client", "unsupported_grant_type":
		return http.StatusBadRequest
	case "invalid_scope":
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}