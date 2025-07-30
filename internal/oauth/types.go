package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/google/uuid"
)

// AuthorizationRequest represents an OAuth 2.1 authorization request
type AuthorizationRequest struct {
	// OAuth 2.1 Standard Parameters
	ResponseType string `form:"response_type" binding:"required"` // Must be "code"
	ClientID     string `form:"client_id" binding:"required"`
	RedirectURI  string `form:"redirect_uri" binding:"required"`
	Scope        string `form:"scope"`
	State        string `form:"state" binding:"required"` // Required for CSRF protection
	
	// PKCE Parameters (RFC 7636) - Required in OAuth 2.1
	CodeChallenge       string `form:"code_challenge" binding:"required"`
	CodeChallengeMethod string `form:"code_challenge_method"` // S256 or plain, defaults to S256
	
	// OIDC Parameters
	Nonce        string `form:"nonce"`         // For ID token
	ResponseMode string `form:"response_mode"` // query, fragment, form_post
	
	// Additional parameters
	Prompt      string `form:"prompt"`       // none, login, consent, select_account
	MaxAge      int    `form:"max_age"`      // Maximum authentication age
	UILocales   string `form:"ui_locales"`   // Preferred languages
	LoginHint   string `form:"login_hint"`   // Hint about user identity
	ACRValues   string `form:"acr_values"`   // Authentication Context Class Reference
}

// TokenRequest represents an OAuth 2.1 token request
type TokenRequest struct {
	// OAuth 2.1 Standard Parameters
	GrantType   string `form:"grant_type" binding:"required"`   // authorization_code, refresh_token
	Code        string `form:"code"`                            // Required for authorization_code grant
	RedirectURI string `form:"redirect_uri"`                    // Must match authorization request
	ClientID    string `form:"client_id" binding:"required"`
	
	// PKCE Parameters (RFC 7636) - Required in OAuth 2.1
	CodeVerifier string `form:"code_verifier"` // Required for authorization_code grant
	
	// Refresh Token Parameters
	RefreshToken string `form:"refresh_token"` // Required for refresh_token grant
	Scope        string `form:"scope"`         // Optional for refresh_token grant
	
	// Client Authentication (for confidential clients)
	ClientSecret string `form:"client_secret"`
}

// AuthorizationResponse represents an OAuth 2.1 authorization response
type AuthorizationResponse struct {
	Code  string `json:"code,omitempty"`
	State string `json:"state"`
	
	// Error response
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// TokenResponse represents an OAuth 2.1 token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"` // OIDC
	
	// Error response
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// PKCEChallenge represents a PKCE challenge for authorization code flow
type PKCEChallenge struct {
	Challenge       string    `json:"challenge"`
	Method          string    `json:"method"`          // S256 or plain
	ClientID        string    `json:"client_id"`
	UserID          string    `json:"user_id,omitempty"`
	RedirectURI     string    `json:"redirect_uri"`
	Scope           string    `json:"scope"`
	State           string    `json:"state"`
	Nonce           string    `json:"nonce,omitempty"`
	ExpiresAt       time.Time `json:"expires_at"`
	CreatedAt       time.Time `json:"created_at"`
}

// OAuthError represents standard OAuth 2.1 error codes
type OAuthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	URI         string `json:"error_uri,omitempty"`
	State       string `json:"state,omitempty"`
}

func (e *OAuthError) Error() string {
	return e.Code + ": " + e.Description
}

// Standard OAuth 2.1 error codes
var (
	ErrInvalidRequest          = &OAuthError{Code: "invalid_request", Description: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."}
	ErrUnauthorizedClient      = &OAuthError{Code: "unauthorized_client", Description: "The client is not authorized to request an authorization code using this method."}
	ErrAccessDenied           = &OAuthError{Code: "access_denied", Description: "The resource owner or authorization server denied the request."}
	ErrUnsupportedResponseType = &OAuthError{Code: "unsupported_response_type", Description: "The authorization server does not support obtaining an authorization code using this method."}
	ErrInvalidScope           = &OAuthError{Code: "invalid_scope", Description: "The requested scope is invalid, unknown, or malformed."}
	ErrServerError            = &OAuthError{Code: "server_error", Description: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request."}
	ErrTemporarilyUnavailable = &OAuthError{Code: "temporarily_unavailable", Description: "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server."}
	
	// Token endpoint errors
	ErrInvalidClient       = &OAuthError{Code: "invalid_client", Description: "Client authentication failed."}
	ErrInvalidGrant        = &OAuthError{Code: "invalid_grant", Description: "The provided authorization grant is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client."}
	ErrUnsupportedGrantType = &OAuthError{Code: "unsupported_grant_type", Description: "The authorization grant type is not supported by the authorization server."}
	
	// PKCE specific errors
	ErrInvalidRequest_PKCE = &OAuthError{Code: "invalid_request", Description: "Code challenge required."}
	ErrInvalidGrant_PKCE   = &OAuthError{Code: "invalid_grant", Description: "Code verifier does not match code challenge."}
)

// ValidatePKCE validates PKCE code verifier against challenge
func ValidatePKCE(codeVerifier, codeChallenge, method string) error {
	if method == "" {
		method = "S256" // Default to S256
	}
	
	var computedChallenge string
	
	switch method {
	case "S256":
		hash := sha256.Sum256([]byte(codeVerifier))
		computedChallenge = base64.RawURLEncoding.EncodeToString(hash[:])
	case "plain":
		computedChallenge = codeVerifier
	default:
		return ErrInvalidRequest
	}
	
	if computedChallenge != codeChallenge {
		return ErrInvalidGrant_PKCE
	}
	
	return nil
}

// GenerateState generates a secure random state parameter
func GenerateState() string {
	return uuid.New().String()
}

// GenerateCodeChallenge generates PKCE code challenge from verifier
func GenerateCodeChallenge(codeVerifier string, method string) string {
	if method == "" || method == "S256" {
		hash := sha256.Sum256([]byte(codeVerifier))
		return base64.RawURLEncoding.EncodeToString(hash[:])
	}
	// Plain method
	return codeVerifier
}

// GenerateCodeVerifier generates a PKCE code verifier
func GenerateCodeVerifier() string {
	// Generate 43-128 character string as per RFC 7636
	return uuid.New().String() + uuid.New().String() + uuid.New().String()[:8] // 76 chars
}

// Scopes defines standard OAuth/OIDC scopes
var (
	ScopeOpenID  = "openid"
	ScopeProfile = "profile"
	ScopeEmail   = "email"
	ScopeOffline = "offline_access" // For refresh tokens
	
	// Admin scopes
	ScopeAdminRead  = "admin:read"
	ScopeAdminWrite = "admin:write"
	ScopeUserManage = "users:manage"
)

// ValidateScope validates requested scopes
func ValidateScope(requestedScopes []string, allowedScopes []string) error {
	for _, requested := range requestedScopes {
		found := false
		for _, allowed := range allowedScopes {
			if requested == allowed {
				found = true
				break
			}
		}
		if !found {
			return ErrInvalidScope
		}
	}
	return nil
}

// ParseScopes parses space-separated scope string into slice
func ParseScopes(scopeString string) []string {
	if scopeString == "" {
		return []string{}
	}
	
	scopes := []string{}
	current := ""
	
	for _, char := range scopeString {
		if char == ' ' {
			if current != "" {
				scopes = append(scopes, current)
				current = ""
			}
		} else {
			current += string(char)
		}
	}
	
	if current != "" {
		scopes = append(scopes, current)
	}
	
	return scopes
}

// ConsentRequest represents user consent information
type ConsentRequest struct {
	ClientID     string   `json:"client_id"`
	ClientName   string   `json:"client_name"`
	Scopes       []string `json:"scopes"`
	RedirectURI  string   `json:"redirect_uri"`
	State        string   `json:"state"`
	Nonce        string   `json:"nonce,omitempty"`
	UserEmail    string   `json:"user_email"`
	RequestedAt  time.Time `json:"requested_at"`
}

// ConsentResponse represents user's consent decision
type ConsentResponse struct {
	Granted     bool     `json:"granted"`
	GrantedScopes []string `json:"granted_scopes,omitempty"`
	State       string   `json:"state"`
}