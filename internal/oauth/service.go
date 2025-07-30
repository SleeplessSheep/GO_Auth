package oauth

import (
	"context"
	"time"

	"auth/internal/jwt"
	"auth/internal/models"
	"auth/internal/repository"
	"github.com/google/uuid"
)

// Service handles OAuth 2.1 operations with PKCE and state support
type Service struct {
	repo       repository.Manager
	jwtService *jwt.Service
	config     *Config
}

// Config holds OAuth service configuration
type Config struct {
	AuthCodeExpiry    time.Duration
	DefaultScopes     []string
	RequirePKCE       bool
	RequireState      bool
	AllowedGrantTypes []string
}

// NewService creates a new OAuth service
func NewService(repo repository.Manager, jwtService *jwt.Service, config *Config) *Service {
	if config.RequirePKCE == false {
		config.RequirePKCE = true // Force PKCE for OAuth 2.1 compliance
	}
	if config.RequireState == false {
		config.RequireState = true // Force state for CSRF protection
	}
	
	return &Service{
		repo:       repo,
		jwtService: jwtService,
		config:     config,
	}
}

// HandleAuthorizationRequest processes OAuth 2.1 authorization requests with PKCE and state
func (s *Service) HandleAuthorizationRequest(ctx context.Context, req *AuthorizationRequest, userID uuid.UUID) (*AuthorizationResponse, error) {
	// Validate request
	if err := s.validateAuthorizationRequest(ctx, req); err != nil {
		if oauthErr, ok := err.(*OAuthError); ok {
			return s.errorResponse(oauthErr, req.State), nil
		}
		return s.errorResponse(ErrServerError, req.State), nil
	}
	
	// Get OAuth client
	client, err := s.repo.Repository().OAuthClient.GetByClientID(ctx, req.ClientID)
	if err != nil {
		return s.errorResponse(ErrInvalidClient, req.State), nil
	}
	
	// Validate redirect URI
	if !s.validateRedirectURI(req.RedirectURI, client.RedirectURIs) {
		return s.errorResponse(ErrInvalidRequest, req.State), nil
	}
	
	// Parse and validate scopes
	requestedScopes := ParseScopes(req.Scope)
	if err := ValidateScope(requestedScopes, []string(client.Scopes)); err != nil {
		return s.errorResponse(err.(*OAuthError), req.State), nil
	}
	
	// Get user
	user, err := s.repo.Repository().User.GetByID(ctx, userID)
	if err != nil {
		return s.errorResponse(ErrServerError, req.State), nil
	}
	
	// Generate authorization code
	authCode := s.generateAuthorizationCode()
	
	// Store authorization code with PKCE challenge and state
	codeModel := &models.AuthCode{
		Code:          authCode,
		ClientID:      req.ClientID,
		UserID:        userID,
		RedirectURI:   req.RedirectURI,
		Scopes:        models.StringArray(requestedScopes),
		PKCEChallenge: req.CodeChallenge,
		PKCEMethod:    s.getPKCEMethod(req.CodeChallengeMethod),
		State:         &req.State,
		Nonce:         s.getNoncePtr(req.Nonce),
		ExpiresAt:     time.Now().Add(s.config.AuthCodeExpiry),
		CreatedAt:     time.Now(),
	}
	
	if err := s.repo.Repository().AuthCode.Create(ctx, codeModel); err != nil {
		return s.errorResponse(ErrServerError, req.State), nil
	}
	
	// Log authorization for audit
	s.logAuthorizationEvent(ctx, user, client, requestedScopes, true)
	
	return &AuthorizationResponse{
		Code:  authCode,
		State: req.State,
	}, nil
}

// HandleTokenRequest processes OAuth 2.1 token requests with PKCE validation
func (s *Service) HandleTokenRequest(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	switch req.GrantType {
	case "authorization_code":
		return s.handleAuthorizationCodeGrant(ctx, req)
	case "refresh_token":
		return s.handleRefreshTokenGrant(ctx, req)
	default:
		return s.tokenErrorResponse(ErrUnsupportedGrantType), nil
	}
}

// handleAuthorizationCodeGrant handles authorization code grant with PKCE validation
func (s *Service) handleAuthorizationCodeGrant(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	// Validate required parameters
	if req.Code == "" || req.CodeVerifier == "" || req.RedirectURI == "" {
		return s.tokenErrorResponse(ErrInvalidRequest), nil
	}
	
	// Get and validate authorization code
	authCode, err := s.repo.Repository().AuthCode.GetByCode(ctx, req.Code)
	if err != nil {
		return s.tokenErrorResponse(ErrInvalidGrant), nil
	}
	
	// Validate client
	if authCode.ClientID != req.ClientID {
		return s.tokenErrorResponse(ErrInvalidClient), nil
	}
	
	// Validate redirect URI
	if authCode.RedirectURI != req.RedirectURI {
		return s.tokenErrorResponse(ErrInvalidGrant), nil
	}
	
	// Validate PKCE code verifier
	if err := ValidatePKCE(req.CodeVerifier, authCode.PKCEChallenge, authCode.PKCEMethod); err != nil {
		// Mark code as used to prevent replay attacks
		s.repo.Repository().AuthCode.MarkAsUsed(ctx, req.Code)
		return s.tokenErrorResponse(ErrInvalidGrant_PKCE), nil
	}
	
	// Get client and user
	client, err := s.repo.Repository().OAuthClient.GetByClientID(ctx, req.ClientID)
	if err != nil {
		return s.tokenErrorResponse(ErrInvalidClient), nil
	}
	
	user, err := s.repo.Repository().User.GetByID(ctx, authCode.UserID)
	if err != nil {
		return s.tokenErrorResponse(ErrServerError), nil
	}
	
	// Create session
	sessionID := s.generateSessionID()
	session := &models.AuthSession{
		SessionID: sessionID,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(24 * time.Hour), // Session expiry
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	if err := s.repo.Repository().AuthSession.Create(ctx, session); err != nil {
		return s.tokenErrorResponse(ErrServerError), nil
	}
	
	// Generate tokens
	nonce := ""
	if authCode.Nonce != nil {
		nonce = *authCode.Nonce
	}
	
	tokenPair, err := s.jwtService.GenerateTokenPair(
		user,
		client,
		[]string(authCode.Scopes),
		nonce,
		sessionID,
	)
	if err != nil {
		return s.tokenErrorResponse(ErrServerError), nil
	}
	
	// Generate refresh token if offline_access scope requested
	var refreshToken string
	if s.hasOfflineAccess([]string(authCode.Scopes)) {
		refreshTokenModel := &models.RefreshToken{
			Token:       s.generateRefreshToken(),
			ClientID:    client.ClientID,
			UserID:      user.ID,
			Scopes:      authCode.Scopes,
			TokenFamily: uuid.New(),
			ExpiresAt:   time.Now().Add(720 * time.Hour), // 30 days
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		
		if err := s.repo.Repository().RefreshToken.Create(ctx, refreshTokenModel); err != nil {
			return s.tokenErrorResponse(ErrServerError), nil
		}
		
		refreshToken = refreshTokenModel.Token
	}
	
	// Mark authorization code as used
	if err := s.repo.Repository().AuthCode.MarkAsUsed(ctx, req.Code); err != nil {
		return s.tokenErrorResponse(ErrServerError), nil
	}
	
	// Log token issuance
	s.logTokenEvent(ctx, user, client, []string(authCode.Scopes), "authorization_code", true)
	
	return &TokenResponse{
		AccessToken:  tokenPair.AccessToken,
		TokenType:    tokenPair.TokenType,
		ExpiresIn:    tokenPair.ExpiresIn,
		RefreshToken: refreshToken,
		Scope:        tokenPair.Scope,
		IDToken:      tokenPair.IDToken,
	}, nil
}

// handleRefreshTokenGrant handles refresh token grant
func (s *Service) handleRefreshTokenGrant(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	if req.RefreshToken == "" {
		return s.tokenErrorResponse(ErrInvalidRequest), nil
	}
	
	// Get refresh token
	refreshToken, err := s.repo.Repository().RefreshToken.GetByToken(ctx, req.RefreshToken)
	if err != nil {
		return s.tokenErrorResponse(ErrInvalidGrant), nil
	}
	
	// Validate client
	if refreshToken.ClientID != req.ClientID {
		return s.tokenErrorResponse(ErrInvalidClient), nil
	}
	
	// Get client and user
	client, err := s.repo.Repository().OAuthClient.GetByClientID(ctx, req.ClientID)
	if err != nil {
		return s.tokenErrorResponse(ErrInvalidClient), nil
	}
	
	user, err := s.repo.Repository().User.GetByID(ctx, refreshToken.UserID)
	if err != nil {
		return s.tokenErrorResponse(ErrServerError), nil
	}
	
	// Determine scopes (use original or requested subset)
	scopes := []string(refreshToken.Scopes)
	if req.Scope != "" {
		requestedScopes := ParseScopes(req.Scope)
		if err := ValidateScope(requestedScopes, scopes); err != nil {
			return s.tokenErrorResponse(ErrInvalidScope), nil
		}
		scopes = requestedScopes
	}
	
	// Generate new access token (and ID token if openid scope)
	sessionID := s.generateSessionID()
	tokenPair, err := s.jwtService.GenerateTokenPair(user, client, scopes, "", sessionID)
	if err != nil {
		return s.tokenErrorResponse(ErrServerError), nil
	}
	
	// Log token refresh
	s.logTokenEvent(ctx, user, client, scopes, "refresh_token", true)
	
	return &TokenResponse{
		AccessToken: tokenPair.AccessToken,
		TokenType:   tokenPair.TokenType,
		ExpiresIn:   tokenPair.ExpiresIn,
		Scope:       tokenPair.Scope,
		IDToken:     tokenPair.IDToken,
	}, nil
}

// Validation methods
func (s *Service) validateAuthorizationRequest(ctx context.Context, req *AuthorizationRequest) error {
	// Validate response type
	if req.ResponseType != "code" {
		return ErrUnsupportedResponseType
	}
	
	// Validate PKCE (required in OAuth 2.1)
	if s.config.RequirePKCE && req.CodeChallenge == "" {
		return ErrInvalidRequest_PKCE
	}
	
	// Validate state (required for CSRF protection)
	if s.config.RequireState && req.State == "" {
		return &OAuthError{Code: "invalid_request", Description: "state parameter is required"}
	}
	
	// Validate code challenge method
	if req.CodeChallengeMethod != "" && req.CodeChallengeMethod != "S256" && req.CodeChallengeMethod != "plain" {
		return ErrInvalidRequest
	}
	
	return nil
}

func (s *Service) validateRedirectURI(redirectURI string, allowedURIs models.StringArray) bool {
	for _, allowed := range allowedURIs {
		if redirectURI == allowed {
			return true
		}
	}
	return false
}

// Helper methods
func (s *Service) generateAuthorizationCode() string {
	return "ac_" + uuid.New().String()
}

func (s *Service) generateRefreshToken() string {
	return "rt_" + uuid.New().String()
}

func (s *Service) generateSessionID() string {
	return "sess_" + uuid.New().String()
}

func (s *Service) getPKCEMethod(method string) string {
	if method == "" {
		return "S256" // Default to S256
	}
	return method
}

func (s *Service) getNoncePtr(nonce string) *string {
	if nonce == "" {
		return nil
	}
	return &nonce
}

func (s *Service) hasOfflineAccess(scopes []string) bool {
	for _, scope := range scopes {
		if scope == ScopeOffline {
			return true
		}
	}
	return false
}

// Error response helpers
func (s *Service) errorResponse(err *OAuthError, state string) *AuthorizationResponse {
	return &AuthorizationResponse{
		Error:            err.Code,
		ErrorDescription: err.Description,
		ErrorURI:         err.URI,
		State:            state,
	}
}

func (s *Service) tokenErrorResponse(err *OAuthError) *TokenResponse {
	return &TokenResponse{
		Error:            err.Code,
		ErrorDescription: err.Description,
		ErrorURI:         err.URI,
	}
}

// Audit logging methods
func (s *Service) logAuthorizationEvent(ctx context.Context, user *models.User, client *models.OAuthClient, scopes []string, success bool) {
	auditLog := &models.AuditLog{
		EventType:     "authorization_request",
		EventCategory: "authorization",
		ActorType:     "user",
		ActorID:       func() *string { s := user.ID.String(); return &s }(),
		TargetType:    &[]string{"oauth_client"}[0],
		TargetID:      &client.ClientID,
		ClientID:      &client.ClientID,
		Success:       success,
		Metadata: map[string]interface{}{
			"scopes":     scopes,
			"user_email": user.Email,
			"user_type":  user.UserType,
		},
		OccurredAt: time.Now(),
	}
	
	s.repo.Repository().AuditLog.Create(ctx, auditLog)
}

func (s *Service) logTokenEvent(ctx context.Context, user *models.User, client *models.OAuthClient, scopes []string, grantType string, success bool) {
	auditLog := &models.AuditLog{
		EventType:     "token_issued",
		EventCategory: "authorization",
		ActorType:     "user",
		ActorID:       func() *string { s := user.ID.String(); return &s }(),
		TargetType:    &[]string{"oauth_client"}[0],
		TargetID:      &client.ClientID,
		ClientID:      &client.ClientID,
		Success:       success,
		Metadata: map[string]interface{}{
			"grant_type": grantType,
			"scopes":     scopes,
			"user_email": user.Email,
			"user_type":  user.UserType,
		},
		OccurredAt: time.Now(),
	}
	
	s.repo.Repository().AuditLog.Create(ctx, auditLog)
}