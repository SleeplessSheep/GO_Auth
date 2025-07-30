package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"auth/internal/models"
	"auth/internal/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Service handles JWT token operations
type Service struct {
	repo   repository.Manager
	config *Config
}

// Config holds JWT service configuration
type Config struct {
	Issuer                 string
	AccessTokenExpiry      time.Duration
	IDTokenExpiry          time.Duration
	RefreshTokenExpiry     time.Duration
	AdminAccessTokenExpiry time.Duration
}

// AccessTokenClaims represents OAuth 2.1 access token claims
type AccessTokenClaims struct {
	jwt.RegisteredClaims
	
	// RFC 6749 (OAuth 2.0) Standard Claims  
	Scope    string `json:"scope"`     // Space-separated scopes
	ClientId string `json:"client_id"` // OAuth client
	
	// RFC 8693 (Token Exchange) Claims
	TokenType string `json:"token_type"` // "access_token"
	
	// Custom Claims (Application-specific)
	UserType     string `json:"user_type"`      // "admin" | "user"  
	SessionId    string `json:"sid"`            // Session identifier
	AuthMethod   string `json:"amr"`            // Authentication method
	AuthProvider string `json:"auth_provider"`  // "ldap" | "local" | "google"
}

// IDTokenClaims represents OIDC ID token claims
type IDTokenClaims struct {
	jwt.RegisteredClaims
	
	// OIDC Core Standard Claims  
	AuthTime int64  `json:"auth_time"`          // When user authenticated
	Nonce    string `json:"nonce,omitempty"`    // CSRF protection
	
	// OIDC Standard Profile Claims
	Name          string `json:"name,omitempty"`           // Full name
	GivenName     string `json:"given_name,omitempty"`     // First name  
	FamilyName    string `json:"family_name,omitempty"`    // Last name
	Email         string `json:"email,omitempty"`          // Email address
	EmailVerified bool   `json:"email_verified,omitempty"` // Email verified
	Picture       string `json:"picture,omitempty"`        // Profile picture
	Locale        string `json:"locale,omitempty"`         // User locale
	
	// OIDC Authentication Context Claims
	AuthContextClassRef   string   `json:"acr,omitempty"` // Authentication strength
	AuthMethodsReferences []string `json:"amr,omitempty"` // Auth methods used
	AuthorizedParty       string   `json:"azp,omitempty"` // Authorized party
	
	// Custom Claims (Your application)
	UserType     string   `json:"user_type"`               // "admin" | "user"
	AuthProvider string   `json:"auth_provider"`           // "ldap" | "local" | "google"  
	Groups       []string `json:"groups,omitempty"`        // LDAP groups (admin only)
	SessionId    string   `json:"sid"`                     // Session identifier
}

// TokenPair holds both access and ID tokens
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

// NewService creates a new JWT service
func NewService(repo repository.Manager, config *Config) *Service {
	return &Service{
		repo:   repo,
		config: config,
	}
}

// GenerateTokenPair creates access and ID tokens for a user
func (s *Service) GenerateTokenPair(user *models.User, client *models.OAuthClient, scopes []string, nonce string, sessionID string) (*TokenPair, error) {
	now := time.Now()
	tokenId := uuid.New().String()
	
	// Determine token expiry based on user type
	accessTokenExpiry := s.config.AccessTokenExpiry
	if user.UserType == "admin" {
		accessTokenExpiry = s.config.AdminAccessTokenExpiry
	}
	
	// Get active signing key
	signingKey, err := s.repo.Repository().SigningKey.GetActive(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("failed to get signing key: %w", err)
	}
	
	// Parse private key
	privateKey, err := s.parsePrivateKey(signingKey.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	
	// Build access token claims
	accessClaims := &AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.config.Issuer,
			Subject:   user.ID.String(),
			Audience:  s.getResourceServerAudiences(),
			ExpiresAt: jwt.NewNumericDate(now.Add(accessTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        tokenId + "_access",
		},
		Scope:        s.scopesToString(scopes),
		ClientId:     client.ClientID,
		TokenType:    "access_token",
		UserType:     user.UserType,
		SessionId:    sessionID,
		AuthMethod:   s.getAuthMethod(user),
		AuthProvider: user.AuthProvider,
	}
	
	// Build ID token claims
	idClaims := &IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.config.Issuer,
			Subject:   user.ID.String(),
			Audience:  []string{client.ClientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(s.config.IDTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        tokenId + "_id",
		},
		AuthTime:      s.getAuthTime(user),
		Nonce:         nonce,
		Email:         user.Email,
		EmailVerified: true, // Assume verified for now
		Name:          s.getUserDisplayName(user),
		AuthContextClassRef: s.getACR(user),
		AuthMethodsReferences: s.getAMR(user),
		UserType:      user.UserType,
		AuthProvider:  user.AuthProvider,
		Groups:        s.getLDAPGroups(user),
		SessionId:     sessionID,
	}
	
	// Sign tokens
	accessToken, err := s.signToken(accessClaims, privateKey, signingKey.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}
	
	idToken, err := s.signToken(idClaims, privateKey, signingKey.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to sign ID token: %w", err)
	}
	
	return &TokenPair{
		AccessToken: accessToken,
		IDToken:     idToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(accessTokenExpiry.Seconds()),
		Scope:       s.scopesToString(scopes),
	}, nil
}

// ValidateAccessToken validates and parses an access token
func (s *Service) ValidateAccessToken(tokenString string) (*AccessTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AccessTokenClaims{}, s.getKeyFunc())
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	
	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}
	
	claims, ok := token.Claims.(*AccessTokenClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}
	
	return claims, nil
}

// ValidateIDToken validates and parses an ID token
func (s *Service) ValidateIDToken(tokenString string) (*IDTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &IDTokenClaims{}, s.getKeyFunc())
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	
	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}
	
	claims, ok := token.Claims.(*IDTokenClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}
	
	return claims, nil
}

// signToken signs a token with the private key
func (s *Service) signToken(claims jwt.Claims, privateKey *rsa.PrivateKey, keyID string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID
	
	return token.SignedString(privateKey)
}

// getKeyFunc returns the key function for JWT validation
func (s *Service) getKeyFunc() jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		
		// Get key ID from header
		keyID, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing key ID in token header")
		}
		
		// Get signing key
		signingKey, err := s.repo.Repository().SigningKey.GetByID(context.TODO(), keyID)
		if err != nil {
			return nil, fmt.Errorf("failed to get signing key: %w", err)
		}
		
		// Parse public key
		return s.parsePublicKey(signingKey.PublicKey)
	}
}

// parsePrivateKey parses PEM encoded private key
func (s *Service) parsePrivateKey(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format
		keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		
		rsaKey, ok := keyInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not RSA private key")
		}
		return rsaKey, nil
	}
	
	return key, nil
}

// parsePublicKey parses PEM encoded public key
func (s *Service) parsePublicKey(pemData string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA public key")
	}
	
	return rsaKey, nil
}

// Helper methods
func (s *Service) getResourceServerAudiences() []string {
	// TODO: Make this configurable
	return []string{"https://api.yourdomain.com"}
}

func (s *Service) scopesToString(scopes []string) string {
	result := ""
	for i, scope := range scopes {
		if i > 0 {
			result += " "
		}
		result += scope
	}
	return result
}

func (s *Service) getAuthMethod(user *models.User) string {
	switch user.AuthProvider {
	case "ldap":
		if user.TFAEnabled {
			return "ldap+mfa"
		}
		return "ldap"
	case "google":
		return "google"
	default:
		if user.TFAEnabled {
			return "pwd+mfa"
		}
		return "pwd"
	}
}

func (s *Service) getAuthTime(user *models.User) int64 {
	if user.LastLoginAt != nil {
		return user.LastLoginAt.Unix()
	}
	return time.Now().Unix()
}

func (s *Service) getUserDisplayName(user *models.User) string {
	// For now, use email as display name
	// TODO: Add proper name fields to user model
	return user.Email
}

func (s *Service) getACR(user *models.User) string {
	// Authentication Context Class Reference
	if user.UserType == "admin" && user.TFAEnabled {
		return "2" // Strong authentication
	}
	return "1" // Standard authentication
}

func (s *Service) getAMR(user *models.User) []string {
	// Authentication Methods References
	methods := []string{}
	
	switch user.AuthProvider {
	case "ldap":
		methods = append(methods, "ldap")
	case "google":
		methods = append(methods, "google")
	default:
		methods = append(methods, "pwd")
	}
	
	if user.TFAEnabled {
		methods = append(methods, "mfa")
	}
	
	return methods
}

func (s *Service) getLDAPGroups(user *models.User) []string {
	// TODO: Implement LDAP group lookup for admin users
	if user.UserType == "admin" && user.AuthProvider == "ldap" {
		return []string{"administrators"} // Placeholder
	}
	return nil
}

// GenerateSigningKey generates a new RSA signing key pair
func (s *Service) GenerateSigningKey() (*models.SigningKey, error) {
	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	
	// Encode private key to PEM
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	
	// Encode public key to PEM
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	
	// Create signing key model
	keyID := uuid.New().String()
	signingKey := &models.SigningKey{
		ID:         keyID,
		PrivateKey: string(privateKeyPEM), // TODO: Encrypt this
		PublicKey:  string(publicKeyPEM),
		Algorithm:  "RS256",
		KeySize:    2048,
		IsActive:   true,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	
	return signingKey, nil
}