package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// User represents a user in the system
type User struct {
	ID           uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Email        string     `json:"email" gorm:"uniqueIndex;not null"`
	PasswordHash *string    `json:"-" gorm:"type:varchar(255)"` // Nullable for Google users
	GoogleID     *string    `json:"google_id" gorm:"uniqueIndex;type:varchar(255)"`
	TFASecret    *string    `json:"-" gorm:"type:text"` // Encrypted TOTP secret
	TFAEnabled   bool       `json:"tfa_enabled" gorm:"default:false"`
	IsActive     bool       `json:"is_active" gorm:"default:true"`
	LastLoginAt  *time.Time `json:"last_login_at"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `json:"-" gorm:"index"`
}

// OAuthClient represents an OAuth 2.1 client application
type OAuthClient struct {
	ID                uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	ClientID          string    `json:"client_id" gorm:"uniqueIndex;not null;type:varchar(255)"`
	ClientSecretHash  string    `json:"-" gorm:"not null;type:varchar(255)"`
	ClientName        string    `json:"client_name" gorm:"not null;type:varchar(255)"`
	RedirectURIs      []string  `json:"redirect_uris" gorm:"type:text[]"`
	Scopes            []string  `json:"scopes" gorm:"type:text[]"`
	GrantTypes        []string  `json:"grant_types" gorm:"type:text[]"`
	ResponseTypes     []string  `json:"response_types" gorm:"type:text[]"`
	IsActive          bool      `json:"is_active" gorm:"default:true"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	DeletedAt         gorm.DeletedAt `json:"-" gorm:"index"`
}

// SigningKey represents an RSA key for JWT signing
type SigningKey struct {
	ID           string    `json:"id" gorm:"primaryKey;type:varchar(255)"` // kid (Key ID)
	PrivateKey   string    `json:"-" gorm:"type:text;not null"`            // Encrypted private key
	PublicKey    string    `json:"public_key" gorm:"type:text;not null"`
	Algorithm    string    `json:"algorithm" gorm:"default:'RS256'"`
	IsActive     bool      `json:"is_active" gorm:"default:true"`
	ExpiresAt    *time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// AuthSession represents a user's SSO session
type AuthSession struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	UserID    uuid.UUID `json:"user_id" gorm:"type:uuid;not null;index"`
	User      User      `json:"user" gorm:"foreignKey:UserID"`
	SessionID string    `json:"session_id" gorm:"uniqueIndex;not null;type:varchar(255)"`
	IPAddress string    `json:"ip_address" gorm:"type:varchar(45)"`
	UserAgent string    `json:"user_agent" gorm:"type:text"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AuthCode represents an OAuth authorization code
type AuthCode struct {
	ID            uuid.UUID   `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Code          string      `json:"code" gorm:"uniqueIndex;not null;type:varchar(255)"`
	ClientID      string      `json:"client_id" gorm:"not null;type:varchar(255)"`
	UserID        uuid.UUID   `json:"user_id" gorm:"type:uuid;not null"`
	User          User        `json:"user" gorm:"foreignKey:UserID"`
	RedirectURI   string      `json:"redirect_uri" gorm:"not null;type:text"`
	Scopes        []string    `json:"scopes" gorm:"type:text[]"`
	PKCEChallenge string      `json:"pkce_challenge" gorm:"not null;type:varchar(255)"`
	PKCEMethod    string      `json:"pkce_method" gorm:"not null;type:varchar(10)"`
	ExpiresAt     time.Time   `json:"expires_at"`
	UsedAt        *time.Time  `json:"used_at"`
	CreatedAt     time.Time   `json:"created_at"`
}

// RefreshToken represents an OAuth refresh token
type RefreshToken struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Token     string    `json:"token" gorm:"uniqueIndex;not null;type:varchar(255)"`
	ClientID  string    `json:"client_id" gorm:"not null;type:varchar(255)"`
	UserID    uuid.UUID `json:"user_id" gorm:"type:uuid;not null"`
	User      User      `json:"user" gorm:"foreignKey:UserID"`
	Scopes    []string  `json:"scopes" gorm:"type:text[]"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// LoginAttempt tracks failed login attempts for rate limiting
type LoginAttempt struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Email       string    `json:"email" gorm:"index;not null;type:varchar(255)"`
	IPAddress   string    `json:"ip_address" gorm:"index;not null;type:varchar(45)"`
	Successful  bool      `json:"successful" gorm:"default:false"`
	AttemptedAt time.Time `json:"attempted_at"`
}

// BeforeCreate hook for User model
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}

// BeforeCreate hook for OAuthClient model
func (c *OAuthClient) BeforeCreate(tx *gorm.DB) error {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	return nil
}