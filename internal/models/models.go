package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// User represents a user in the system
type User struct {
	ID           uuid.UUID      `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Email        string         `json:"email" gorm:"uniqueIndex;not null;type:varchar(255)"`
	PasswordHash *string        `json:"-" gorm:"type:varchar(255)"` // Nullable for OAuth-only users
	GoogleID     *string        `json:"google_id,omitempty" gorm:"uniqueIndex;type:varchar(255)"`
	TFASecret    *string        `json:"-" gorm:"type:text"` // Encrypted TOTP secret
	TFAEnabled   bool           `json:"tfa_enabled" gorm:"default:false;not null"`
	IsActive     bool           `json:"is_active" gorm:"default:true;not null"`
	LastLoginAt  *time.Time     `json:"last_login_at,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `json:"-" gorm:"index"`

	// Relationships
	AuthSessions      []AuthSession      `json:"-" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	AuthCodes         []AuthCode         `json:"-" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	RefreshTokens     []RefreshToken     `json:"-" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	PasswordResetTokens []PasswordResetToken `json:"-" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
}

// StringArray custom type for PostgreSQL array handling
type StringArray []string

// Scan implements the Scanner interface for database/sql
func (s *StringArray) Scan(value interface{}) error {
	if value == nil {
		*s = StringArray{}
		return nil
	}
	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, s)
	case string:
		return json.Unmarshal([]byte(v), s)
	default:
		return errors.New("cannot scan into StringArray")
	}
}

// Value implements the driver Valuer interface
func (s StringArray) Value() (driver.Value, error) {
	if len(s) == 0 {
		return "{}", nil
	}
	return json.Marshal(s)
}

// OAuthClient represents an OAuth 2.1 client application
type OAuthClient struct {
	ID                   uuid.UUID      `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	ClientID             string         `json:"client_id" gorm:"uniqueIndex;not null;type:varchar(255)"`
	ClientSecretHash     string         `json:"-" gorm:"not null;type:varchar(255)"`
	ClientName           string         `json:"client_name" gorm:"not null;type:varchar(255)"`
	RedirectURIs         StringArray    `json:"redirect_uris" gorm:"type:text[];not null;default:'{}'"`
	Scopes               StringArray    `json:"scopes" gorm:"type:text[];not null;default:'{}'"`
	GrantTypes           StringArray    `json:"grant_types" gorm:"type:text[];not null;default:'{\"authorization_code\",\"refresh_token\"}'"`
	ResponseTypes        StringArray    `json:"response_types" gorm:"type:text[];not null;default:'{\"code\"}'"`
	ClientDescription    *string        `json:"client_description,omitempty" gorm:"type:text"`
	LogoURL              *string        `json:"logo_url,omitempty" gorm:"type:varchar(500)"`
	PrivacyPolicyURL     *string        `json:"privacy_policy_url,omitempty" gorm:"type:varchar(500)"`
	TermsOfServiceURL    *string        `json:"terms_of_service_url,omitempty" gorm:"type:varchar(500)"`
	IsActive             bool           `json:"is_active" gorm:"default:true;not null"`
	IsConfidential       bool           `json:"is_confidential" gorm:"default:true;not null"`
	RequirePKCE          bool           `json:"require_pkce" gorm:"default:true;not null"`
	CreatedAt            time.Time      `json:"created_at"`
	UpdatedAt            time.Time      `json:"updated_at"`
	DeletedAt            gorm.DeletedAt `json:"-" gorm:"index"`
}

// SigningKey represents an RSA key for JWT signing
type SigningKey struct {
	ID        string     `json:"id" gorm:"primaryKey;type:varchar(255)"` // kid (Key ID)
	PrivateKey string    `json:"-" gorm:"type:text;not null"`            // Encrypted private key
	PublicKey  string    `json:"public_key" gorm:"type:text;not null"`
	Algorithm  string    `json:"algorithm" gorm:"type:varchar(10);not null;default:'RS256'"`
	KeySize    int       `json:"key_size" gorm:"not null;default:2048"`
	IsActive   bool      `json:"is_active" gorm:"default:true;not null"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// AuthSession represents a user's SSO session
type AuthSession struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	SessionID string    `json:"session_id" gorm:"uniqueIndex;not null;type:varchar(255)"`
	UserID    uuid.UUID `json:"user_id" gorm:"type:uuid;not null;index"`
	User      User      `json:"user,omitempty" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	IPAddress *net.IP   `json:"ip_address,omitempty" gorm:"type:inet"`
	UserAgent *string   `json:"user_agent,omitempty" gorm:"type:text"`
	ExpiresAt time.Time `json:"expires_at" gorm:"not null"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AuthCode represents an OAuth authorization code
type AuthCode struct {
	ID            uuid.UUID   `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Code          string      `json:"code" gorm:"uniqueIndex;not null;type:varchar(255)"`
	ClientID      string      `json:"client_id" gorm:"not null;type:varchar(255);index"`
	UserID        uuid.UUID   `json:"user_id" gorm:"type:uuid;not null;index"`
	User          User        `json:"user,omitempty" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	RedirectURI   string      `json:"redirect_uri" gorm:"not null;type:text"`
	Scopes        StringArray `json:"scopes" gorm:"type:text[];not null;default:'{}'"`
	PKCEChallenge string      `json:"pkce_challenge" gorm:"not null;type:varchar(255)"`
	PKCEMethod    string      `json:"pkce_method" gorm:"not null;type:varchar(10);default:'S256'"`
	State         *string     `json:"state,omitempty" gorm:"type:varchar(255)"`
	Nonce         *string     `json:"nonce,omitempty" gorm:"type:varchar(255)"`
	ExpiresAt     time.Time   `json:"expires_at" gorm:"not null;index"`
	UsedAt        *time.Time  `json:"used_at,omitempty" gorm:"index"`
	CreatedAt     time.Time   `json:"created_at"`
}

// RefreshToken represents an OAuth refresh token
type RefreshToken struct {
	ID          uuid.UUID   `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Token       string      `json:"token" gorm:"uniqueIndex;not null;type:varchar(255)"`
	ClientID    string      `json:"client_id" gorm:"not null;type:varchar(255);index"`
	UserID      uuid.UUID   `json:"user_id" gorm:"type:uuid;not null;index"`
	User        User        `json:"user,omitempty" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	Scopes      StringArray `json:"scopes" gorm:"type:text[];not null;default:'{}'"`
	TokenFamily uuid.UUID   `json:"token_family" gorm:"type:uuid;not null;default:gen_random_uuid();index"`
	ExpiresAt   time.Time   `json:"expires_at" gorm:"not null;index"`
	RevokedAt   *time.Time  `json:"revoked_at,omitempty" gorm:"index"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

// LoginAttempt tracks authentication attempts for rate limiting
type LoginAttempt struct {
	ID            uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Email         string    `json:"email" gorm:"index;not null;type:varchar(255)"`
	IPAddress     net.IP    `json:"ip_address" gorm:"type:inet;not null;index"`
	UserAgent     *string   `json:"user_agent,omitempty" gorm:"type:text"`
	Successful    bool      `json:"successful" gorm:"default:false;not null"`
	FailureReason *string   `json:"failure_reason,omitempty" gorm:"type:varchar(100)"`
	TFARequired   bool      `json:"tfa_required" gorm:"default:false;not null"`
	TFASuccessful *bool     `json:"tfa_successful,omitempty"`
	AttemptedAt   time.Time `json:"attempted_at" gorm:"not null;default:now();index"`
}

// PasswordResetToken represents a password reset token
type PasswordResetToken struct {
	ID        uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Token     string     `json:"token" gorm:"uniqueIndex;not null;type:varchar(255)"`
	UserID    uuid.UUID  `json:"user_id" gorm:"type:uuid;not null;index"`
	User      User       `json:"user,omitempty" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	Email     string     `json:"email" gorm:"not null;type:varchar(255)"`
	ExpiresAt time.Time  `json:"expires_at" gorm:"not null;index"`
	UsedAt    *time.Time `json:"used_at,omitempty" gorm:"index"`
	CreatedAt time.Time  `json:"created_at"`
}

// AuditLog represents audit trail entries
type AuditLog struct {
	ID            uuid.UUID   `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	EventType     string      `json:"event_type" gorm:"not null;type:varchar(50);index"`
	EventCategory string      `json:"event_category" gorm:"not null;type:varchar(20);index"`
	ActorType     string      `json:"actor_type" gorm:"not null;type:varchar(20)"`
	ActorID       *string     `json:"actor_id,omitempty" gorm:"type:varchar(255)"`
	TargetType    *string     `json:"target_type,omitempty" gorm:"type:varchar(20)"`
	TargetID      *string     `json:"target_id,omitempty" gorm:"type:varchar(255)"`
	IPAddress     *net.IP     `json:"ip_address,omitempty" gorm:"type:inet;index"`
	UserAgent     *string     `json:"user_agent,omitempty" gorm:"type:text"`
	ClientID      *string     `json:"client_id,omitempty" gorm:"type:varchar(255)"`
	Success       bool        `json:"success" gorm:"not null;index"`
	ErrorCode     *string     `json:"error_code,omitempty" gorm:"type:varchar(50)"`
	ErrorMessage  *string     `json:"error_message,omitempty" gorm:"type:text"`
	Metadata      interface{} `json:"metadata,omitempty" gorm:"type:jsonb"`
	OccurredAt    time.Time   `json:"occurred_at" gorm:"not null;default:now();index"`
}

// BeforeCreate hooks for UUID generation
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}

func (c *OAuthClient) BeforeCreate(tx *gorm.DB) error {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	return nil
}

func (rt *RefreshToken) BeforeCreate(tx *gorm.DB) error {
	if rt.TokenFamily == uuid.Nil {
		rt.TokenFamily = uuid.New()
	}
	return nil
}

// TableName methods for explicit table naming
func (User) TableName() string             { return "users" }
func (OAuthClient) TableName() string      { return "oauth_clients" }
func (SigningKey) TableName() string       { return "signing_keys" }
func (AuthSession) TableName() string      { return "auth_sessions" }
func (AuthCode) TableName() string         { return "auth_codes" }
func (RefreshToken) TableName() string     { return "refresh_tokens" }
func (LoginAttempt) TableName() string     { return "login_attempts" }
func (PasswordResetToken) TableName() string { return "password_reset_tokens" }
func (AuditLog) TableName() string         { return "audit_log" }