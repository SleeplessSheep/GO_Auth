package repository

import (
	"context"
	"net"
	"time"

	"auth/internal/models"
	"github.com/google/uuid"
)

// UserRepository defines the interface for user data access
type UserRepository interface {
	// Create operations
	Create(ctx context.Context, user *models.User) error
	
	// Read operations
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetByEmail(ctx context.Context, email string) (*models.User, error)
	GetByGoogleID(ctx context.Context, googleID string) (*models.User, error)
	List(ctx context.Context, limit, offset int) ([]*models.User, error)
	Count(ctx context.Context) (int64, error)
	
	// Update operations
	Update(ctx context.Context, user *models.User) error
	UpdateLastLogin(ctx context.Context, userID uuid.UUID, loginTime time.Time) error
	UpdatePassword(ctx context.Context, userID uuid.UUID, passwordHash string) error
	EnableTFA(ctx context.Context, userID uuid.UUID, secret string) error
	DisableTFA(ctx context.Context, userID uuid.UUID) error
	
	// Delete operations
	Delete(ctx context.Context, id uuid.UUID) error
	SoftDelete(ctx context.Context, id uuid.UUID) error
}

// OAuthClientRepository defines the interface for OAuth client data access
type OAuthClientRepository interface {
	// Create operations
	Create(ctx context.Context, client *models.OAuthClient) error
	
	// Read operations
	GetByID(ctx context.Context, id uuid.UUID) (*models.OAuthClient, error)
	GetByClientID(ctx context.Context, clientID string) (*models.OAuthClient, error)
	List(ctx context.Context, limit, offset int) ([]*models.OAuthClient, error)
	ListActive(ctx context.Context, limit, offset int) ([]*models.OAuthClient, error)
	Count(ctx context.Context) (int64, error)
	
	// Update operations
	Update(ctx context.Context, client *models.OAuthClient) error
	UpdateSecret(ctx context.Context, clientID, secretHash string) error
	SetActive(ctx context.Context, clientID string, active bool) error
	
	// Delete operations
	Delete(ctx context.Context, id uuid.UUID) error
	SoftDelete(ctx context.Context, id uuid.UUID) error
}

// SigningKeyRepository defines the interface for signing key data access
type SigningKeyRepository interface {
	// Create operations
	Create(ctx context.Context, key *models.SigningKey) error
	
	// Read operations
	GetByID(ctx context.Context, keyID string) (*models.SigningKey, error)
	GetActive(ctx context.Context) (*models.SigningKey, error)
	ListActive(ctx context.Context) ([]*models.SigningKey, error)
	List(ctx context.Context, limit, offset int) ([]*models.SigningKey, error)
	
	// Update operations
	Update(ctx context.Context, key *models.SigningKey) error
	SetActive(ctx context.Context, keyID string, active bool) error
	DeactivateAll(ctx context.Context) error
	
	// Delete operations
	Delete(ctx context.Context, keyID string) error
	DeleteExpired(ctx context.Context) (int64, error)
}

// AuthSessionRepository defines the interface for auth session data access
type AuthSessionRepository interface {
	// Create operations
	Create(ctx context.Context, session *models.AuthSession) error
	
	// Read operations
	GetByID(ctx context.Context, id uuid.UUID) (*models.AuthSession, error)
	GetBySessionID(ctx context.Context, sessionID string) (*models.AuthSession, error)
	GetByUserID(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*models.AuthSession, error)
	ListActive(ctx context.Context, limit, offset int) ([]*models.AuthSession, error)
	
	// Update operations
	Update(ctx context.Context, session *models.AuthSession) error
	ExtendExpiration(ctx context.Context, sessionID string, newExpiry time.Time) error
	
	// Delete operations
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteBySessionID(ctx context.Context, sessionID string) error
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error
	DeleteExpired(ctx context.Context) (int64, error)
}

// AuthCodeRepository defines the interface for authorization code data access
type AuthCodeRepository interface {
	// Create operations
	Create(ctx context.Context, code *models.AuthCode) error
	
	// Read operations
	GetByCode(ctx context.Context, code string) (*models.AuthCode, error)
	GetByUserID(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*models.AuthCode, error)
	
	// Update operations
	MarkAsUsed(ctx context.Context, code string) error
	
	// Delete operations
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteByCode(ctx context.Context, code string) error
	DeleteExpired(ctx context.Context) (int64, error)
}

// RefreshTokenRepository defines the interface for refresh token data access
type RefreshTokenRepository interface {
	// Create operations
	Create(ctx context.Context, token *models.RefreshToken) error
	
	// Read operations
	GetByToken(ctx context.Context, token string) (*models.RefreshToken, error)
	GetByUserID(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*models.RefreshToken, error)
	GetByTokenFamily(ctx context.Context, family uuid.UUID) ([]*models.RefreshToken, error)
	ListActive(ctx context.Context, limit, offset int) ([]*models.RefreshToken, error)
	
	// Update operations
	Update(ctx context.Context, token *models.RefreshToken) error
	Revoke(ctx context.Context, token string) error
	RevokeFamily(ctx context.Context, family uuid.UUID) error
	RevokeByUserID(ctx context.Context, userID uuid.UUID) error
	
	// Delete operations
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteByToken(ctx context.Context, token string) error
	DeleteExpired(ctx context.Context) (int64, error)
}

// LoginAttemptRepository defines the interface for login attempt data access
type LoginAttemptRepository interface {
	// Create operations
	Create(ctx context.Context, attempt *models.LoginAttempt) error
	
	// Read operations
	GetByEmail(ctx context.Context, email string, limit, offset int) ([]*models.LoginAttempt, error)
	GetByIP(ctx context.Context, ip net.IP, limit, offset int) ([]*models.LoginAttempt, error)
	GetRecentFailures(ctx context.Context, email string, ip net.IP, since time.Time) ([]*models.LoginAttempt, error)
	CountRecentFailures(ctx context.Context, email string, ip net.IP, since time.Time) (int64, error)
	
	// Delete operations
	DeleteOld(ctx context.Context, before time.Time) (int64, error)
}

// PasswordResetTokenRepository defines the interface for password reset token data access
type PasswordResetTokenRepository interface {
	// Create operations
	Create(ctx context.Context, token *models.PasswordResetToken) error
	
	// Read operations
	GetByToken(ctx context.Context, token string) (*models.PasswordResetToken, error)
	GetByUserID(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*models.PasswordResetToken, error)
	
	// Update operations
	MarkAsUsed(ctx context.Context, token string) error
	
	// Delete operations
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteByToken(ctx context.Context, token string) error
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error
	DeleteExpired(ctx context.Context) (int64, error)
}

// AuditLogRepository defines the interface for audit log data access
type AuditLogRepository interface {
	// Create operations
	Create(ctx context.Context, log *models.AuditLog) error
	CreateBatch(ctx context.Context, logs []*models.AuditLog) error
	
	// Read operations
	GetByID(ctx context.Context, id uuid.UUID) (*models.AuditLog, error)
	List(ctx context.Context, limit, offset int) ([]*models.AuditLog, error)
	ListByActor(ctx context.Context, actorType, actorID string, limit, offset int) ([]*models.AuditLog, error)
	ListByTarget(ctx context.Context, targetType, targetID string, limit, offset int) ([]*models.AuditLog, error)
	ListByEventType(ctx context.Context, eventType string, limit, offset int) ([]*models.AuditLog, error)
	ListByTimeRange(ctx context.Context, start, end time.Time, limit, offset int) ([]*models.AuditLog, error)
	Count(ctx context.Context) (int64, error)
	
	// Delete operations
	DeleteOld(ctx context.Context, before time.Time) (int64, error)
}

// Repository aggregates all repository interfaces
type Repository struct {
	User               UserRepository
	OAuthClient        OAuthClientRepository
	SigningKey         SigningKeyRepository
	AuthSession        AuthSessionRepository
	AuthCode           AuthCodeRepository
	RefreshToken       RefreshTokenRepository
	LoginAttempt       LoginAttemptRepository
	PasswordResetToken PasswordResetTokenRepository
	AuditLog           AuditLogRepository
}

// Transaction interface for database transactions
type Transaction interface {
	// Commit commits the transaction
	Commit() error
	
	// Rollback rolls back the transaction
	Rollback() error
	
	// Repository returns repository instances bound to this transaction
	Repository() *Repository
}

// Manager interface for repository management
type Manager interface {
	// Repository returns the main repository instance
	Repository() *Repository
	
	// Transaction starts a new database transaction
	Transaction(ctx context.Context) (Transaction, error)
	
	// Close closes the repository manager
	Close() error
	
	// Health checks the database connection
	Health(ctx context.Context) error
}