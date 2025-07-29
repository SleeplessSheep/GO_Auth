package postgres

import (
	"context"

	"auth/internal/database"
	"auth/internal/repository"
	"gorm.io/gorm"
)

// manager implements the repository.Manager interface
type manager struct {
	db   *database.DB
	repo *repository.Repository
}

// NewManager creates a new repository manager
func NewManager(db *database.DB) repository.Manager {
	gormDB := db.DB
	
	repo := &repository.Repository{
		User:               NewUserRepository(gormDB),
		OAuthClient:        NewOAuthClientRepository(gormDB),
		SigningKey:         NewSigningKeyRepository(gormDB),
		AuthSession:        NewAuthSessionRepository(gormDB),
		AuthCode:           NewAuthCodeRepository(gormDB),
		RefreshToken:       NewRefreshTokenRepository(gormDB),
		LoginAttempt:       NewLoginAttemptRepository(gormDB),
		PasswordResetToken: NewPasswordResetTokenRepository(gormDB),
		AuditLog:           NewAuditLogRepository(gormDB),
	}
	
	return &manager{
		db:   db,
		repo: repo,
	}
}

// Repository returns the main repository instance
func (m *manager) Repository() *repository.Repository {
	return m.repo
}

// Transaction starts a new database transaction
func (m *manager) Transaction(ctx context.Context) (repository.Transaction, error) {
	tx := m.db.DB.Begin()
	if tx.Error != nil {
		return nil, handleGORMError(tx.Error, "transaction", "begin")
	}
	
	return newTransaction(tx), nil
}

// Close closes the repository manager
func (m *manager) Close() error {
	return m.db.Close()
}

// Health checks the database connection
func (m *manager) Health(ctx context.Context) error {
	return m.db.Health()
}

// transaction implements the repository.Transaction interface
type transaction struct {
	tx   *gorm.DB
	repo *repository.Repository
}

// newTransaction creates a new transaction
func newTransaction(tx *gorm.DB) repository.Transaction {
	repo := &repository.Repository{
		User:               NewUserRepository(tx),
		OAuthClient:        NewOAuthClientRepository(tx),
		SigningKey:         NewSigningKeyRepository(tx),
		AuthSession:        NewAuthSessionRepository(tx),
		AuthCode:           NewAuthCodeRepository(tx),
		RefreshToken:       NewRefreshTokenRepository(tx),
		LoginAttempt:       NewLoginAttemptRepository(tx),
		PasswordResetToken: NewPasswordResetTokenRepository(tx),
		AuditLog:           NewAuditLogRepository(tx),
	}
	
	return &transaction{
		tx:   tx,
		repo: repo,
	}
}

// Commit commits the transaction
func (t *transaction) Commit() error {
	if err := t.tx.Commit().Error; err != nil {
		return handleGORMError(err, "transaction", "commit")
	}
	return nil
}

// Rollback rolls back the transaction
func (t *transaction) Rollback() error {
	if err := t.tx.Rollback().Error; err != nil {
		return handleGORMError(err, "transaction", "rollback")
	}
	return nil
}

// Repository returns repository instances bound to this transaction
func (t *transaction) Repository() *repository.Repository {
	return t.repo
}