package postgres

import (
	"context"
	"errors"
	"time"

	"auth/internal/models"
	"auth/internal/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// authSessionRepository implements the AuthSessionRepository interface using GORM
type authSessionRepository struct {
	db *gorm.DB
}

// NewAuthSessionRepository creates a new auth session repository
func NewAuthSessionRepository(db *gorm.DB) repository.AuthSessionRepository {
	return &authSessionRepository{db: db}
}

// Create creates a new auth session
func (r *authSessionRepository) Create(ctx context.Context, session *models.AuthSession) error {
	if err := r.db.WithContext(ctx).Create(session).Error; err != nil {
		return handleGORMError(err, "auth_session", "create")
	}
	return nil
}

// GetByID retrieves an auth session by ID
func (r *authSessionRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.AuthSession, error) {
	var session models.AuthSession
	if err := r.db.WithContext(ctx).Preload("User").First(&session, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, repository.ErrNotFound
		}
		return nil, handleGORMError(err, "auth_session", "get")
	}
	return &session, nil
}

// GetBySessionID retrieves an auth session by session ID
func (r *authSessionRepository) GetBySessionID(ctx context.Context, sessionID string) (*models.AuthSession, error) {
	var session models.AuthSession
	if err := r.db.WithContext(ctx).Preload("User").Where("session_id = ? AND expires_at > NOW()", sessionID).First(&session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, repository.ErrNotFound
		}
		return nil, handleGORMError(err, "auth_session", "get")
	}
	return &session, nil
}

// GetByUserID retrieves auth sessions by user ID with pagination
func (r *authSessionRepository) GetByUserID(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*models.AuthSession, error) {
	var sessions []*models.AuthSession
	query := r.db.WithContext(ctx).Where("user_id = ?", userID).Order("created_at DESC")
	
	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}
	
	if err := query.Find(&sessions).Error; err != nil {
		return nil, handleGORMError(err, "auth_session", "get_by_user")
	}
	return sessions, nil
}

// ListActive retrieves active auth sessions with pagination
func (r *authSessionRepository) ListActive(ctx context.Context, limit, offset int) ([]*models.AuthSession, error) {
	var sessions []*models.AuthSession
	query := r.db.WithContext(ctx).Preload("User").Where("expires_at > NOW()").Order("created_at DESC")
	
	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}
	
	if err := query.Find(&sessions).Error; err != nil {
		return nil, handleGORMError(err, "auth_session", "list_active")
	}
	return sessions, nil
}

// Update updates an auth session
func (r *authSessionRepository) Update(ctx context.Context, session *models.AuthSession) error {
	if err := r.db.WithContext(ctx).Save(session).Error; err != nil {
		return handleGORMError(err, "auth_session", "update")
	}
	return nil
}

// ExtendExpiration extends the expiration time of a session
func (r *authSessionRepository) ExtendExpiration(ctx context.Context, sessionID string, newExpiry time.Time) error {
	if err := r.db.WithContext(ctx).Model(&models.AuthSession{}).Where("session_id = ?", sessionID).Update("expires_at", newExpiry).Error; err != nil {
		return handleGORMError(err, "auth_session", "extend_expiration")
	}
	return nil
}

// Delete permanently deletes an auth session
func (r *authSessionRepository) Delete(ctx context.Context, id uuid.UUID) error {
	if err := r.db.WithContext(ctx).Delete(&models.AuthSession{}, "id = ?", id).Error; err != nil {
		return handleGORMError(err, "auth_session", "delete")
	}
	return nil
}

// DeleteBySessionID deletes an auth session by session ID
func (r *authSessionRepository) DeleteBySessionID(ctx context.Context, sessionID string) error {
	if err := r.db.WithContext(ctx).Delete(&models.AuthSession{}, "session_id = ?", sessionID).Error; err != nil {
		return handleGORMError(err, "auth_session", "delete")
	}
	return nil
}

// DeleteByUserID deletes all auth sessions for a user
func (r *authSessionRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	if err := r.db.WithContext(ctx).Delete(&models.AuthSession{}, "user_id = ?", userID).Error; err != nil {
		return handleGORMError(err, "auth_session", "delete_by_user")
	}
	return nil
}

// DeleteExpired deletes expired auth sessions
func (r *authSessionRepository) DeleteExpired(ctx context.Context) (int64, error) {
	result := r.db.WithContext(ctx).Where("expires_at < NOW()").Delete(&models.AuthSession{})
	if result.Error != nil {
		return 0, handleGORMError(result.Error, "auth_session", "delete_expired")
	}
	return result.RowsAffected, nil
}