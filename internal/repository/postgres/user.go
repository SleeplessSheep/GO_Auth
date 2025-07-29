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

// userRepository implements the UserRepository interface using GORM
type userRepository struct {
	db *gorm.DB
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *gorm.DB) repository.UserRepository {
	return &userRepository{db: db}
}

// Create creates a new user
func (r *userRepository) Create(ctx context.Context, user *models.User) error {
	if err := r.db.WithContext(ctx).Create(user).Error; err != nil {
		return handleGORMError(err, "user", "create")
	}
	return nil
}

// GetByID retrieves a user by ID
func (r *userRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	var user models.User
	if err := r.db.WithContext(ctx).First(&user, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, repository.ErrNotFound
		}
		return nil, handleGORMError(err, "user", "get")
	}
	return &user, nil
}

// GetByEmail retrieves a user by email
func (r *userRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	if err := r.db.WithContext(ctx).Where("email = ? AND deleted_at IS NULL", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, repository.ErrNotFound
		}
		return nil, handleGORMError(err, "user", "get")
	}
	return &user, nil
}

// GetByGoogleID retrieves a user by Google ID
func (r *userRepository) GetByGoogleID(ctx context.Context, googleID string) (*models.User, error) {
	var user models.User
	if err := r.db.WithContext(ctx).Where("google_id = ? AND deleted_at IS NULL", googleID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, repository.ErrNotFound
		}
		return nil, handleGORMError(err, "user", "get")
	}
	return &user, nil
}

// List retrieves users with pagination
func (r *userRepository) List(ctx context.Context, limit, offset int) ([]*models.User, error) {
	var users []*models.User
	query := r.db.WithContext(ctx).Where("deleted_at IS NULL").Order("created_at DESC")
	
	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}
	
	if err := query.Find(&users).Error; err != nil {
		return nil, handleGORMError(err, "user", "list")
	}
	return users, nil
}

// Count returns the total number of users
func (r *userRepository) Count(ctx context.Context) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&models.User{}).Where("deleted_at IS NULL").Count(&count).Error; err != nil {
		return 0, handleGORMError(err, "user", "count")
	}
	return count, nil
}

// Update updates a user
func (r *userRepository) Update(ctx context.Context, user *models.User) error {
	if err := r.db.WithContext(ctx).Save(user).Error; err != nil {
		return handleGORMError(err, "user", "update")
	}
	return nil
}

// UpdateLastLogin updates the last login time for a user
func (r *userRepository) UpdateLastLogin(ctx context.Context, userID uuid.UUID, loginTime time.Time) error {
	if err := r.db.WithContext(ctx).Model(&models.User{}).Where("id = ?", userID).Update("last_login_at", loginTime).Error; err != nil {
		return handleGORMError(err, "user", "update_last_login")
	}
	return nil
}

// UpdatePassword updates the password hash for a user
func (r *userRepository) UpdatePassword(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	if err := r.db.WithContext(ctx).Model(&models.User{}).Where("id = ?", userID).Update("password_hash", passwordHash).Error; err != nil {
		return handleGORMError(err, "user", "update_password")
	}
	return nil
}

// EnableTFA enables two-factor authentication for a user
func (r *userRepository) EnableTFA(ctx context.Context, userID uuid.UUID, secret string) error {
	updates := map[string]interface{}{
		"tfa_secret":  secret,
		"tfa_enabled": true,
	}
	if err := r.db.WithContext(ctx).Model(&models.User{}).Where("id = ?", userID).Updates(updates).Error; err != nil {
		return handleGORMError(err, "user", "enable_tfa")
	}
	return nil
}

// DisableTFA disables two-factor authentication for a user
func (r *userRepository) DisableTFA(ctx context.Context, userID uuid.UUID) error {
	updates := map[string]interface{}{
		"tfa_secret":  nil,
		"tfa_enabled": false,
	}
	if err := r.db.WithContext(ctx).Model(&models.User{}).Where("id = ?", userID).Updates(updates).Error; err != nil {
		return handleGORMError(err, "user", "disable_tfa")
	}
	return nil
}

// Delete permanently deletes a user
func (r *userRepository) Delete(ctx context.Context, id uuid.UUID) error {
	if err := r.db.WithContext(ctx).Unscoped().Delete(&models.User{}, "id = ?", id).Error; err != nil {
		return handleGORMError(err, "user", "delete")
	}
	return nil
}

// SoftDelete soft deletes a user
func (r *userRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	if err := r.db.WithContext(ctx).Delete(&models.User{}, "id = ?", id).Error; err != nil {
		return handleGORMError(err, "user", "soft_delete")
	}
	return nil
}