package postgres

import (
	"context"
	"errors"

	"auth/internal/models"
	"auth/internal/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type passwordResetTokenRepository struct {
	db *gorm.DB
}

func NewPasswordResetTokenRepository(db *gorm.DB) repository.PasswordResetTokenRepository {
	return &passwordResetTokenRepository{db: db}
}

func (r *passwordResetTokenRepository) Create(ctx context.Context, token *models.PasswordResetToken) error {
	if err := r.db.WithContext(ctx).Create(token).Error; err != nil {
		return handleGORMError(err, "password_reset_token", "create")
	}
	return nil
}

func (r *passwordResetTokenRepository) GetByToken(ctx context.Context, token string) (*models.PasswordResetToken, error) {
	var resetToken models.PasswordResetToken
	if err := r.db.WithContext(ctx).Preload("User").Where("token = ? AND expires_at > NOW() AND used_at IS NULL", token).First(&resetToken).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, repository.ErrNotFound
		}
		return nil, handleGORMError(err, "password_reset_token", "get")
	}
	return &resetToken, nil
}

func (r *passwordResetTokenRepository) GetByUserID(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*models.PasswordResetToken, error) {
	var tokens []*models.PasswordResetToken
	query := r.db.WithContext(ctx).Where("user_id = ?", userID).Order("created_at DESC")
	
	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}
	
	if err := query.Find(&tokens).Error; err != nil {
		return nil, handleGORMError(err, "password_reset_token", "get_by_user")
	}
	return tokens, nil
}

func (r *passwordResetTokenRepository) MarkAsUsed(ctx context.Context, token string) error {
	if err := r.db.WithContext(ctx).Model(&models.PasswordResetToken{}).Where("token = ?", token).Update("used_at", "NOW()").Error; err != nil {
		return handleGORMError(err, "password_reset_token", "mark_used")
	}
	return nil
}

func (r *passwordResetTokenRepository) Delete(ctx context.Context, id uuid.UUID) error {
	if err := r.db.WithContext(ctx).Delete(&models.PasswordResetToken{}, "id = ?", id).Error; err != nil {
		return handleGORMError(err, "password_reset_token", "delete")
	}
	return nil
}

func (r *passwordResetTokenRepository) DeleteByToken(ctx context.Context, token string) error {
	if err := r.db.WithContext(ctx).Delete(&models.PasswordResetToken{}, "token = ?", token).Error; err != nil {
		return handleGORMError(err, "password_reset_token", "delete")
	}
	return nil
}

func (r *passwordResetTokenRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	if err := r.db.WithContext(ctx).Delete(&models.PasswordResetToken{}, "user_id = ?", userID).Error; err != nil {
		return handleGORMError(err, "password_reset_token", "delete_by_user")
	}
	return nil
}

func (r *passwordResetTokenRepository) DeleteExpired(ctx context.Context) (int64, error) {
	result := r.db.WithContext(ctx).Where("expires_at < NOW() OR used_at IS NOT NULL").Delete(&models.PasswordResetToken{})
	if result.Error != nil {
		return 0, handleGORMError(result.Error, "password_reset_token", "delete_expired")
	}
	return result.RowsAffected, nil
}