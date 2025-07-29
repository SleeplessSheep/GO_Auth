package postgres

import (
	"context"
	"errors"

	"auth/internal/models"
	"auth/internal/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type refreshTokenRepository struct {
	db *gorm.DB
}

func NewRefreshTokenRepository(db *gorm.DB) repository.RefreshTokenRepository {
	return &refreshTokenRepository{db: db}
}

func (r *refreshTokenRepository) Create(ctx context.Context, token *models.RefreshToken) error {
	if err := r.db.WithContext(ctx).Create(token).Error; err != nil {
		return handleGORMError(err, "refresh_token", "create")
	}
	return nil
}

func (r *refreshTokenRepository) GetByToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	var refreshToken models.RefreshToken
	if err := r.db.WithContext(ctx).Preload("User").Where("token = ? AND expires_at > NOW() AND revoked_at IS NULL", token).First(&refreshToken).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, repository.ErrNotFound
		}
		return nil, handleGORMError(err, "refresh_token", "get")
	}
	return &refreshToken, nil
}

func (r *refreshTokenRepository) GetByUserID(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*models.RefreshToken, error) {
	var tokens []*models.RefreshToken
	query := r.db.WithContext(ctx).Where("user_id = ?", userID).Order("created_at DESC")
	
	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}
	
	if err := query.Find(&tokens).Error; err != nil {
		return nil, handleGORMError(err, "refresh_token", "get_by_user")
	}
	return tokens, nil
}

func (r *refreshTokenRepository) GetByTokenFamily(ctx context.Context, family uuid.UUID) ([]*models.RefreshToken, error) {
	var tokens []*models.RefreshToken
	if err := r.db.WithContext(ctx).Where("token_family = ?", family).Order("created_at DESC").Find(&tokens).Error; err != nil {
		return nil, handleGORMError(err, "refresh_token", "get_by_family")
	}
	return tokens, nil
}

func (r *refreshTokenRepository) ListActive(ctx context.Context, limit, offset int) ([]*models.RefreshToken, error) {
	var tokens []*models.RefreshToken
	query := r.db.WithContext(ctx).Preload("User").Where("expires_at > NOW() AND revoked_at IS NULL").Order("created_at DESC")
	
	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}
	
	if err := query.Find(&tokens).Error; err != nil {
		return nil, handleGORMError(err, "refresh_token", "list_active")
	}
	return tokens, nil
}

func (r *refreshTokenRepository) Update(ctx context.Context, token *models.RefreshToken) error {
	if err := r.db.WithContext(ctx).Save(token).Error; err != nil {
		return handleGORMError(err, "refresh_token", "update")
	}
	return nil
}

func (r *refreshTokenRepository) Revoke(ctx context.Context, token string) error {
	if err := r.db.WithContext(ctx).Model(&models.RefreshToken{}).Where("token = ?", token).Update("revoked_at", "NOW()").Error; err != nil {
		return handleGORMError(err, "refresh_token", "revoke")
	}
	return nil
}

func (r *refreshTokenRepository) RevokeFamily(ctx context.Context, family uuid.UUID) error {
	if err := r.db.WithContext(ctx).Model(&models.RefreshToken{}).Where("token_family = ? AND revoked_at IS NULL", family).Update("revoked_at", "NOW()").Error; err != nil {
		return handleGORMError(err, "refresh_token", "revoke_family")
	}
	return nil
}

func (r *refreshTokenRepository) RevokeByUserID(ctx context.Context, userID uuid.UUID) error {
	if err := r.db.WithContext(ctx).Model(&models.RefreshToken{}).Where("user_id = ? AND revoked_at IS NULL", userID).Update("revoked_at", "NOW()").Error; err != nil {
		return handleGORMError(err, "refresh_token", "revoke_by_user")
	}
	return nil
}

func (r *refreshTokenRepository) Delete(ctx context.Context, id uuid.UUID) error {
	if err := r.db.WithContext(ctx).Delete(&models.RefreshToken{}, "id = ?", id).Error; err != nil {
		return handleGORMError(err, "refresh_token", "delete")
	}
	return nil
}

func (r *refreshTokenRepository) DeleteByToken(ctx context.Context, token string) error {
	if err := r.db.WithContext(ctx).Delete(&models.RefreshToken{}, "token = ?", token).Error; err != nil {
		return handleGORMError(err, "refresh_token", "delete")
	}
	return nil
}

func (r *refreshTokenRepository) DeleteExpired(ctx context.Context) (int64, error) {
	result := r.db.WithContext(ctx).Where("expires_at < NOW() OR revoked_at IS NOT NULL").Delete(&models.RefreshToken{})
	if result.Error != nil {
		return 0, handleGORMError(result.Error, "refresh_token", "delete_expired")
	}
	return result.RowsAffected, nil
}