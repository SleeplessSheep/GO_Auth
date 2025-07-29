package postgres

import (
	"context"
	"errors"

	"auth/internal/models"
	"auth/internal/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type authCodeRepository struct {
	db *gorm.DB
}

func NewAuthCodeRepository(db *gorm.DB) repository.AuthCodeRepository {
	return &authCodeRepository{db: db}
}

func (r *authCodeRepository) Create(ctx context.Context, code *models.AuthCode) error {
	if err := r.db.WithContext(ctx).Create(code).Error; err != nil {
		return handleGORMError(err, "auth_code", "create")
	}
	return nil
}

func (r *authCodeRepository) GetByCode(ctx context.Context, code string) (*models.AuthCode, error) {
	var authCode models.AuthCode
	if err := r.db.WithContext(ctx).Preload("User").Where("code = ? AND expires_at > NOW() AND used_at IS NULL", code).First(&authCode).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, repository.ErrNotFound
		}
		return nil, handleGORMError(err, "auth_code", "get")
	}
	return &authCode, nil
}

func (r *authCodeRepository) GetByUserID(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*models.AuthCode, error) {
	var codes []*models.AuthCode
	query := r.db.WithContext(ctx).Where("user_id = ?", userID).Order("created_at DESC")
	
	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}
	
	if err := query.Find(&codes).Error; err != nil {
		return nil, handleGORMError(err, "auth_code", "get_by_user")
	}
	return codes, nil
}

func (r *authCodeRepository) MarkAsUsed(ctx context.Context, code string) error {
	if err := r.db.WithContext(ctx).Model(&models.AuthCode{}).Where("code = ?", code).Update("used_at", "NOW()").Error; err != nil {
		return handleGORMError(err, "auth_code", "mark_used")
	}
	return nil
}

func (r *authCodeRepository) Delete(ctx context.Context, id uuid.UUID) error {
	if err := r.db.WithContext(ctx).Delete(&models.AuthCode{}, "id = ?", id).Error; err != nil {
		return handleGORMError(err, "auth_code", "delete")
	}
	return nil
}

func (r *authCodeRepository) DeleteByCode(ctx context.Context, code string) error {
	if err := r.db.WithContext(ctx).Delete(&models.AuthCode{}, "code = ?", code).Error; err != nil {
		return handleGORMError(err, "auth_code", "delete")
	}
	return nil
}

func (r *authCodeRepository) DeleteExpired(ctx context.Context) (int64, error) {
	result := r.db.WithContext(ctx).Where("expires_at < NOW() OR used_at IS NOT NULL").Delete(&models.AuthCode{})
	if result.Error != nil {
		return 0, handleGORMError(result.Error, "auth_code", "delete_expired")
	}
	return result.RowsAffected, nil
}