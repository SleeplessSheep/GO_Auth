package postgres

import (
	"context"
	"errors"

	"auth/internal/models"
	"auth/internal/repository"
	"gorm.io/gorm"
)

// signingKeyRepository implements the SigningKeyRepository interface using GORM
type signingKeyRepository struct {
	db *gorm.DB
}

// NewSigningKeyRepository creates a new signing key repository
func NewSigningKeyRepository(db *gorm.DB) repository.SigningKeyRepository {
	return &signingKeyRepository{db: db}
}

// Create creates a new signing key
func (r *signingKeyRepository) Create(ctx context.Context, key *models.SigningKey) error {
	if err := r.db.WithContext(ctx).Create(key).Error; err != nil {
		return handleGORMError(err, "signing_key", "create")
	}
	return nil
}

// GetByID retrieves a signing key by ID
func (r *signingKeyRepository) GetByID(ctx context.Context, keyID string) (*models.SigningKey, error) {
	var key models.SigningKey
	if err := r.db.WithContext(ctx).First(&key, "id = ?", keyID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, repository.ErrNotFound
		}
		return nil, handleGORMError(err, "signing_key", "get")
	}
	return &key, nil
}

// GetActive retrieves the active signing key
func (r *signingKeyRepository) GetActive(ctx context.Context) (*models.SigningKey, error) {
	var key models.SigningKey
	if err := r.db.WithContext(ctx).Where("is_active = ?", true).First(&key).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, repository.ErrNotFound
		}
		return nil, handleGORMError(err, "signing_key", "get_active")
	}
	return &key, nil
}

// ListActive retrieves all active signing keys
func (r *signingKeyRepository) ListActive(ctx context.Context) ([]*models.SigningKey, error) {
	var keys []*models.SigningKey
	if err := r.db.WithContext(ctx).Where("is_active = ?", true).Order("created_at DESC").Find(&keys).Error; err != nil {
		return nil, handleGORMError(err, "signing_key", "list_active")
	}
	return keys, nil
}

// List retrieves signing keys with pagination
func (r *signingKeyRepository) List(ctx context.Context, limit, offset int) ([]*models.SigningKey, error) {
	var keys []*models.SigningKey
	query := r.db.WithContext(ctx).Order("created_at DESC")
	
	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}
	
	if err := query.Find(&keys).Error; err != nil {
		return nil, handleGORMError(err, "signing_key", "list")
	}
	return keys, nil
}

// Update updates a signing key
func (r *signingKeyRepository) Update(ctx context.Context, key *models.SigningKey) error {
	if err := r.db.WithContext(ctx).Save(key).Error; err != nil {
		return handleGORMError(err, "signing_key", "update")
	}
	return nil
}

// SetActive sets the active status of a signing key
func (r *signingKeyRepository) SetActive(ctx context.Context, keyID string, active bool) error {
	if err := r.db.WithContext(ctx).Model(&models.SigningKey{}).Where("id = ?", keyID).Update("is_active", active).Error; err != nil {
		return handleGORMError(err, "signing_key", "set_active")
	}
	return nil
}

// DeactivateAll deactivates all signing keys
func (r *signingKeyRepository) DeactivateAll(ctx context.Context) error {
	if err := r.db.WithContext(ctx).Model(&models.SigningKey{}).Where("is_active = ?", true).Update("is_active", false).Error; err != nil {
		return handleGORMError(err, "signing_key", "deactivate_all")
	}
	return nil
}

// Delete permanently deletes a signing key
func (r *signingKeyRepository) Delete(ctx context.Context, keyID string) error {
	if err := r.db.WithContext(ctx).Delete(&models.SigningKey{}, "id = ?", keyID).Error; err != nil {
		return handleGORMError(err, "signing_key", "delete")
	}
	return nil
}

// DeleteExpired deletes expired signing keys
func (r *signingKeyRepository) DeleteExpired(ctx context.Context) (int64, error) {
	result := r.db.WithContext(ctx).Where("expires_at IS NOT NULL AND expires_at < NOW()").Delete(&models.SigningKey{})
	if result.Error != nil {
		return 0, handleGORMError(result.Error, "signing_key", "delete_expired")
	}
	return result.RowsAffected, nil
}