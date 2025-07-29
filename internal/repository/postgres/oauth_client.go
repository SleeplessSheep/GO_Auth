package postgres

import (
	"context"
	"errors"

	"auth/internal/models"
	"auth/internal/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// oauthClientRepository implements the OAuthClientRepository interface using GORM
type oauthClientRepository struct {
	db *gorm.DB
}

// NewOAuthClientRepository creates a new OAuth client repository
func NewOAuthClientRepository(db *gorm.DB) repository.OAuthClientRepository {
	return &oauthClientRepository{db: db}
}

// Create creates a new OAuth client
func (r *oauthClientRepository) Create(ctx context.Context, client *models.OAuthClient) error {
	if err := r.db.WithContext(ctx).Create(client).Error; err != nil {
		return handleGORMError(err, "oauth_client", "create")
	}
	return nil
}

// GetByID retrieves an OAuth client by ID
func (r *oauthClientRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.OAuthClient, error) {
	var client models.OAuthClient
	if err := r.db.WithContext(ctx).First(&client, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, repository.ErrNotFound
		}
		return nil, handleGORMError(err, "oauth_client", "get")
	}
	return &client, nil
}

// GetByClientID retrieves an OAuth client by client ID
func (r *oauthClientRepository) GetByClientID(ctx context.Context, clientID string) (*models.OAuthClient, error) {
	var client models.OAuthClient
	if err := r.db.WithContext(ctx).Where("client_id = ? AND deleted_at IS NULL", clientID).First(&client).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, repository.ErrNotFound
		}
		return nil, handleGORMError(err, "oauth_client", "get")
	}
	return &client, nil
}

// List retrieves OAuth clients with pagination
func (r *oauthClientRepository) List(ctx context.Context, limit, offset int) ([]*models.OAuthClient, error) {
	var clients []*models.OAuthClient
	query := r.db.WithContext(ctx).Where("deleted_at IS NULL").Order("created_at DESC")
	
	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}
	
	if err := query.Find(&clients).Error; err != nil {
		return nil, handleGORMError(err, "oauth_client", "list")
	}
	return clients, nil
}

// ListActive retrieves active OAuth clients with pagination
func (r *oauthClientRepository) ListActive(ctx context.Context, limit, offset int) ([]*models.OAuthClient, error) {
	var clients []*models.OAuthClient
	query := r.db.WithContext(ctx).Where("is_active = ? AND deleted_at IS NULL", true).Order("created_at DESC")
	
	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}
	
	if err := query.Find(&clients).Error; err != nil {
		return nil, handleGORMError(err, "oauth_client", "list_active")
	}
	return clients, nil
}

// Count returns the total number of OAuth clients
func (r *oauthClientRepository) Count(ctx context.Context) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&models.OAuthClient{}).Where("deleted_at IS NULL").Count(&count).Error; err != nil {
		return 0, handleGORMError(err, "oauth_client", "count")
	}
	return count, nil
}

// Update updates an OAuth client
func (r *oauthClientRepository) Update(ctx context.Context, client *models.OAuthClient) error {
	if err := r.db.WithContext(ctx).Save(client).Error; err != nil {
		return handleGORMError(err, "oauth_client", "update")
	}
	return nil
}

// UpdateSecret updates the client secret hash
func (r *oauthClientRepository) UpdateSecret(ctx context.Context, clientID, secretHash string) error {
	if err := r.db.WithContext(ctx).Model(&models.OAuthClient{}).Where("client_id = ?", clientID).Update("client_secret_hash", secretHash).Error; err != nil {
		return handleGORMError(err, "oauth_client", "update_secret")
	}
	return nil
}

// SetActive sets the active status of an OAuth client
func (r *oauthClientRepository) SetActive(ctx context.Context, clientID string, active bool) error {
	if err := r.db.WithContext(ctx).Model(&models.OAuthClient{}).Where("client_id = ?", clientID).Update("is_active", active).Error; err != nil {
		return handleGORMError(err, "oauth_client", "set_active")
	}
	return nil
}

// Delete permanently deletes an OAuth client
func (r *oauthClientRepository) Delete(ctx context.Context, id uuid.UUID) error {
	if err := r.db.WithContext(ctx).Unscoped().Delete(&models.OAuthClient{}, "id = ?", id).Error; err != nil {
		return handleGORMError(err, "oauth_client", "delete")
	}
	return nil
}

// SoftDelete soft deletes an OAuth client
func (r *oauthClientRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	if err := r.db.WithContext(ctx).Delete(&models.OAuthClient{}, "id = ?", id).Error; err != nil {
		return handleGORMError(err, "oauth_client", "soft_delete")
	}
	return nil
}