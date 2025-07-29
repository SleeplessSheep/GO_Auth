package postgres

import (
	"context"
	"net"
	"time"

	"auth/internal/models"
	"auth/internal/repository"
	"gorm.io/gorm"
)

type loginAttemptRepository struct {
	db *gorm.DB
}

func NewLoginAttemptRepository(db *gorm.DB) repository.LoginAttemptRepository {
	return &loginAttemptRepository{db: db}
}

func (r *loginAttemptRepository) Create(ctx context.Context, attempt *models.LoginAttempt) error {
	if err := r.db.WithContext(ctx).Create(attempt).Error; err != nil {
		return handleGORMError(err, "login_attempt", "create")
	}
	return nil
}

func (r *loginAttemptRepository) GetByEmail(ctx context.Context, email string, limit, offset int) ([]*models.LoginAttempt, error) {
	var attempts []*models.LoginAttempt
	query := r.db.WithContext(ctx).Where("email = ?", email).Order("attempted_at DESC")
	
	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}
	
	if err := query.Find(&attempts).Error; err != nil {
		return nil, handleGORMError(err, "login_attempt", "get_by_email")
	}
	return attempts, nil
}

func (r *loginAttemptRepository) GetByIP(ctx context.Context, ip net.IP, limit, offset int) ([]*models.LoginAttempt, error) {
	var attempts []*models.LoginAttempt
	query := r.db.WithContext(ctx).Where("ip_address = ?", ip).Order("attempted_at DESC")
	
	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}
	
	if err := query.Find(&attempts).Error; err != nil {
		return nil, handleGORMError(err, "login_attempt", "get_by_ip")
	}
	return attempts, nil
}

func (r *loginAttemptRepository) GetRecentFailures(ctx context.Context, email string, ip net.IP, since time.Time) ([]*models.LoginAttempt, error) {
	var attempts []*models.LoginAttempt
	query := r.db.WithContext(ctx).Where("email = ? AND ip_address = ? AND attempted_at > ? AND successful = ?", email, ip, since, false)
	
	if err := query.Find(&attempts).Error; err != nil {
		return nil, handleGORMError(err, "login_attempt", "get_recent_failures")
	}
	return attempts, nil
}

func (r *loginAttemptRepository) CountRecentFailures(ctx context.Context, email string, ip net.IP, since time.Time) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).Where("email = ? AND ip_address = ? AND attempted_at > ? AND successful = ?", email, ip, since, false).Count(&count).Error; err != nil {
		return 0, handleGORMError(err, "login_attempt", "count_recent_failures")
	}
	return count, nil
}

func (r *loginAttemptRepository) DeleteOld(ctx context.Context, before time.Time) (int64, error) {
	result := r.db.WithContext(ctx).Delete(&models.LoginAttempt{}, "attempted_at < ?", before)
	if result.Error != nil {
		return 0, handleGORMError(result.Error, "login_attempt", "delete_old")
	}
	return result.RowsAffected, nil
}