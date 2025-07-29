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

type auditLogRepository struct {
	db *gorm.DB
}

func NewAuditLogRepository(db *gorm.DB) repository.AuditLogRepository {
	return &auditLogRepository{db: db}
}

func (r *auditLogRepository) Create(ctx context.Context, log *models.AuditLog) error {
	if err := r.db.WithContext(ctx).Create(log).Error; err != nil {
		return handleGORMError(err, "audit_log", "create")
	}
	return nil
}

func (r *auditLogRepository) CreateBatch(ctx context.Context, logs []*models.AuditLog) error {
	if err := r.db.WithContext(ctx).CreateInBatches(logs, 100).Error; err != nil {
		return handleGORMError(err, "audit_log", "create_batch")
	}
	return nil
}

func (r *auditLogRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.AuditLog, error) {
	var log models.AuditLog
	if err := r.db.WithContext(ctx).First(&log, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, repository.ErrNotFound
		}
		return nil, handleGORMError(err, "audit_log", "get")
	}
	return &log, nil
}

func (r *auditLogRepository) List(ctx context.Context, limit, offset int) ([]*models.AuditLog, error) {
	var logs []*models.AuditLog
	query := r.db.WithContext(ctx).Order("occurred_at DESC")
	
	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}
	
	if err := query.Find(&logs).Error; err != nil {
		return nil, handleGORMError(err, "audit_log", "list")
	}
	return logs, nil
}

func (r *auditLogRepository) ListByActor(ctx context.Context, actorType, actorID string, limit, offset int) ([]*models.AuditLog, error) {
	var logs []*models.AuditLog
	query := r.db.WithContext(ctx).Where("actor_type = ? AND actor_id = ?", actorType, actorID).Order("occurred_at DESC")
	
	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}
	
	if err := query.Find(&logs).Error; err != nil {
		return nil, handleGORMError(err, "audit_log", "list_by_actor")
	}
	return logs, nil
}

func (r *auditLogRepository) ListByTarget(ctx context.Context, targetType, targetID string, limit, offset int) ([]*models.AuditLog, error) {
	var logs []*models.AuditLog
	query := r.db.WithContext(ctx).Where("target_type = ? AND target_id = ?", targetType, targetID).Order("occurred_at DESC")
	
	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}
	
	if err := query.Find(&logs).Error; err != nil {
		return nil, handleGORMError(err, "audit_log", "list_by_target")
	}
	return logs, nil
}

func (r *auditLogRepository) ListByEventType(ctx context.Context, eventType string, limit, offset int) ([]*models.AuditLog, error) {
	var logs []*models.AuditLog
	query := r.db.WithContext(ctx).Where("event_type = ?", eventType).Order("occurred_at DESC")
	
	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}
	
	if err := query.Find(&logs).Error; err != nil {
		return nil, handleGORMError(err, "audit_log", "list_by_event_type")
	}
	return logs, nil
}

func (r *auditLogRepository) ListByTimeRange(ctx context.Context, start, end time.Time, limit, offset int) ([]*models.AuditLog, error) {
	var logs []*models.AuditLog
	query := r.db.WithContext(ctx).Where("occurred_at BETWEEN ? AND ?", start, end).Order("occurred_at DESC")
	
	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}
	
	if err := query.Find(&logs).Error; err != nil {
		return nil, handleGORMError(err, "audit_log", "list_by_time_range")
	}
	return logs, nil
}

func (r *auditLogRepository) Count(ctx context.Context) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&models.AuditLog{}).Count(&count).Error; err != nil {
		return 0, handleGORMError(err, "audit_log", "count")
	}
	return count, nil
}

func (r *auditLogRepository) DeleteOld(ctx context.Context, before time.Time) (int64, error) {
	result := r.db.WithContext(ctx).Where("occurred_at < ?", before).Delete(&models.AuditLog{})
	if result.Error != nil {
		return 0, handleGORMError(result.Error, "audit_log", "delete_old")
	}
	return result.RowsAffected, nil
}