package postgres

import (
	"errors"
	"fmt"
	"strings"

	"auth/internal/repository"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// handleGORMError converts GORM/PostgreSQL errors to repository errors
func handleGORMError(err error, entity, operation string) error {
	if err == nil {
		return nil
	}

	// Handle GORM specific errors
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return repository.ErrNotFound
	}
	
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return repository.ErrConflict
	}

	// Handle PostgreSQL specific errors
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		switch pqErr.Code {
		case "23505": // unique_violation
			return handleUniqueViolation(pqErr)
		case "23503": // foreign_key_violation
			return repository.ErrConstraintViolation
		case "23502": // not_null_violation
			return repository.ErrInvalidInput
		case "23514": // check_violation
			return repository.ErrInvalidInput
		case "42P01": // undefined_table
			return repository.ErrInternal
		case "42703": // undefined_column
			return repository.ErrInternal
		default:
			return &repository.Error{
				Type:      repository.ErrTypeDatabase,
				Operation: operation,
				Entity:    entity,
				Message:   fmt.Sprintf("database error: %s", pqErr.Message),
				Cause:     err,
			}
		}
	}

	// Generic database error
	return &repository.Error{
		Type:      repository.ErrTypeDatabase,
		Operation: operation,
		Entity:    entity,
		Message:   "database operation failed",
		Cause:     err,
	}
}

// handleUniqueViolation extracts field information from unique constraint violations
func handleUniqueViolation(pqErr *pq.Error) error {
	// Extract constraint name to determine which field violated uniqueness
	constraint := pqErr.Constraint
	field := "unknown"
	
	// Map common constraint patterns to field names
	if strings.Contains(constraint, "email") {
		field = "email"
	} else if strings.Contains(constraint, "client_id") {
		field = "client_id"
	} else if strings.Contains(constraint, "google_id") {
		field = "google_id"
	} else if strings.Contains(constraint, "session_id") {
		field = "session_id"
	} else if strings.Contains(constraint, "token") {
		field = "token"
	} else if strings.Contains(constraint, "code") {
		field = "code"
	}

	return &repository.Error{
		Type:      repository.ErrTypeConflict,
		Operation: "create",
		Entity:    extractEntityFromConstraint(constraint),
		Message:   fmt.Sprintf("duplicate value for field '%s'", field),
		Cause:     pqErr,
		Details: map[string]interface{}{
			"constraint": constraint,
			"field":      field,
		},
	}
}

// extractEntityFromConstraint attempts to extract entity name from constraint name
func extractEntityFromConstraint(constraint string) string {
	// Common patterns: idx_users_email, uniq_oauth_clients_client_id, etc.
	parts := strings.Split(constraint, "_")
	if len(parts) >= 2 {
		// Try to find table name pattern
		for i, part := range parts {
			if (part == "idx" || part == "uniq") && i+1 < len(parts) {
				return parts[i+1]
			}
		}
		// Fallback to second part
		return parts[1]
	}
	return "unknown"
}