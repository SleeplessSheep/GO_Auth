package repository

import (
	"errors"
	"fmt"
)

// Common repository errors
var (
	ErrNotFound            = errors.New("record not found")
	ErrConflict            = errors.New("record already exists")
	ErrInvalidInput        = errors.New("invalid input")
	ErrConstraintViolation = errors.New("constraint violation")
	ErrInternal            = errors.New("internal error")
)

// ErrorType represents the type of repository error
type ErrorType string

const (
	ErrTypeNotFound            ErrorType = "not_found"
	ErrTypeConflict            ErrorType = "conflict"
	ErrTypeInvalidInput        ErrorType = "invalid_input"
	ErrTypeConstraintViolation ErrorType = "constraint_violation"
	ErrTypeDatabase            ErrorType = "database"
	ErrTypeInternal            ErrorType = "internal"
)

// Error represents a detailed repository error
type Error struct {
	Type      ErrorType              `json:"type"`
	Operation string                 `json:"operation"`
	Entity    string                 `json:"entity"`
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Cause     error                  `json:"-"`
}

// Error implements the error interface
func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (caused by: %v)", e.Type, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// Unwrap returns the underlying error
func (e *Error) Unwrap() error {
	return e.Cause
}

// Is checks if this error matches the target error
func (e *Error) Is(target error) bool {
	var repoErr *Error
	if errors.As(target, &repoErr) {
		return e.Type == repoErr.Type
	}
	
	// Check against common errors
	switch target {
	case ErrNotFound:
		return e.Type == ErrTypeNotFound
	case ErrConflict:
		return e.Type == ErrTypeConflict
	case ErrInvalidInput:
		return e.Type == ErrTypeInvalidInput
	case ErrConstraintViolation:
		return e.Type == ErrTypeConstraintViolation
	case ErrInternal:
		return e.Type == ErrTypeInternal
	}
	
	return false
}

// NewError creates a new repository error
func NewError(errType ErrorType, operation, entity, message string) *Error {
	return &Error{
		Type:      errType,
		Operation: operation,
		Entity:    entity,
		Message:   message,
	}
}

// NewErrorWithCause creates a new repository error with a cause
func NewErrorWithCause(errType ErrorType, operation, entity, message string, cause error) *Error {
	return &Error{
		Type:      errType,
		Operation: operation,
		Entity:    entity,
		Message:   message,
		Cause:     cause,
	}
}

// NewErrorWithDetails creates a new repository error with additional details
func NewErrorWithDetails(errType ErrorType, operation, entity, message string, details map[string]interface{}) *Error {
	return &Error{
		Type:      errType,
		Operation: operation,
		Entity:    entity,
		Message:   message,
		Details:   details,
	}
}