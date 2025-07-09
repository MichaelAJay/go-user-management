package user

import (
	"errors"
	"fmt"
)

// Sentinel errors for expected conditions
var (
	ErrUserNotFound      = errors.New("user not found")
	ErrUserExists        = errors.New("user already exists")
	ErrInvalidEmail      = errors.New("invalid email format")
	ErrInvalidInput      = errors.New("invalid input")
	ErrVersionMismatch   = errors.New("version mismatch")
	ErrUserInactive      = errors.New("user is inactive")
	ErrUserNotVerified   = errors.New("user is not verified")
)

// AppError represents a structured application error
type AppError struct {
	Code    string
	Message string
	Err     error
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// Unwrap returns the underlying error
func (e *AppError) Unwrap() error {
	return e.Err
}

// Is checks if the error matches the target
func (e *AppError) Is(target error) bool {
	return errors.Is(e.Err, target)
}

// NewAppError creates a new application error
func NewAppError(code, message string, err error) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

// Error codes for different error types
const (
	ErrCodeNotFound     = "USER_NOT_FOUND"
	ErrCodeExists       = "USER_EXISTS"
	ErrCodeInvalidEmail = "INVALID_EMAIL"
	ErrCodeInvalidInput = "INVALID_INPUT"
	ErrCodeVersion      = "VERSION_MISMATCH"
	ErrCodeInactive     = "USER_INACTIVE"
	ErrCodeNotVerified  = "USER_NOT_VERIFIED"
	ErrCodeStorage      = "STORAGE_ERROR"
	ErrCodeEncryption   = "ENCRYPTION_ERROR"
)

// Helper functions for common error scenarios
func NewNotFoundError(message string) *AppError {
	return NewAppError(ErrCodeNotFound, message, ErrUserNotFound)
}

func NewExistsError(message string) *AppError {
	return NewAppError(ErrCodeExists, message, ErrUserExists)
}

func NewInvalidEmailError(message string) *AppError {
	return NewAppError(ErrCodeInvalidEmail, message, ErrInvalidEmail)
}

func NewInvalidInputError(message string) *AppError {
	return NewAppError(ErrCodeInvalidInput, message, ErrInvalidInput)
}

func NewVersionMismatchError(message string) *AppError {
	return NewAppError(ErrCodeVersion, message, ErrVersionMismatch)
}

func NewInactiveError(message string) *AppError {
	return NewAppError(ErrCodeInactive, message, ErrUserInactive)
}

func NewNotVerifiedError(message string) *AppError {
	return NewAppError(ErrCodeNotVerified, message, ErrUserNotVerified)
}

func NewStorageError(message string, err error) *AppError {
	return NewAppError(ErrCodeStorage, message, err)
}

func NewEncryptionError(message string, err error) *AppError {
	return NewAppError(ErrCodeEncryption, message, err)
}