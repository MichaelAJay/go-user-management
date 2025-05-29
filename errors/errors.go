package errors

import (
	"errors"
	"fmt"
)

// Core error definitions for the user management package
// These errors provide specific context for different failure scenarios

// User-related errors
var (
	// ErrUserNotFound indicates the requested user was not found
	ErrUserNotFound = errors.New("user not found")

	// ErrInvalidUserID indicates the provided user ID is invalid
	ErrInvalidUserID = errors.New("invalid user ID")

	// ErrInvalidEmail indicates the provided email is invalid
	ErrInvalidEmail = errors.New("invalid email address")

	// ErrInvalidPassword indicates the provided password is invalid
	ErrInvalidPassword = errors.New("invalid password")

	// ErrInvalidUserStatus indicates the user status is invalid
	ErrInvalidUserStatus = errors.New("invalid user status")

	// ErrInvalidVersion indicates the version number is invalid
	ErrInvalidVersion = errors.New("invalid version number")

	// ErrDuplicateEmail indicates an attempt to create a user with an existing email
	ErrDuplicateEmail = errors.New("email address already exists")

	// ErrWeakPassword indicates the password does not meet strength requirements
	ErrWeakPassword = errors.New("password does not meet strength requirements")

	// ErrUserAlreadyExists indicates the user already exists in the system
	ErrUserAlreadyExists = errors.New("user already exists")

	// ErrUserDeactivated indicates the user account has been deactivated
	ErrUserDeactivated = errors.New("user account is deactivated")

	// ErrUserSuspended indicates the user account has been suspended
	ErrUserSuspended = errors.New("user account is suspended")
)

// Authentication-related errors
var (
	// ErrInvalidCredentials indicates the provided credentials are invalid
	ErrInvalidCredentials = errors.New("invalid credentials")

	// ErrAccountLocked indicates the user account is locked due to failed login attempts
	ErrAccountLocked = errors.New("account locked due to too many failed attempts")

	// ErrAccountNotActivated indicates the user account has not been activated
	ErrAccountNotActivated = errors.New("account not activated")

	// ErrMaxLoginAttemptsExceeded indicates too many login attempts have been made
	ErrMaxLoginAttemptsExceeded = errors.New("maximum login attempts exceeded")

	// ErrAuthenticationFailed indicates authentication failed for an unspecified reason
	ErrAuthenticationFailed = errors.New("authentication failed")

	// ErrPasswordMismatch indicates the current password doesn't match when updating
	ErrPasswordMismatch = errors.New("current password does not match")
)

// Session-related errors
var (
	// ErrSessionNotFound indicates the requested session was not found
	ErrSessionNotFound = errors.New("session not found")

	// ErrSessionExpired indicates the session has expired
	ErrSessionExpired = errors.New("session has expired")

	// ErrSessionRevoked indicates the session has been revoked
	ErrSessionRevoked = errors.New("session has been revoked")

	// ErrInvalidSessionToken indicates the session token is invalid
	ErrInvalidSessionToken = errors.New("invalid session token")

	// ErrSessionAlreadyExists indicates a session already exists for this user/context
	ErrSessionAlreadyExists = errors.New("session already exists")
)

// Token-related errors
var (
	// ErrTokenNotFound indicates the requested token was not found
	ErrTokenNotFound = errors.New("token not found")

	// ErrTokenExpired indicates the token has expired
	ErrTokenExpired = errors.New("token has expired")

	// ErrTokenAlreadyUsed indicates the token has already been used
	ErrTokenAlreadyUsed = errors.New("token has already been used")

	// ErrInvalidToken indicates the token is invalid or malformed
	ErrInvalidToken = errors.New("invalid token")

	// ErrTokenGenerationFailed indicates token generation failed
	ErrTokenGenerationFailed = errors.New("token generation failed")
)

// Validation-related errors
var (
	// ErrValidationFailed indicates general validation failure
	ErrValidationFailed = errors.New("validation failed")

	// ErrEmailValidationFailed indicates email validation failed
	ErrEmailValidationFailed = errors.New("email validation failed")

	// ErrPasswordValidationFailed indicates password validation failed
	ErrPasswordValidationFailed = errors.New("password validation failed")

	// ErrRequiredFieldMissing indicates a required field is missing
	ErrRequiredFieldMissing = errors.New("required field is missing")

	// ErrInvalidFieldFormat indicates a field has an invalid format
	ErrInvalidFieldFormat = errors.New("invalid field format")

	// ErrFieldTooLong indicates a field exceeds maximum length
	ErrFieldTooLong = errors.New("field exceeds maximum length")

	// ErrFieldTooShort indicates a field is below minimum length
	ErrFieldTooShort = errors.New("field is below minimum length")
)

// Data integrity and concurrency errors
var (
	// ErrVersionMismatch indicates a version mismatch in optimistic locking
	ErrVersionMismatch = errors.New("version mismatch - record was modified by another process")

	// ErrConcurrentModification indicates concurrent modification of the same resource
	ErrConcurrentModification = errors.New("concurrent modification detected")

	// ErrDataCorruption indicates data corruption was detected
	ErrDataCorruption = errors.New("data corruption detected")

	// ErrOptimisticLockFailed indicates optimistic locking failed
	ErrOptimisticLockFailed = errors.New("optimistic lock failed")
)

// Service-level errors
var (
	// ErrServiceUnavailable indicates the service is temporarily unavailable
	ErrServiceUnavailable = errors.New("service temporarily unavailable")

	// ErrInternalError indicates an internal service error
	ErrInternalError = errors.New("internal service error")

	// ErrDependencyFailure indicates a dependency service failed
	ErrDependencyFailure = errors.New("dependency service failure")

	// ErrConfigurationError indicates a configuration error
	ErrConfigurationError = errors.New("configuration error")

	// ErrRateLimitExceeded indicates rate limiting has been triggered
	ErrRateLimitExceeded = errors.New("rate limit exceeded")
)

// Repository and storage errors
var (
	// ErrRepositoryFailure indicates a repository operation failed
	ErrRepositoryFailure = errors.New("repository operation failed")

	// ErrDatabaseConnection indicates database connection failed
	ErrDatabaseConnection = errors.New("database connection failed")

	// ErrQueryFailed indicates a database query failed
	ErrQueryFailed = errors.New("database query failed")

	// ErrTransactionFailed indicates a database transaction failed
	ErrTransactionFailed = errors.New("database transaction failed")

	// ErrCacheMiss indicates a cache miss occurred
	ErrCacheMiss = errors.New("cache miss")

	// ErrCacheFailure indicates a cache operation failed
	ErrCacheFailure = errors.New("cache operation failed")
)

// Context and cancellation errors
var (
	// ErrContextCancelled indicates the context was cancelled
	ErrContextCancelled = errors.New("context cancelled")

	// ErrTimeout indicates an operation timed out
	ErrTimeout = errors.New("operation timed out")

	// ErrDeadlineExceeded indicates a deadline was exceeded
	ErrDeadlineExceeded = errors.New("deadline exceeded")
)

// ErrorCode represents standardized error codes for API responses
type ErrorCode string

const (
	// User error codes
	CodeUserNotFound        ErrorCode = "USER_NOT_FOUND"
	CodeInvalidCredentials  ErrorCode = "INVALID_CREDENTIALS"
	CodeAccountLocked       ErrorCode = "ACCOUNT_LOCKED"
	CodeAccountNotActivated ErrorCode = "ACCOUNT_NOT_ACTIVATED"
	CodeDuplicateEmail      ErrorCode = "DUPLICATE_EMAIL"
	CodeWeakPassword        ErrorCode = "WEAK_PASSWORD"
	CodeUserDeactivated     ErrorCode = "USER_DEACTIVATED"
	CodeUserSuspended       ErrorCode = "USER_SUSPENDED"

	// Session error codes
	CodeSessionNotFound     ErrorCode = "SESSION_NOT_FOUND"
	CodeSessionExpired      ErrorCode = "SESSION_EXPIRED"
	CodeSessionRevoked      ErrorCode = "SESSION_REVOKED"
	CodeInvalidSessionToken ErrorCode = "INVALID_SESSION_TOKEN"

	// Token error codes
	CodeTokenNotFound    ErrorCode = "TOKEN_NOT_FOUND"
	CodeTokenExpired     ErrorCode = "TOKEN_EXPIRED"
	CodeTokenAlreadyUsed ErrorCode = "TOKEN_ALREADY_USED"
	CodeInvalidToken     ErrorCode = "INVALID_TOKEN"

	// Validation error codes
	CodeValidationFailed         ErrorCode = "VALIDATION_FAILED"
	CodeEmailValidationFailed    ErrorCode = "EMAIL_VALIDATION_FAILED"
	CodePasswordValidationFailed ErrorCode = "PASSWORD_VALIDATION_FAILED"
	CodeRequiredFieldMissing     ErrorCode = "REQUIRED_FIELD_MISSING"
	CodeInvalidFieldFormat       ErrorCode = "INVALID_FIELD_FORMAT"
	CodeInvalidName              ErrorCode = "INVALID_NAME"
	CodeInvalidEmailFormat       ErrorCode = "INVALID_EMAIL_FORMAT"
	CodeMissingCredentials       ErrorCode = "MISSING_CREDENTIALS"
	CodeUnsupportedProvider      ErrorCode = "UNSUPPORTED_AUTH_PROVIDER"
	CodeEmptyField               ErrorCode = "EMPTY_FIELD"

	// System error codes
	CodeInternalError      ErrorCode = "INTERNAL_ERROR"
	CodeServiceUnavailable ErrorCode = "SERVICE_UNAVAILABLE"
	CodeRateLimitExceeded  ErrorCode = "RATE_LIMIT_EXCEEDED"
	CodeVersionMismatch    ErrorCode = "VERSION_MISMATCH"
	CodeNotImplemented     ErrorCode = "NOT_IMPLEMENTED"
)

// AppError represents a structured application error with context
type AppError struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	Details string    `json:"details,omitempty"`
	Cause   error     `json:"-"` // Don't serialize the underlying error
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying error for error wrapping
func (e *AppError) Unwrap() error {
	return e.Cause
}

// NewAppError creates a new AppError with the given code and message
func NewAppError(code ErrorCode, message string) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
	}
}

// NewAppErrorWithCause creates a new AppError with an underlying cause
func NewAppErrorWithCause(code ErrorCode, message string, cause error) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// NewAppErrorWithDetails creates a new AppError with additional details
func NewAppErrorWithDetails(code ErrorCode, message, details string) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Details: details,
	}
}

// Wrap wraps an existing error with an AppError
func Wrap(err error, code ErrorCode, message string) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Cause:   err,
	}
}

// Helper functions to create common errors with proper codes

// NewUserNotFoundError creates a user not found error
func NewUserNotFoundError(userID string) *AppError {
	return NewAppErrorWithDetails(CodeUserNotFound, "User not found", fmt.Sprintf("User ID: %s", userID))
}

// NewInvalidCredentialsError creates an invalid credentials error
func NewInvalidCredentialsError() *AppError {
	return NewAppError(CodeInvalidCredentials, "Invalid email or password")
}

// NewAccountLockedError creates an account locked error
func NewAccountLockedError(until string) *AppError {
	if until != "" {
		return NewAppErrorWithDetails(CodeAccountLocked, "Account temporarily locked", fmt.Sprintf("Locked until: %s", until))
	}
	return NewAppError(CodeAccountLocked, "Account locked due to too many failed attempts")
}

// NewDuplicateEmailError creates a duplicate email error
func NewDuplicateEmailError(email string) *AppError {
	return NewAppErrorWithDetails(CodeDuplicateEmail, "Email address already exists", fmt.Sprintf("Email: %s", email))
}

// NewWeakPasswordError creates a weak password error
func NewWeakPasswordError(requirements string) *AppError {
	return NewAppErrorWithDetails(CodeWeakPassword, "Password does not meet requirements", requirements)
}

// NewSessionExpiredError creates a session expired error
func NewSessionExpiredError() *AppError {
	return NewAppError(CodeSessionExpired, "Session has expired, please log in again")
}

// NewValidationError creates a validation error
func NewValidationError(field, reason string) *AppError {
	return NewAppErrorWithDetails(CodeValidationFailed, "Validation failed", fmt.Sprintf("Field: %s, Reason: %s", field, reason))
}

// NewVersionMismatchError creates a version mismatch error
func NewVersionMismatchError(expected, actual int64) *AppError {
	return NewAppErrorWithDetails(CodeVersionMismatch, "Record was modified by another process",
		fmt.Sprintf("Expected version: %d, Actual version: %d", expected, actual))
}

// NewInvalidNameError creates an invalid name error
func NewInvalidNameError(field string) *AppError {
	return NewAppErrorWithDetails(CodeInvalidName, "Invalid name field",
		fmt.Sprintf("Field: %s", field))
}

// NewInvalidEmailFormatError creates an invalid email format error
func NewInvalidEmailFormatError(email string) *AppError {
	return NewAppErrorWithDetails(CodeInvalidEmailFormat, "Invalid email format",
		fmt.Sprintf("Email: %s", email))
}

// NewMissingCredentialsError creates a missing credentials error
func NewMissingCredentialsError() *AppError {
	return NewAppError(CodeMissingCredentials, "Authentication credentials are required")
}

// NewUnsupportedProviderError creates an unsupported provider error
func NewUnsupportedProviderError(provider string) *AppError {
	return NewAppErrorWithDetails(CodeUnsupportedProvider, "Unsupported authentication provider",
		fmt.Sprintf("Provider: %s", provider))
}

// IsErrorType checks if an error is of a specific type
func IsErrorType(err error, target error) bool {
	return errors.Is(err, target)
}

// GetErrorCode extracts the error code from an error
func GetErrorCode(err error) ErrorCode {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Code
	}
	return CodeInternalError
}
