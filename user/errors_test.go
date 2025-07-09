package user

import (
	"errors"
	"testing"
)

func TestAppError_Error(t *testing.T) {
	tests := []struct {
		name     string
		appError *AppError
		expected string
	}{
		{
			name: "error with underlying error",
			appError: &AppError{
				Code:    "TEST_CODE",
				Message: "test message",
				Err:     errors.New("underlying error"),
			},
			expected: "test message: underlying error",
		},
		{
			name: "error without underlying error",
			appError: &AppError{
				Code:    "TEST_CODE",
				Message: "test message",
				Err:     nil,
			},
			expected: "test message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.appError.Error(); got != tt.expected {
				t.Errorf("AppError.Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAppError_Unwrap(t *testing.T) {
	underlyingErr := errors.New("underlying error")
	appError := &AppError{
		Code:    "TEST_CODE",
		Message: "test message",
		Err:     underlyingErr,
	}

	if got := appError.Unwrap(); got != underlyingErr {
		t.Errorf("AppError.Unwrap() = %v, want %v", got, underlyingErr)
	}

	// Test with nil underlying error
	appErrorNil := &AppError{
		Code:    "TEST_CODE",
		Message: "test message",
		Err:     nil,
	}

	if got := appErrorNil.Unwrap(); got != nil {
		t.Errorf("AppError.Unwrap() = %v, want nil", got)
	}
}

func TestAppError_Is(t *testing.T) {
	underlyingErr := errors.New("underlying error")
	appError := &AppError{
		Code:    "TEST_CODE",
		Message: "test message",
		Err:     underlyingErr,
	}

	if !appError.Is(underlyingErr) {
		t.Error("AppError.Is() should return true for underlying error")
	}

	otherErr := errors.New("other error")
	if appError.Is(otherErr) {
		t.Error("AppError.Is() should return false for different error")
	}

	// Test with nil underlying error
	appErrorNil := &AppError{
		Code:    "TEST_CODE",
		Message: "test message",
		Err:     nil,
	}

	if appErrorNil.Is(underlyingErr) {
		t.Error("AppError.Is() should return false when underlying error is nil")
	}
}

func TestNewAppError(t *testing.T) {
	code := "TEST_CODE"
	message := "test message"
	err := errors.New("underlying error")

	appError := NewAppError(code, message, err)

	if appError.Code != code {
		t.Errorf("NewAppError() code = %v, want %v", appError.Code, code)
	}

	if appError.Message != message {
		t.Errorf("NewAppError() message = %v, want %v", appError.Message, message)
	}

	if appError.Err != err {
		t.Errorf("NewAppError() err = %v, want %v", appError.Err, err)
	}
}

func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrUserNotFound", ErrUserNotFound},
		{"ErrUserExists", ErrUserExists},
		{"ErrInvalidEmail", ErrInvalidEmail},
		{"ErrInvalidInput", ErrInvalidInput},
		{"ErrVersionMismatch", ErrVersionMismatch},
		{"ErrUserInactive", ErrUserInactive},
		{"ErrUserNotVerified", ErrUserNotVerified},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Errorf("Sentinel error %s should not be nil", tt.name)
			}

			if tt.err.Error() == "" {
				t.Errorf("Sentinel error %s should have non-empty error message", tt.name)
			}
		})
	}
}

func TestErrorHelperFunctions(t *testing.T) {
	tests := []struct {
		name     string
		function func(string) *AppError
		code     string
		message  string
	}{
		{
			name:     "NewNotFoundError",
			function: NewNotFoundError,
			code:     ErrCodeNotFound,
			message:  "user not found",
		},
		{
			name:     "NewExistsError",
			function: NewExistsError,
			code:     ErrCodeExists,
			message:  "user already exists",
		},
		{
			name:     "NewInvalidEmailError",
			function: NewInvalidEmailError,
			code:     ErrCodeInvalidEmail,
			message:  "invalid email format",
		},
		{
			name:     "NewInvalidInputError",
			function: NewInvalidInputError,
			code:     ErrCodeInvalidInput,
			message:  "invalid input",
		},
		{
			name:     "NewVersionMismatchError",
			function: NewVersionMismatchError,
			code:     ErrCodeVersion,
			message:  "version mismatch",
		},
		{
			name:     "NewInactiveError",
			function: NewInactiveError,
			code:     ErrCodeInactive,
			message:  "user is inactive",
		},
		{
			name:     "NewNotVerifiedError",
			function: NewNotVerifiedError,
			code:     ErrCodeNotVerified,
			message:  "user not verified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			appError := tt.function(tt.message)

			if appError.Code != tt.code {
				t.Errorf("%s() code = %v, want %v", tt.name, appError.Code, tt.code)
			}

			if appError.Message != tt.message {
				t.Errorf("%s() message = %v, want %v", tt.name, appError.Message, tt.message)
			}

			if appError.Err == nil {
				t.Errorf("%s() should wrap a sentinel error", tt.name)
			}
		})
	}
}

func TestErrorHelperFunctionsWithUnderlyingError(t *testing.T) {
	underlyingErr := errors.New("database connection failed")
	message := "storage operation failed"

	tests := []struct {
		name     string
		function func(string, error) *AppError
		code     string
	}{
		{
			name:     "NewStorageError",
			function: NewStorageError,
			code:     ErrCodeStorage,
		},
		{
			name:     "NewEncryptionError",
			function: NewEncryptionError,
			code:     ErrCodeEncryption,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			appError := tt.function(message, underlyingErr)

			if appError.Code != tt.code {
				t.Errorf("%s() code = %v, want %v", tt.name, appError.Code, tt.code)
			}

			if appError.Message != message {
				t.Errorf("%s() message = %v, want %v", tt.name, appError.Message, message)
			}

			if appError.Err != underlyingErr {
				t.Errorf("%s() err = %v, want %v", tt.name, appError.Err, underlyingErr)
			}
		})
	}
}

func TestErrorCodes(t *testing.T) {
	tests := []struct {
		name string
		code string
	}{
		{"ErrCodeNotFound", ErrCodeNotFound},
		{"ErrCodeExists", ErrCodeExists},
		{"ErrCodeInvalidEmail", ErrCodeInvalidEmail},
		{"ErrCodeInvalidInput", ErrCodeInvalidInput},
		{"ErrCodeVersion", ErrCodeVersion},
		{"ErrCodeInactive", ErrCodeInactive},
		{"ErrCodeNotVerified", ErrCodeNotVerified},
		{"ErrCodeStorage", ErrCodeStorage},
		{"ErrCodeEncryption", ErrCodeEncryption},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.code == "" {
				t.Errorf("Error code %s should not be empty", tt.name)
			}
		})
	}
}

func TestErrorChaining(t *testing.T) {
	// Test error chaining with errors.Is
	originalErr := errors.New("database error")
	appError := NewStorageError("failed to save user", originalErr)

	if !errors.Is(appError, originalErr) {
		t.Error("AppError should be identifiable as the original error using errors.Is")
	}

	// Test error chaining with errors.As
	var appErr *AppError
	if !errors.As(appError, &appErr) {
		t.Error("Should be able to extract AppError using errors.As")
	}

	if appErr.Code != ErrCodeStorage {
		t.Errorf("Extracted AppError code = %v, want %v", appErr.Code, ErrCodeStorage)
	}
}

func TestErrorWrapping(t *testing.T) {
	// Test that AppError properly wraps sentinel errors
	notFoundErr := NewNotFoundError("user not found")
	
	if !errors.Is(notFoundErr, ErrUserNotFound) {
		t.Error("NewNotFoundError should wrap ErrUserNotFound")
	}

	existsErr := NewExistsError("user exists")
	
	if !errors.Is(existsErr, ErrUserExists) {
		t.Error("NewExistsError should wrap ErrUserExists")
	}

	invalidEmailErr := NewInvalidEmailError("invalid email")
	
	if !errors.Is(invalidEmailErr, ErrInvalidEmail) {
		t.Error("NewInvalidEmailError should wrap ErrInvalidEmail")
	}
}