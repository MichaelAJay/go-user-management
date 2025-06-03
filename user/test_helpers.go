package user

import (
	"context"
	"fmt"

	"github.com/MichaelAJay/go-logger"
	"github.com/MichaelAJay/go-user-management/auth"
)

// MockEncrypter implements the encrypter.Encrypter interface for testing
type MockEncrypter struct {
	shouldFail bool
}

func (m *MockEncrypter) Encrypt(plaintext []byte) ([]byte, error) {
	if m.shouldFail {
		return nil, fmt.Errorf("encryption failed")
	}
	// Simple mock encryption - just return the plaintext prefixed with "encrypted:"
	return append([]byte("encrypted:"), plaintext...), nil
}

func (m *MockEncrypter) EncryptWithAAD(data, additionalData []byte) ([]byte, error) {
	if m.shouldFail {
		return nil, fmt.Errorf("encryption with AAD failed")
	}
	return append([]byte("encrypted:"), data...), nil
}

func (m *MockEncrypter) Decrypt(ciphertext []byte) ([]byte, error) {
	if m.shouldFail {
		return nil, fmt.Errorf("decryption failed")
	}
	// Simple mock decryption - remove the "encrypted:" prefix
	if len(ciphertext) > 10 && string(ciphertext[:10]) == "encrypted:" {
		return ciphertext[10:], nil
	}
	return nil, fmt.Errorf("invalid ciphertext format")
}

func (m *MockEncrypter) DecryptWithAAD(data, additionalData []byte) ([]byte, error) {
	if m.shouldFail {
		return nil, fmt.Errorf("decryption with AAD failed")
	}
	// Simple mock decryption - remove the "encrypted:" prefix
	if len(data) > 10 && string(data[:10]) == "encrypted:" {
		return data[10:], nil
	}
	return nil, fmt.Errorf("invalid ciphertext format")
}

func (m *MockEncrypter) HashPassword(password []byte) ([]byte, error) {
	if m.shouldFail {
		return nil, fmt.Errorf("password hashing failed")
	}
	return []byte("hashed_" + string(password)), nil
}

func (m *MockEncrypter) VerifyPassword(hashedPassword, password []byte) (bool, error) {
	if m.shouldFail {
		return false, fmt.Errorf("password verification failed")
	}
	return string(hashedPassword) == "hashed_"+string(password), nil
}

func (m *MockEncrypter) HashLookupData(data []byte) []byte {
	return append([]byte("hashed_"), data...)
}

func (m *MockEncrypter) GetKeyVersion() string {
	return "v1"
}

// MockLogger implements the logger.Logger interface for testing
type MockLogger struct {
	warnCalled bool
	lastFields []logger.Field
}

func (m *MockLogger) Debug(msg string, fields ...logger.Field) {}
func (m *MockLogger) Info(msg string, fields ...logger.Field)  {}
func (m *MockLogger) Warn(msg string, fields ...logger.Field) {
	m.warnCalled = true
	m.lastFields = fields
}
func (m *MockLogger) Error(msg string, fields ...logger.Field) {}
func (m *MockLogger) Fatal(msg string, fields ...logger.Field) {}
func (m *MockLogger) With(fields ...logger.Field) logger.Logger {
	return m
}
func (m *MockLogger) WithContext(ctx context.Context) logger.Logger {
	return m
}

// Test helper functions that can be used across test files

// createValidUserForTesting creates a valid user for testing purposes
func createValidUserForTesting() *User {
	return NewUser("John", "Doe", "john.doe@example.com", "hashedEmail123", auth.ProviderTypePassword)
}

// createEncryptedDataForTesting creates encrypted data for testing
func createEncryptedDataForTesting(data string) []byte {
	return []byte("encrypted:" + data)
}

// createCompleteTestUser creates a user with all associated entities (User + Security + Credentials)
// This helper ensures tests have complete user setup for authentication scenarios
func createCompleteTestUser(service UserService, ctx context.Context) (*UserResponse, error) {
	// Create user via service - this automatically creates User + Security + Credentials
	createReq := &CreateUserRequest{
		FirstName:              "John",
		LastName:               "Doe",
		Email:                  "john.doe@example.com",
		Credentials:            "password123",
		AuthenticationProvider: auth.ProviderTypePassword,
	}

	userResponse, err := service.CreateUser(ctx, createReq)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return userResponse, nil
}

// createAndActivateTestUser creates a complete user and activates them for authentication testing
func createAndActivateTestUser(service UserService, ctx context.Context) (*UserResponse, error) {
	// Create complete user
	userResponse, err := createCompleteTestUser(service, ctx)
	if err != nil {
		return nil, err
	}

	// Activate the user so they can authenticate
	activatedUser, err := service.ActivateUser(ctx, userResponse.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to activate user: %w", err)
	}

	return activatedUser, nil
}
