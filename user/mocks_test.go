package user

import (
	"context"
	"errors"
	"sync"

	"github.com/google/uuid"
)

// MockUserRepository is a mock implementation of UserRepository for testing
type MockUserRepository struct {
	mu    sync.RWMutex
	users map[uuid.UUID]*User
	
	// Control mock behavior
	createError    error
	updateError    error
	deleteError    error
	getByIDError   error
	getByEmailError error
	existsError    error
}

// NewMockUserRepository creates a new mock user repository
func NewMockUserRepository() *MockUserRepository {
	return &MockUserRepository{
		users: make(map[uuid.UUID]*User),
	}
}

// GetByID implements UserReader
func (m *MockUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.getByIDError != nil {
		return nil, m.getByIDError
	}

	user, exists := m.users[id]
	if !exists {
		return nil, nil
	}

	// Return a copy to prevent modifications
	userCopy := *user
	return &userCopy, nil
}

// GetByEmail implements UserReader
func (m *MockUserRepository) GetByEmail(ctx context.Context, email string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.getByEmailError != nil {
		return nil, m.getByEmailError
	}

	// For testing purposes, we'll check both encrypted and plain email
	// In real implementation, this would use a lookup hash or encrypt the search term
	for _, user := range m.users {
		if string(user.Email) == email || string(user.Email) == "encrypted:"+email {
			// Return a copy to prevent modifications
			userCopy := *user
			return &userCopy, nil
		}
	}

	return nil, nil
}

// Exists implements UserReader
func (m *MockUserRepository) Exists(ctx context.Context, email string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.existsError != nil {
		return false, m.existsError
	}

	// For testing purposes, we'll check both encrypted and plain email
	// In real implementation, this would use a lookup hash or encrypt the search term
	for _, user := range m.users {
		if string(user.Email) == email || string(user.Email) == "encrypted:"+email {
			return true, nil
		}
	}

	return false, nil
}

// Create implements UserWriter
func (m *MockUserRepository) Create(ctx context.Context, user *User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.createError != nil {
		return m.createError
	}

	// Check if user already exists
	for _, existingUser := range m.users {
		if string(existingUser.Email) == string(user.Email) {
			return errors.New("user already exists")
		}
	}

	// Store a copy to prevent external modifications
	userCopy := *user
	m.users[user.ID] = &userCopy

	return nil
}

// Update implements UserWriter
func (m *MockUserRepository) Update(ctx context.Context, user *User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.updateError != nil {
		return m.updateError
	}

	_, exists := m.users[user.ID]
	if !exists {
		return errors.New("user not found")
	}

	// Store a copy to prevent external modifications
	userCopy := *user
	m.users[user.ID] = &userCopy

	return nil
}

// Delete implements UserWriter
func (m *MockUserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.deleteError != nil {
		return m.deleteError
	}

	_, exists := m.users[id]
	if !exists {
		return errors.New("user not found")
	}

	delete(m.users, id)
	return nil
}

// Mock control methods for testing
func (m *MockUserRepository) SetCreateError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createError = err
}

func (m *MockUserRepository) SetUpdateError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateError = err
}

func (m *MockUserRepository) SetDeleteError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteError = err
}

func (m *MockUserRepository) SetGetByIDError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getByIDError = err
}

func (m *MockUserRepository) SetGetByEmailError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getByEmailError = err
}

func (m *MockUserRepository) SetExistsError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.existsError = err
}

func (m *MockUserRepository) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users = make(map[uuid.UUID]*User)
}

func (m *MockUserRepository) GetUserCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.users)
}

// MockEncrypter is a mock implementation of Encrypter for testing
type MockEncrypter struct {
	mu sync.RWMutex
	
	// Control mock behavior
	encryptError error
	decryptError error
	
	// Track calls
	encryptCalls [][]byte
	decryptCalls [][]byte
}

// NewMockEncrypter creates a new mock encrypter
func NewMockEncrypter() *MockEncrypter {
	return &MockEncrypter{
		encryptCalls: make([][]byte, 0),
		decryptCalls: make([][]byte, 0),
	}
}

// Encrypt implements Encrypter - simple mock that prefixes data with "encrypted:"
func (m *MockEncrypter) Encrypt(data []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.encryptCalls = append(m.encryptCalls, data)

	if m.encryptError != nil {
		return nil, m.encryptError
	}

	// Simple mock encryption - prefix with "encrypted:"
	result := append([]byte("encrypted:"), data...)
	return result, nil
}

// EncryptWithAAD implements Encrypter
func (m *MockEncrypter) EncryptWithAAD(data, additionalData []byte) ([]byte, error) {
	return m.Encrypt(data)
}

// Decrypt implements Encrypter - removes "encrypted:" prefix
func (m *MockEncrypter) Decrypt(data []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.decryptCalls = append(m.decryptCalls, data)

	if m.decryptError != nil {
		return nil, m.decryptError
	}

	// Simple mock decryption - remove "encrypted:" prefix
	prefix := []byte("encrypted:")
	if len(data) < len(prefix) {
		return nil, errors.New("invalid encrypted data")
	}

	for i, b := range prefix {
		if data[i] != b {
			return nil, errors.New("invalid encrypted data format")
		}
	}

	return data[len(prefix):], nil
}

// DecryptWithAAD implements Encrypter
func (m *MockEncrypter) DecryptWithAAD(data, additionalData []byte) ([]byte, error) {
	return m.Decrypt(data)
}

// HashPassword implements Encrypter
func (m *MockEncrypter) HashPassword(password []byte) ([]byte, error) {
	return append([]byte("hashed:"), password...), nil
}

// VerifyPassword implements Encrypter
func (m *MockEncrypter) VerifyPassword(hashedPassword, password []byte) (bool, error) {
	expectedHash := append([]byte("hashed:"), password...)
	return string(hashedPassword) == string(expectedHash), nil
}

// HashLookupData implements Encrypter
func (m *MockEncrypter) HashLookupData(data []byte) []byte {
	return append([]byte("lookup:"), data...)
}

// GetKeyVersion implements Encrypter
func (m *MockEncrypter) GetKeyVersion() string {
	return "mock-v1"
}

// Mock control methods for testing
func (m *MockEncrypter) SetEncryptError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.encryptError = err
}

func (m *MockEncrypter) SetDecryptError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.decryptError = err
}

func (m *MockEncrypter) GetEncryptCalls() [][]byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([][]byte, len(m.encryptCalls))
	copy(result, m.encryptCalls)
	return result
}

func (m *MockEncrypter) GetDecryptCalls() [][]byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([][]byte, len(m.decryptCalls))
	copy(result, m.decryptCalls)
	return result
}

func (m *MockEncrypter) ClearCalls() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.encryptCalls = make([][]byte, 0)
	m.decryptCalls = make([][]byte, 0)
}