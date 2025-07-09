package user

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/MichaelAJay/go-encrypter"
	"github.com/google/uuid"
)

// Service provides business logic for user management
type Service struct {
	repo      UserRepository
	encrypter encrypter.Encrypter
}

// NewService creates a new user service
func NewService(repo UserRepository, enc encrypter.Encrypter) *Service {
	return &Service{
		repo:      repo,
		encrypter: enc,
	}
}

// CreateUser creates a new user with PII encryption
func (s *Service) CreateUser(ctx context.Context, req *CreateUserRequest) (*User, error) {
	if err := s.validateCreateUserRequest(req); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Check if user already exists
	exists, err := s.repo.Exists(ctx, req.Email)
	if err != nil {
		return nil, NewStorageError("failed to check user existence", err)
	}
	if exists {
		return nil, NewExistsError("user with this email already exists")
	}

	// Create user with unencrypted data
	user := NewUser(req.Email, req.FirstName, req.LastName)

	// Encrypt PII fields before storing
	if err := s.encryptUserPII(user); err != nil {
		return nil, NewEncryptionError("failed to encrypt user PII", err)
	}

	// Store user
	if err := s.repo.Create(ctx, user); err != nil {
		return nil, NewStorageError("failed to create user", err)
	}

	// Decrypt PII for return (service layer responsibility)
	if err := s.decryptUserPII(user); err != nil {
		return nil, NewEncryptionError("failed to decrypt user PII", err)
	}

	return user, nil
}

// GetUserByID retrieves a user by ID with PII decryption
func (s *Service) GetUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	user, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, NewStorageError("failed to get user by ID", err)
	}
	if user == nil {
		return nil, NewNotFoundError("user not found")
	}

	// Decrypt PII fields
	if err := s.decryptUserPII(user); err != nil {
		return nil, NewEncryptionError("failed to decrypt user PII", err)
	}

	return user, nil
}

// GetUserByEmail retrieves a user by email with PII decryption
func (s *Service) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	if !s.isValidEmail(email) {
		return nil, NewInvalidEmailError("invalid email format")
	}

	user, err := s.repo.GetByEmail(ctx, email)
	if err != nil {
		return nil, NewStorageError("failed to get user by email", err)
	}
	if user == nil {
		return nil, NewNotFoundError("user not found")
	}

	// Decrypt PII fields
	if err := s.decryptUserPII(user); err != nil {
		return nil, NewEncryptionError("failed to decrypt user PII", err)
	}

	return user, nil
}

// UpdateUser updates a user with optimistic locking
func (s *Service) UpdateUser(ctx context.Context, req *UpdateUserRequest) (*User, error) {
	if err := s.validateUpdateUserRequest(req); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Get current user
	currentUser, err := s.repo.GetByID(ctx, req.ID)
	if err != nil {
		return nil, NewStorageError("failed to get current user", err)
	}
	if currentUser == nil {
		return nil, NewNotFoundError("user not found")
	}

	// Check version for optimistic locking
	if currentUser.Version != req.Version {
		return nil, NewVersionMismatchError("user was modified by another process")
	}

	// Update fields
	if req.FirstName != nil {
		currentUser.FirstName = *req.FirstName
	}
	if req.LastName != nil {
		currentUser.LastName = *req.LastName
	}
	if req.IsActive != nil {
		currentUser.IsActive = *req.IsActive
	}
	if req.IsVerified != nil {
		currentUser.IsVerified = *req.IsVerified
	}

	// Update version
	currentUser.UpdateVersion()

	// Encrypt PII fields before storing
	if err := s.encryptUserPII(currentUser); err != nil {
		return nil, NewEncryptionError("failed to encrypt user PII", err)
	}

	// Store updated user
	if err := s.repo.Update(ctx, currentUser); err != nil {
		return nil, NewStorageError("failed to update user", err)
	}

	// Decrypt PII for return
	if err := s.decryptUserPII(currentUser); err != nil {
		return nil, NewEncryptionError("failed to decrypt user PII", err)
	}

	return currentUser, nil
}

// DeleteUser deletes a user
func (s *Service) DeleteUser(ctx context.Context, id uuid.UUID) error {
	if err := s.repo.Delete(ctx, id); err != nil {
		return NewStorageError("failed to delete user", err)
	}
	return nil
}

// ActivateUser activates a user
func (s *Service) ActivateUser(ctx context.Context, id uuid.UUID) error {
	user, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return NewStorageError("failed to get user", err)
	}
	if user == nil {
		return NewNotFoundError("user not found")
	}

	user.Activate()

	// Encrypt PII before storing
	if err := s.encryptUserPII(user); err != nil {
		return NewEncryptionError("failed to encrypt user PII", err)
	}

	if err := s.repo.Update(ctx, user); err != nil {
		return NewStorageError("failed to update user", err)
	}

	return nil
}

// DeactivateUser deactivates a user
func (s *Service) DeactivateUser(ctx context.Context, id uuid.UUID) error {
	user, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return NewStorageError("failed to get user", err)
	}
	if user == nil {
		return NewNotFoundError("user not found")
	}

	user.Deactivate()

	// Encrypt PII before storing
	if err := s.encryptUserPII(user); err != nil {
		return NewEncryptionError("failed to encrypt user PII", err)
	}

	if err := s.repo.Update(ctx, user); err != nil {
		return NewStorageError("failed to update user", err)
	}

	return nil
}

// RecordLogin records a user login
func (s *Service) RecordLogin(ctx context.Context, id uuid.UUID) error {
	user, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return NewStorageError("failed to get user", err)
	}
	if user == nil {
		return NewNotFoundError("user not found")
	}

	if !user.IsActive {
		return NewInactiveError("user is inactive")
	}

	user.RecordLogin()

	// Encrypt PII before storing
	if err := s.encryptUserPII(user); err != nil {
		return NewEncryptionError("failed to encrypt user PII", err)
	}

	if err := s.repo.Update(ctx, user); err != nil {
		return NewStorageError("failed to update user", err)
	}

	return nil
}

// encryptUserPII encrypts PII fields in the user
func (s *Service) encryptUserPII(user *User) error {
	var err error

	// Convert string to bytes, encrypt, then convert back to string
	emailBytes, err := s.encrypter.Encrypt([]byte(user.Email))
	if err != nil {
		return fmt.Errorf("failed to encrypt email: %w", err)
	}
	user.Email = string(emailBytes)

	firstNameBytes, err := s.encrypter.Encrypt([]byte(user.FirstName))
	if err != nil {
		return fmt.Errorf("failed to encrypt first name: %w", err)
	}
	user.FirstName = string(firstNameBytes)

	lastNameBytes, err := s.encrypter.Encrypt([]byte(user.LastName))
	if err != nil {
		return fmt.Errorf("failed to encrypt last name: %w", err)
	}
	user.LastName = string(lastNameBytes)

	return nil
}

// decryptUserPII decrypts PII fields in the user
func (s *Service) decryptUserPII(user *User) error {
	var err error

	// Convert string to bytes, decrypt, then convert back to string
	emailBytes, err := s.encrypter.Decrypt([]byte(user.Email))
	if err != nil {
		return fmt.Errorf("failed to decrypt email: %w", err)
	}
	user.Email = string(emailBytes)

	firstNameBytes, err := s.encrypter.Decrypt([]byte(user.FirstName))
	if err != nil {
		return fmt.Errorf("failed to decrypt first name: %w", err)
	}
	user.FirstName = string(firstNameBytes)

	lastNameBytes, err := s.encrypter.Decrypt([]byte(user.LastName))
	if err != nil {
		return fmt.Errorf("failed to decrypt last name: %w", err)
	}
	user.LastName = string(lastNameBytes)

	return nil
}

// validateCreateUserRequest validates create user request
func (s *Service) validateCreateUserRequest(req *CreateUserRequest) error {
	if req == nil {
		return NewInvalidInputError("request is nil")
	}

	if strings.TrimSpace(req.Email) == "" {
		return NewInvalidInputError("email is required")
	}

	if !s.isValidEmail(req.Email) {
		return NewInvalidEmailError("invalid email format")
	}

	if strings.TrimSpace(req.FirstName) == "" {
		return NewInvalidInputError("first name is required")
	}

	if strings.TrimSpace(req.LastName) == "" {
		return NewInvalidInputError("last name is required")
	}

	return nil
}

// validateUpdateUserRequest validates update user request
func (s *Service) validateUpdateUserRequest(req *UpdateUserRequest) error {
	if req == nil {
		return NewInvalidInputError("request is nil")
	}

	if req.ID == uuid.Nil {
		return NewInvalidInputError("user ID is required")
	}

	if req.FirstName != nil && strings.TrimSpace(*req.FirstName) == "" {
		return NewInvalidInputError("first name cannot be empty")
	}

	if req.LastName != nil && strings.TrimSpace(*req.LastName) == "" {
		return NewInvalidInputError("last name cannot be empty")
	}

	return nil
}

// isValidEmail validates email format
func (s *Service) isValidEmail(email string) bool {
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	regex := regexp.MustCompile(pattern)
	return regex.MatchString(email)
}