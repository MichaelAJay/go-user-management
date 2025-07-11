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
func (s *Service) CreateUser(ctx context.Context, req *CreateUserRequest) (*UserResponse, error) {
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

	// Encrypt PII data before creating User
	encryptedEmail, err := s.encrypter.Encrypt([]byte(req.Email))
	if err != nil {
		return nil, NewEncryptionError("failed to encrypt email", err)
	}

	encryptedFirstName, err := s.encrypter.Encrypt([]byte(req.FirstName))
	if err != nil {
		return nil, NewEncryptionError("failed to encrypt first name", err)
	}

	encryptedLastName, err := s.encrypter.Encrypt([]byte(req.LastName))
	if err != nil {
		return nil, NewEncryptionError("failed to encrypt last name", err)
	}

	// Create user with encrypted data - PII never exists unencrypted in User
	user := NewUser(encryptedEmail, encryptedFirstName, encryptedLastName)

	// Store user
	if err := s.repo.Create(ctx, user); err != nil {
		return nil, NewStorageError("failed to create user", err)
	}

	// Return UserResponse with decrypted PII
	return s.toUserResponse(user)
}

// GetUserByID retrieves a user by ID with PII decryption
func (s *Service) GetUserByID(ctx context.Context, id uuid.UUID) (*UserResponse, error) {
	user, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, NewStorageError("failed to get user by ID", err)
	}
	if user == nil {
		return nil, NewNotFoundError("user not found")
	}

	// Return UserResponse with decrypted PII
	return s.toUserResponse(user)
}

// GetUserByEmail retrieves a user by email with PII decryption
func (s *Service) GetUserByEmail(ctx context.Context, email string) (*UserResponse, error) {
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

	// Return UserResponse with decrypted PII
	return s.toUserResponse(user)
}

// UpdateUser updates a user with optimistic locking
func (s *Service) UpdateUser(ctx context.Context, req *UpdateUserRequest) (*UserResponse, error) {
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

	// Decrypt current user PII for updates
	emailBytes, err := s.encrypter.Decrypt(currentUser.Email)
	if err != nil {
		return nil, NewEncryptionError("failed to decrypt email", err)
	}
	firstNameBytes, err := s.encrypter.Decrypt(currentUser.FirstName)
	if err != nil {
		return nil, NewEncryptionError("failed to decrypt first name", err)
	}
	lastNameBytes, err := s.encrypter.Decrypt(currentUser.LastName)
	if err != nil {
		return nil, NewEncryptionError("failed to decrypt last name", err)
	}

	// Update fields
	if req.FirstName != nil {
		firstNameBytes = []byte(*req.FirstName)
	}
	if req.LastName != nil {
		lastNameBytes = []byte(*req.LastName)
	}
	if req.IsActive != nil {
		currentUser.IsActive = *req.IsActive
	}
	if req.IsVerified != nil {
		currentUser.IsVerified = *req.IsVerified
	}

	// Update version
	currentUser.UpdateVersion()

	// Encrypt updated PII fields
	encryptedEmail, err := s.encrypter.Encrypt(emailBytes)
	if err != nil {
		return nil, NewEncryptionError("failed to encrypt email", err)
	}
	encryptedFirstName, err := s.encrypter.Encrypt(firstNameBytes)
	if err != nil {
		return nil, NewEncryptionError("failed to encrypt first name", err)
	}
	encryptedLastName, err := s.encrypter.Encrypt(lastNameBytes)
	if err != nil {
		return nil, NewEncryptionError("failed to encrypt last name", err)
	}

	// Update user with encrypted PII
	currentUser.Email = encryptedEmail
	currentUser.FirstName = encryptedFirstName
	currentUser.LastName = encryptedLastName

	// Store updated user
	if err := s.repo.Update(ctx, currentUser); err != nil {
		return nil, NewStorageError("failed to update user", err)
	}

	// Return UserResponse with decrypted PII
	return s.toUserResponse(currentUser)
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

	// User is already encrypted, no need to encrypt again

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

	// User is already encrypted, no need to encrypt again

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

	// User is already encrypted, no need to encrypt again

	if err := s.repo.Update(ctx, user); err != nil {
		return NewStorageError("failed to update user", err)
	}

	return nil
}

// toUserResponse converts a User to UserResponse with decrypted PII
func (s *Service) toUserResponse(user *User) (*UserResponse, error) {
	// Decrypt PII fields
	emailBytes, err := s.encrypter.Decrypt(user.Email)
	if err != nil {
		return nil, NewEncryptionError("failed to decrypt email", err)
	}

	firstNameBytes, err := s.encrypter.Decrypt(user.FirstName)
	if err != nil {
		return nil, NewEncryptionError("failed to decrypt first name", err)
	}

	lastNameBytes, err := s.encrypter.Decrypt(user.LastName)
	if err != nil {
		return nil, NewEncryptionError("failed to decrypt last name", err)
	}

	return &UserResponse{
		ID:          user.ID,
		Email:       string(emailBytes),
		FirstName:   string(firstNameBytes),
		LastName:    string(lastNameBytes),
		IsActive:    user.IsActive,
		IsVerified:  user.IsVerified,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		LastLoginAt: user.LastLoginAt,
		Version:     user.Version,
	}, nil
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
