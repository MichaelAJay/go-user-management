package user

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestNewService(t *testing.T) {
	repo := NewMockUserRepository()
	encrypter := NewMockEncrypter()

	service := NewService(repo, encrypter)

	if service == nil {
		t.Fatal("NewService() should return a non-nil service")
	}

	if service.repo != repo {
		t.Error("NewService() should set the repository")
	}

	if service.encrypter != encrypter {
		t.Error("NewService() should set the encrypter")
	}
}

func TestService_CreateUser(t *testing.T) {
	tests := []struct {
		name          string
		request       *CreateUserRequest
		setupMocks    func(*MockUserRepository, *MockEncrypter)
		wantErr       bool
		expectedError string
	}{
		{
			name: "successful user creation",
			request: &CreateUserRequest{
				Email:     "test@example.com",
				FirstName: "John",
				LastName:  "Doe",
			},
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				// No setup needed - defaults work
			},
			wantErr: false,
		},
		{
			name:    "nil request",
			request: nil,
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				// No setup needed
			},
			wantErr:       true,
			expectedError: "validation failed",
		},
		{
			name: "empty email",
			request: &CreateUserRequest{
				Email:     "",
				FirstName: "John",
				LastName:  "Doe",
			},
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				// No setup needed
			},
			wantErr:       true,
			expectedError: "validation failed",
		},
		{
			name: "invalid email format",
			request: &CreateUserRequest{
				Email:     "invalid-email",
				FirstName: "John",
				LastName:  "Doe",
			},
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				// No setup needed
			},
			wantErr:       true,
			expectedError: "validation failed",
		},
		{
			name: "empty first name",
			request: &CreateUserRequest{
				Email:     "test@example.com",
				FirstName: "",
				LastName:  "Doe",
			},
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				// No setup needed
			},
			wantErr:       true,
			expectedError: "validation failed",
		},
		{
			name: "empty last name",
			request: &CreateUserRequest{
				Email:     "test@example.com",
				FirstName: "John",
				LastName:  "",
			},
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				// No setup needed
			},
			wantErr:       true,
			expectedError: "validation failed",
		},
		{
			name: "user already exists",
			request: &CreateUserRequest{
				Email:     "test@example.com",
				FirstName: "John",
				LastName:  "Doe",
			},
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				// Create a user first
				existingUser := NewUser([]byte("encrypted:test@example.com"), []byte("encrypted:Jane"), []byte("encrypted:Smith"))
				repo.Create(context.Background(), existingUser)
			},
			wantErr:       true,
			expectedError: "user with this email already exists",
		},
		{
			name: "repository exists error",
			request: &CreateUserRequest{
				Email:     "test@example.com",
				FirstName: "John",
				LastName:  "Doe",
			},
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				repo.SetExistsError(errors.New("database error"))
			},
			wantErr:       true,
			expectedError: "failed to check user existence",
		},
		{
			name: "encryption error",
			request: &CreateUserRequest{
				Email:     "test@example.com",
				FirstName: "John",
				LastName:  "Doe",
			},
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				enc.SetEncryptError(errors.New("encryption failed"))
			},
			wantErr:       true,
			expectedError: "failed to encrypt email",
		},
		{
			name: "repository create error",
			request: &CreateUserRequest{
				Email:     "test@example.com",
				FirstName: "John",
				LastName:  "Doe",
			},
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				repo.SetCreateError(errors.New("database error"))
			},
			wantErr:       true,
			expectedError: "failed to create user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := NewMockUserRepository()
			encrypter := NewMockEncrypter()
			tt.setupMocks(repo, encrypter)

			service := NewService(repo, encrypter)
			user, err := service.CreateUser(context.Background(), tt.request)

			if tt.wantErr {
				if err == nil {
					t.Errorf("CreateUser() expected error, got nil")
				}
				if tt.expectedError != "" && !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("CreateUser() error = %v, want to contain %v", err, tt.expectedError)
				}
				return
			}

			if err != nil {
				t.Errorf("CreateUser() unexpected error = %v", err)
				return
			}

			if user == nil {
				t.Error("CreateUser() should return a user on success")
				return
			}

			// Verify user properties - now returns UserResponse with decrypted PII
			if user.Email != tt.request.Email {
				t.Errorf("CreateUser() email = %v, want %v", user.Email, tt.request.Email)
			}

			if user.FirstName != tt.request.FirstName {
				t.Errorf("CreateUser() firstName = %v, want %v", user.FirstName, tt.request.FirstName)
			}

			if user.LastName != tt.request.LastName {
				t.Errorf("CreateUser() lastName = %v, want %v", user.LastName, tt.request.LastName)
			}

			if !user.IsActive {
				t.Error("CreateUser() should create active user")
			}

			if user.IsVerified {
				t.Error("CreateUser() should create unverified user")
			}
		})
	}
}

func TestService_GetUserByID(t *testing.T) {
	tests := []struct {
		name          string
		userID        uuid.UUID
		setupMocks    func(*MockUserRepository, *MockEncrypter)
		wantErr       bool
		expectedError string
	}{
		{
			name:   "successful user retrieval",
			userID: uuid.New(),
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				user := NewUser([]byte("encrypted:test@example.com"), []byte("encrypted:John"), []byte("encrypted:Doe"))
				user.ID = uuid.New()
				// Store user with encrypted data (mock will handle encryption)
				user.Email = []byte("encrypted:test@example.com")
				user.FirstName = []byte("encrypted:John")
				user.LastName = []byte("encrypted:Doe")
				repo.Create(context.Background(), user)
			},
			wantErr: false,
		},
		{
			name:   "user not found",
			userID: uuid.New(),
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				// No setup needed - user won't exist
			},
			wantErr:       true,
			expectedError: "user not found",
		},
		{
			name:   "repository error",
			userID: uuid.New(),
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				repo.SetGetByIDError(errors.New("database error"))
			},
			wantErr:       true,
			expectedError: "failed to get user by ID",
		},
		{
			name:   "decryption error",
			userID: uuid.New(),
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				user := NewUser([]byte("encrypted:test@example.com"), []byte("encrypted:John"), []byte("encrypted:Doe"))
				// Store user with encrypted data
				user.Email = []byte("encrypted:test@example.com")
				user.FirstName = []byte("encrypted:John")
				user.LastName = []byte("encrypted:Doe")
				repo.Create(context.Background(), user)
				enc.SetDecryptError(errors.New("decryption failed"))
			},
			wantErr:       true,
			expectedError: "failed to decrypt email",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := NewMockUserRepository()
			encrypter := NewMockEncrypter()
			tt.setupMocks(repo, encrypter)

			service := NewService(repo, encrypter)

			// For successful retrieval and decryption error, use the ID of the created user
			var testID uuid.UUID
			if tt.name == "successful user retrieval" || tt.name == "decryption error" {
				// Get the user from the repository to use its ID
				for id := range repo.users {
					testID = id
					break
				}
			} else {
				testID = tt.userID
			}

			user, err := service.GetUserByID(context.Background(), testID)

			if tt.wantErr {
				if err == nil {
					t.Errorf("GetUserByID() expected error, got nil")
				}
				if tt.expectedError != "" && !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("GetUserByID() error = %v, want to contain %v", err, tt.expectedError)
				}
				return
			}

			if err != nil {
				t.Errorf("GetUserByID() unexpected error = %v", err)
				return
			}

			if user == nil {
				t.Error("GetUserByID() should return a user on success")
				return
			}

			if user.ID != testID {
				t.Errorf("GetUserByID() ID = %v, want %v", user.ID, testID)
			}
		})
	}
}

func TestService_GetUserByEmail(t *testing.T) {
	tests := []struct {
		name          string
		email         string
		setupMocks    func(*MockUserRepository, *MockEncrypter)
		wantErr       bool
		expectedError string
	}{
		{
			name:  "successful user retrieval",
			email: "test@example.com",
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				user := NewUser([]byte("encrypted:test@example.com"), []byte("encrypted:John"), []byte("encrypted:Doe"))
				// Store user with encrypted email that will be searched
				user.Email = []byte("encrypted:test@example.com")
				user.FirstName = []byte("encrypted:John")
				user.LastName = []byte("encrypted:Doe")
				repo.Create(context.Background(), user)
			},
			wantErr: false,
		},
		{
			name:  "invalid email format",
			email: "invalid-email",
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				// No setup needed
			},
			wantErr:       true,
			expectedError: "invalid email format",
		},
		{
			name:  "user not found",
			email: "nonexistent@example.com",
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				// No setup needed - user won't exist
			},
			wantErr:       true,
			expectedError: "user not found",
		},
		{
			name:  "repository error",
			email: "test@example.com",
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				repo.SetGetByEmailError(errors.New("database error"))
			},
			wantErr:       true,
			expectedError: "failed to get user by email",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := NewMockUserRepository()
			encrypter := NewMockEncrypter()
			tt.setupMocks(repo, encrypter)

			service := NewService(repo, encrypter)
			user, err := service.GetUserByEmail(context.Background(), tt.email)

			if tt.wantErr {
				if err == nil {
					t.Errorf("GetUserByEmail() expected error, got nil")
				}
				if tt.expectedError != "" && !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("GetUserByEmail() error = %v, want to contain %v", err, tt.expectedError)
				}
				return
			}

			if err != nil {
				t.Errorf("GetUserByEmail() unexpected error = %v", err)
				return
			}

			if user == nil {
				t.Error("GetUserByEmail() should return a user on success")
				return
			}

			// Service now returns UserResponse with decrypted email
			if user.Email != tt.email {
				t.Errorf("GetUserByEmail() email = %v, want %v", user.Email, tt.email)
			}
		})
	}
}

func TestService_UpdateUser(t *testing.T) {
	existingUser := NewUser([]byte("encrypted:test@example.com"), []byte("encrypted:John"), []byte("encrypted:Doe"))
	existingUser.Version = 1

	tests := []struct {
		name          string
		request       *UpdateUserRequest
		setupMocks    func(*MockUserRepository, *MockEncrypter)
		wantErr       bool
		expectedError string
	}{
		{
			name: "successful user update",
			request: &UpdateUserRequest{
				ID:      existingUser.ID,
				Version: 1,
			},
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				repo.Create(context.Background(), existingUser)
			},
			wantErr: false,
		},
		{
			name:    "nil request",
			request: nil,
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				// No setup needed
			},
			wantErr:       true,
			expectedError: "validation failed",
		},
		{
			name: "empty user ID",
			request: &UpdateUserRequest{
				ID:      uuid.Nil,
				Version: 1,
			},
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				// No setup needed
			},
			wantErr:       true,
			expectedError: "validation failed",
		},
		{
			name: "user not found",
			request: &UpdateUserRequest{
				ID:      uuid.New(),
				Version: 1,
			},
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				// No setup needed - user won't exist
			},
			wantErr:       true,
			expectedError: "user not found",
		},
		{
			name: "version mismatch",
			request: &UpdateUserRequest{
				ID:      existingUser.ID,
				Version: 2, // Wrong version
			},
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				repo.Create(context.Background(), existingUser)
			},
			wantErr:       true,
			expectedError: "user was modified by another process",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := NewMockUserRepository()
			encrypter := NewMockEncrypter()
			tt.setupMocks(repo, encrypter)

			service := NewService(repo, encrypter)
			user, err := service.UpdateUser(context.Background(), tt.request)

			if tt.wantErr {
				if err == nil {
					t.Errorf("UpdateUser() expected error, got nil")
				}
				if tt.expectedError != "" && !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("UpdateUser() error = %v, want to contain %v", err, tt.expectedError)
				}
				return
			}

			if err != nil {
				t.Errorf("UpdateUser() unexpected error = %v", err)
				return
			}

			if user == nil {
				t.Error("UpdateUser() should return a user on success")
				return
			}

			if user.Version != tt.request.Version+1 {
				t.Errorf("UpdateUser() version = %v, want %v", user.Version, tt.request.Version+1)
			}
		})
	}
}

func TestService_DeleteUser(t *testing.T) {
	existingUser := NewUser([]byte("encrypted:test@example.com"), []byte("encrypted:John"), []byte("encrypted:Doe"))

	tests := []struct {
		name          string
		userID        uuid.UUID
		setupMocks    func(*MockUserRepository, *MockEncrypter)
		wantErr       bool
		expectedError string
	}{
		{
			name:   "successful user deletion",
			userID: existingUser.ID,
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				repo.Create(context.Background(), existingUser)
			},
			wantErr: false,
		},
		{
			name:   "repository error",
			userID: existingUser.ID,
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				repo.SetDeleteError(errors.New("database error"))
			},
			wantErr:       true,
			expectedError: "failed to delete user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := NewMockUserRepository()
			encrypter := NewMockEncrypter()
			tt.setupMocks(repo, encrypter)

			service := NewService(repo, encrypter)
			err := service.DeleteUser(context.Background(), tt.userID)

			if tt.wantErr {
				if err == nil {
					t.Errorf("DeleteUser() expected error, got nil")
				}
				if tt.expectedError != "" && !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("DeleteUser() error = %v, want to contain %v", err, tt.expectedError)
				}
				return
			}

			if err != nil {
				t.Errorf("DeleteUser() unexpected error = %v", err)
				return
			}
		})
	}
}

func TestService_ActivateUser(t *testing.T) {
	existingUser := NewUser([]byte("encrypted:test@example.com"), []byte("encrypted:John"), []byte("encrypted:Doe"))
	existingUser.IsActive = false

	tests := []struct {
		name          string
		userID        uuid.UUID
		setupMocks    func(*MockUserRepository, *MockEncrypter)
		wantErr       bool
		expectedError string
	}{
		{
			name:   "successful user activation",
			userID: existingUser.ID,
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				repo.Create(context.Background(), existingUser)
			},
			wantErr: false,
		},
		{
			name:   "user not found",
			userID: uuid.New(),
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				// No setup needed - user won't exist
			},
			wantErr:       true,
			expectedError: "user not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := NewMockUserRepository()
			encrypter := NewMockEncrypter()
			tt.setupMocks(repo, encrypter)

			service := NewService(repo, encrypter)
			err := service.ActivateUser(context.Background(), tt.userID)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ActivateUser() expected error, got nil")
				}
				if tt.expectedError != "" && !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("ActivateUser() error = %v, want to contain %v", err, tt.expectedError)
				}
				return
			}

			if err != nil {
				t.Errorf("ActivateUser() unexpected error = %v", err)
				return
			}
		})
	}
}

func TestService_RecordLogin(t *testing.T) {
	existingUser := NewUser([]byte("encrypted:test@example.com"), []byte("encrypted:John"), []byte("encrypted:Doe"))
	existingUser.IsActive = true

	inactiveUser := NewUser([]byte("encrypted:inactive@example.com"), []byte("encrypted:Jane"), []byte("encrypted:Doe"))
	inactiveUser.IsActive = false

	tests := []struct {
		name          string
		userID        uuid.UUID
		setupMocks    func(*MockUserRepository, *MockEncrypter)
		wantErr       bool
		expectedError string
	}{
		{
			name:   "successful login recording",
			userID: existingUser.ID,
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				repo.Create(context.Background(), existingUser)
			},
			wantErr: false,
		},
		{
			name:   "user not found",
			userID: uuid.New(),
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				// No setup needed - user won't exist
			},
			wantErr:       true,
			expectedError: "user not found",
		},
		{
			name:   "inactive user",
			userID: inactiveUser.ID,
			setupMocks: func(repo *MockUserRepository, enc *MockEncrypter) {
				repo.Create(context.Background(), inactiveUser)
			},
			wantErr:       true,
			expectedError: "user is inactive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := NewMockUserRepository()
			encrypter := NewMockEncrypter()
			tt.setupMocks(repo, encrypter)

			service := NewService(repo, encrypter)
			err := service.RecordLogin(context.Background(), tt.userID)

			if tt.wantErr {
				if err == nil {
					t.Errorf("RecordLogin() expected error, got nil")
				}
				if tt.expectedError != "" && !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("RecordLogin() error = %v, want to contain %v", err, tt.expectedError)
				}
				return
			}

			if err != nil {
				t.Errorf("RecordLogin() unexpected error = %v", err)
				return
			}
		})
	}
}

func TestService_EmailValidation(t *testing.T) {
	service := NewService(NewMockUserRepository(), NewMockEncrypter())

	tests := []struct {
		name     string
		email    string
		expected bool
	}{
		{"valid email", "test@example.com", true},
		{"valid email with subdomain", "user@mail.example.com", true},
		{"valid email with numbers", "user123@example.com", true},
		{"valid email with plus", "user+tag@example.com", true},
		{"valid email with dash", "user-name@example.com", true},
		{"invalid email missing @", "userexample.com", false},
		{"invalid email missing domain", "user@", false},
		{"invalid email missing local", "@example.com", false},
		{"invalid email missing extension", "user@example", false},
		{"invalid email with spaces", "user @example.com", false},
		{"empty email", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.isValidEmail(tt.email)
			if result != tt.expected {
				t.Errorf("isValidEmail(%v) = %v, want %v", tt.email, result, tt.expected)
			}
		})
	}
}
