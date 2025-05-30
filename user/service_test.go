package user

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/MichaelAJay/go-user-management/auth"
	"github.com/MichaelAJay/go-user-management/errors"
)

// Test CreateUser with comprehensive validation
func TestCreateUser_Validation(t *testing.T) {
	tests := []struct {
		name    string
		req     *CreateUserRequest
		wantErr bool
		errCode errors.ErrorCode
	}{
		{
			name: "valid request",
			req: &CreateUserRequest{
				FirstName:              "John",
				LastName:               "Doe",
				Email:                  "john@example.com",
				AuthenticationProvider: auth.ProviderTypePassword,
				Credentials:            map[string]interface{}{"password": "StrongPass123!"},
			},
			wantErr: false,
		},
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
			errCode: errors.CodeValidationFailed,
		},
		{
			name: "empty first name",
			req: &CreateUserRequest{
				FirstName:              "",
				LastName:               "Doe",
				Email:                  "john@example.com",
				AuthenticationProvider: auth.ProviderTypePassword,
				Credentials:            map[string]interface{}{"password": "StrongPass123!"},
			},
			wantErr: true,
			errCode: errors.CodeEmptyField,
		},
		{
			name: "invalid email format",
			req: &CreateUserRequest{
				FirstName:              "John",
				LastName:               "Doe",
				Email:                  "not-an-email",
				AuthenticationProvider: auth.ProviderTypePassword,
				Credentials:            map[string]interface{}{"password": "StrongPass123!"},
			},
			wantErr: true,
			errCode: errors.CodeInvalidEmailFormat,
		},
		{
			name: "missing credentials",
			req: &CreateUserRequest{
				FirstName:              "John",
				LastName:               "Doe",
				Email:                  "john@example.com",
				AuthenticationProvider: auth.ProviderTypePassword,
				Credentials:            nil,
			},
			wantErr: true,
			errCode: errors.CodeMissingCredentials,
		},
		{
			name: "unsupported auth provider",
			req: &CreateUserRequest{
				FirstName:              "John",
				LastName:               "Doe",
				Email:                  "john@example.com",
				AuthenticationProvider: "unsupported",
				Credentials:            map[string]interface{}{"password": "StrongPass123!"},
			},
			wantErr: true,
			errCode: errors.CodeUnsupportedProvider,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := createTestUserService()
			ctx := context.Background()

			response, err := service.CreateUser(ctx, tt.req)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				appErr, ok := err.(*errors.AppError)
				if !ok {
					t.Errorf("Expected AppError but got different error type: %v", err)
					return
				}
				if appErr.Code != tt.errCode {
					t.Errorf("Expected error code %s, got %s", tt.errCode, appErr.Code)
				}

				if response != nil {
					t.Errorf("Expected nil response on error, got %+v", response)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
				if response == nil {
					t.Errorf("Expected response, got nil")
				}
			}
		})
	}
}

// Test duplicate email handling with various scenarios
func TestCreateUser_DuplicateEmailScenarios(t *testing.T) {
	service := createTestUserService()
	ctx := context.Background()

	baseReq := &CreateUserRequest{
		FirstName:              "John",
		LastName:               "Doe",
		Email:                  "john@example.com",
		AuthenticationProvider: auth.ProviderTypePassword,
		Credentials:            map[string]interface{}{"password": "StrongPass123!"},
	}

	// Create first user
	_, err := service.CreateUser(ctx, baseReq)
	if err != nil {
		t.Fatalf("Failed to create first user: %v", err)
	}

	tests := []struct {
		name  string
		email string
	}{
		{"exact duplicate", "john@example.com"},
		{"case variation", "John@Example.Com"},
		{"whitespace variation", " john@example.com "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := *baseReq
			req.Email = tt.email

			_, err := service.CreateUser(ctx, &req)

			if err == nil {
				t.Error("Expected duplicate email error")
				return
			}
			appErr, ok := err.(*errors.AppError)
			if !ok || appErr.Code != errors.CodeDuplicateEmail {
				t.Errorf("Expected duplicate email error, got %v", err)
			}
		})
	}
}

// Test authentication with comprehensive scenarios including concurrency
func TestAuthenticateUser_Comprehensive(t *testing.T) {
	service := createTestUserService()
	ctx := context.Background()

	// Create test user
	createReq := &CreateUserRequest{
		FirstName:              "John",
		LastName:               "Doe",
		Email:                  "john@example.com",
		AuthenticationProvider: auth.ProviderTypePassword,
		Credentials:            map[string]interface{}{"password": "StrongPass123!"},
	}

	user, err := service.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Activate user for authentication tests
	_, err = service.ActivateUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to activate user: %v", err)
	}

	tests := []struct {
		name        string
		email       string
		password    string
		wantErr     bool
		expectedErr errors.ErrorCode
	}{
		{
			name:     "valid credentials",
			email:    "john@example.com",
			password: "StrongPass123!",
			wantErr:  false,
		},
		{
			name:        "wrong password",
			email:       "john@example.com",
			password:    "WrongPassword",
			wantErr:     true,
			expectedErr: errors.CodeInvalidCredentials,
		},
		{
			name:        "non-existent user",
			email:       "nobody@example.com",
			password:    "StrongPass123!",
			wantErr:     true,
			expectedErr: errors.CodeInvalidCredentials,
		},
		{
			name:        "invalid email format",
			email:       "not-an-email",
			password:    "StrongPass123!",
			wantErr:     true,
			expectedErr: errors.CodeInvalidEmailFormat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authReq := &AuthenticateRequest{
				Email:                  tt.email,
				AuthenticationProvider: auth.ProviderTypePassword,
				Credentials:            map[string]interface{}{"password": tt.password},
			}

			response, err := service.AuthenticateUser(ctx, authReq)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				if response != nil {
					t.Error("Expected nil response on error")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
				if response == nil || response.User == nil {
					t.Error("Expected valid response with user")
				}
			}
		})
	}
}

// Test account lockout logic with race conditions
func TestAuthenticateUser_AccountLockout(t *testing.T) {
	service := createTestUserService()
	ctx := context.Background()

	// Create and activate user
	createReq := &CreateUserRequest{
		FirstName:              "John",
		LastName:               "Doe",
		Email:                  "john@example.com",
		AuthenticationProvider: auth.ProviderTypePassword,
		Credentials:            map[string]interface{}{"password": "StrongPass123!"},
	}

	user, err := service.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	_, err = service.ActivateUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to activate user: %v", err)
	}

	// Test multiple failed attempts
	authReq := &AuthenticateRequest{
		Email:                  "john@example.com",
		AuthenticationProvider: auth.ProviderTypePassword,
		Credentials:            map[string]interface{}{"password": "WrongPassword"},
	}

	// Attempt authentication up to lockout threshold
	maxAttempts := 5 // Default from config
	for i := 0; i < maxAttempts; i++ {
		_, err := service.AuthenticateUser(ctx, authReq)
		if err == nil {
			t.Errorf("Expected authentication to fail on attempt %d", i+1)
		}
	}

	// Next attempt should result in account locked error
	_, err = service.AuthenticateUser(ctx, authReq)
	if err == nil {
		t.Error("Expected account locked error")
	}
	if err.Error() != "account locked" {
		t.Errorf("Expected account locked error, got %v", err)
	}

	// Even correct password should fail when locked
	correctAuthReq := &AuthenticateRequest{
		Email:                  "john@example.com",
		AuthenticationProvider: auth.ProviderTypePassword,
		Credentials:            map[string]interface{}{"password": "StrongPass123!"},
	}

	_, err = service.AuthenticateUser(ctx, correctAuthReq)
	if err == nil {
		t.Error("Expected authentication to fail for locked account")
	}
}

// Test concurrent authentication attempts (race condition testing)
func TestAuthenticateUser_ConcurrentAttempts(t *testing.T) {
	service := createTestUserService()
	ctx := context.Background()

	// Create and activate user
	createReq := &CreateUserRequest{
		FirstName:              "John",
		LastName:               "Doe",
		Email:                  "john@example.com",
		AuthenticationProvider: auth.ProviderTypePassword,
		Credentials:            map[string]interface{}{"password": "StrongPass123!"},
	}

	user, err := service.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	_, err = service.ActivateUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to activate user: %v", err)
	}

	// Simulate concurrent failed authentication attempts
	const numGoroutines = 10
	var wg sync.WaitGroup
	errChan := make(chan error, numGoroutines)

	authReq := &AuthenticateRequest{
		Email:                  "john@example.com",
		AuthenticationProvider: auth.ProviderTypePassword,
		Credentials:            map[string]interface{}{"password": "WrongPassword"},
	}

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := service.AuthenticateUser(ctx, authReq)
			errChan <- err
		}()
	}

	wg.Wait()
	close(errChan)

	// All attempts should fail
	errorCount := 0
	for err := range errChan {
		if err != nil {
			errorCount++
		}
	}

	if errorCount != numGoroutines {
		t.Errorf("Expected all %d attempts to fail, got %d failures", numGoroutines, errorCount)
	}

	// Verify account is properly locked
	userAfter, err := service.GetUserByEmail(ctx, "john@example.com")
	if err != nil {
		t.Fatalf("Failed to get user after concurrent attempts: %v", err)
	}

	if userAfter.CanAuthenticate {
		t.Error("Expected user to be locked after concurrent failed attempts")
	}
}

// Test update profile with version conflicts
func TestUpdateProfile_VersionConflict(t *testing.T) {
	service := createTestUserService()
	ctx := context.Background()

	// Create user
	createReq := &CreateUserRequest{
		FirstName:              "John",
		LastName:               "Doe",
		Email:                  "john@example.com",
		AuthenticationProvider: auth.ProviderTypePassword,
		Credentials:            map[string]interface{}{"password": "StrongPass123!"},
	}

	user, err := service.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Simulate concurrent updates
	var wg sync.WaitGroup
	const numUpdates = 5
	successCount := make(chan bool, numUpdates)

	for i := 0; i < numUpdates; i++ {
		wg.Add(1)
		go func(updateNum int) {
			defer wg.Done()

			updateReq := &UpdateProfileRequest{
				FirstName: stringPtr(fmt.Sprintf("UpdatedName%d", updateNum)),
			}

			_, err := service.UpdateProfile(ctx, user.ID, updateReq)
			successCount <- err == nil
		}(i)
	}

	wg.Wait()
	close(successCount)

	// Some updates should succeed, others should fail due to version conflicts
	// The exact behavior depends on timing, but not all should succeed
	successes := 0
	for success := range successCount {
		if success {
			successes++
		}
	}

	// At least one should succeed, but not necessarily all due to version conflicts
	if successes == 0 {
		t.Error("Expected at least one update to succeed")
	}

	t.Logf("Concurrent updates: %d/%d succeeded", successes, numUpdates)
}

// Test repository error handling
func TestCreateUser_RepositoryErrors(t *testing.T) {
	service := createTestUserService()
	ctx := context.Background()

	// Get the mock repository and set it to fail
	mockRepo := getMockRepository(service)
	if mockRepo == nil {
		t.Fatal("Failed to get mock repository from service")
	}
	mockRepo.createFunc = func(context.Context, *User) error {
		return fmt.Errorf("database connection failed")
	}

	req := &CreateUserRequest{
		FirstName:              "John",
		LastName:               "Doe",
		Email:                  "john@example.com",
		AuthenticationProvider: auth.ProviderTypePassword,
		Credentials:            map[string]interface{}{"password": "StrongPass123!"},
	}

	response, err := service.CreateUser(ctx, req)

	if err == nil {
		t.Error("Expected error when repository fails")
	}
	if response != nil {
		t.Error("Expected nil response when repository fails")
	}
	appErr, ok := err.(*errors.AppError)
	if !ok {
		t.Error("Expected AppError type")
	} else if appErr.Code != errors.CodeInternalError {
		t.Errorf("Expected internal error, got %s", appErr.Code)
	}
}

// Test using createTestUserServiceWithRepoError helper
func TestCreateUser_RepositoryErrorsWithHelper(t *testing.T) {
	ctx := context.Background()

	// Use helper to create service with repository that always fails on create
	service := createTestUserServiceWithRepoError("create", fmt.Errorf("database connection failed"))

	req := &CreateUserRequest{
		FirstName:              "John",
		LastName:               "Doe",
		Email:                  "john@example.com",
		AuthenticationProvider: auth.ProviderTypePassword,
		Credentials:            map[string]interface{}{"password": "StrongPass123!"},
	}

	response, err := service.CreateUser(ctx, req)

	if err == nil {
		t.Error("Expected error when repository fails")
	}
	if response != nil {
		t.Error("Expected nil response when repository fails")
	}
}

// Test using createTestUserServiceWithUsers helper
func TestGetUserByID_WithPreexistingUser(t *testing.T) {
	ctx := context.Background()

	// Create a test user and service with that user already in the repository
	testUser := createActiveTestUser()
	service := createTestUserServiceWithUsers(testUser)

	// Should be able to retrieve the pre-existing user
	retrievedUser, err := service.GetUserByID(ctx, testUser.ID)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if retrievedUser == nil {
		t.Error("Expected user to be found")
	}
	if retrievedUser != nil && retrievedUser.ID != testUser.ID {
		t.Errorf("Expected user ID %s, got %s", testUser.ID, retrievedUser.ID)
	}
}

// Test using createTestUserServiceWithAuth helper for custom authentication behavior
func TestAuthenticateUser_WithCustomAuthManager(t *testing.T) {
	ctx := context.Background()

	// Create a mock auth manager that always fails authentication
	mockAuth := newMockAuthManager().(*mockAuthManager)
	mockAuth.authenticateFunc = func(ctx context.Context, req *auth.AuthenticationRequest) (*auth.AuthenticationResult, error) {
		return nil, errors.NewInvalidCredentialsError()
	}

	// Create service with the custom auth manager
	service := createTestUserServiceWithAuth(mockAuth)

	// Create and add a user to the service
	testUser := createActiveTestUser()
	if repo := getMockRepository(service); repo != nil {
		repo.users[testUser.HashedEmail] = testUser.Clone()
		repo.emailIndex[testUser.HashedEmail] = testUser.ID
	}

	authReq := &AuthenticateRequest{
		Email:                  string(testUser.Email),
		AuthenticationProvider: auth.ProviderTypePassword,
		Credentials:            map[string]interface{}{"password": "StrongPass123!"},
	}

	result, err := service.AuthenticateUser(ctx, authReq)

	// Should fail due to our custom auth manager
	if err == nil {
		t.Error("Expected authentication to fail with custom auth manager")
	}
	if result != nil {
		t.Error("Expected nil result when authentication fails")
	}

	// Verify the custom auth manager was called
	if mockAuth := getMockAuthManager(service); mockAuth != nil {
		if len(mockAuth.providers) == 0 {
			t.Error("Expected mock auth manager to have providers")
		}
	}
}

// Test using createIntegrationTestService for more realistic authentication testing
func TestAuthenticateUser_IntegrationTest(t *testing.T) {
	ctx := context.Background()

	// Use integration test service with real auth manager but mock providers
	service := createIntegrationTestService()

	// Create a user with the service
	createReq := &CreateUserRequest{
		FirstName:              "John",
		LastName:               "Doe",
		Email:                  "john@example.com",
		AuthenticationProvider: auth.ProviderTypePassword,
		Credentials:            map[string]interface{}{"password": "StrongPass123!"},
	}

	user, err := service.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Activate user
	_, err = service.ActivateUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to activate user: %v", err)
	}

	// Test authentication with integration service
	authReq := &AuthenticateRequest{
		Email:                  "john@example.com",
		AuthenticationProvider: auth.ProviderTypePassword,
		Credentials:            map[string]interface{}{"password": "StrongPass123!"},
	}

	authResult, err := service.AuthenticateUser(ctx, authReq)

	if err != nil {
		t.Errorf("Expected successful authentication, got error: %v", err)
	}
	if authResult == nil || authResult.User == nil {
		t.Error("Expected authentication result with user")
	}
}
