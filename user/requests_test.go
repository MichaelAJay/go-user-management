package user

import (
	"strings"
	"testing"
	"time"

	"github.com/MichaelAJay/go-user-management/auth"
)

func TestUpdateProfileRequest_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		req      *UpdateProfileRequest
		expected bool
	}{
		{
			name:     "EmptyRequest",
			req:      &UpdateProfileRequest{},
			expected: true,
		},
		{
			name: "WithFirstName",
			req: &UpdateProfileRequest{
				FirstName: stringPtr("John"),
			},
			expected: false,
		},
		{
			name: "WithLastName",
			req: &UpdateProfileRequest{
				LastName: stringPtr("Doe"),
			},
			expected: false,
		},
		{
			name: "WithEmail",
			req: &UpdateProfileRequest{
				Email: stringPtr("john.doe@example.com"),
			},
			expected: false,
		},
		{
			name: "WithAllFields",
			req: &UpdateProfileRequest{
				FirstName: stringPtr("John"),
				LastName:  stringPtr("Doe"),
				Email:     stringPtr("john.doe@example.com"),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.req.IsEmpty(); got != tt.expected {
				t.Errorf("UpdateProfileRequest.IsEmpty() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestUpdateProfileRequest_HasEmailChange(t *testing.T) {
	tests := []struct {
		name     string
		req      *UpdateProfileRequest
		expected bool
	}{
		{
			name:     "NoEmail",
			req:      &UpdateProfileRequest{},
			expected: false,
		},
		{
			name: "WithEmail",
			req: &UpdateProfileRequest{
				Email: stringPtr("john.doe@example.com"),
			},
			expected: true,
		},
		{
			name: "WithOtherFields",
			req: &UpdateProfileRequest{
				FirstName: stringPtr("John"),
				LastName:  stringPtr("Doe"),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.req.HasEmailChange(); got != tt.expected {
				t.Errorf("UpdateProfileRequest.HasEmailChange() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestUser_ToUserResponse(t *testing.T) {
	user := createActiveTestUser()
	user.LastLoginAt = timePtr(time.Now())

	// Add multiple authentication providers
	user.AddAuthenticationProvider(auth.ProviderTypeOAuth, map[string]interface{}{"token": "oauth_token"})

	response := user.ToUserResponse(nil)

	// Verify basic fields
	if response.ID != user.ID {
		t.Errorf("Expected ID %s, got %s", user.ID, response.ID)
	}
	if response.Status != user.Status {
		t.Errorf("Expected Status %s, got %s", user.Status, response.Status)
	}
	if response.Version != user.Version {
		t.Errorf("Expected Version %d, got %d", user.Version, response.Version)
	}
	if response.PrimaryAuthProvider != user.PrimaryAuthProvider {
		t.Errorf("Expected PrimaryAuthProvider %s, got %s", user.PrimaryAuthProvider, response.PrimaryAuthProvider)
	}

	// Verify computed fields
	if !response.EmailVerified {
		t.Error("Expected EmailVerified to be true for active user")
	}
	if response.AccountLocked {
		t.Error("Expected AccountLocked to be false for unlocked user")
	}
	if !response.CanAuthenticate {
		t.Error("Expected CanAuthenticate to be true for active user")
	}

	// Verify available providers
	if len(response.AvailableAuthProviders) != 2 {
		t.Errorf("Expected 2 available providers, got %d", len(response.AvailableAuthProviders))
	}

	// Verify display name is set
	if response.DisplayName == "" {
		t.Error("Expected DisplayName to be set")
	}

	// Verify timestamps
	if !response.CreatedAt.Equal(user.CreatedAt) {
		t.Error("Expected CreatedAt to match")
	}
	if !response.UpdatedAt.Equal(user.UpdatedAt) {
		t.Error("Expected UpdatedAt to match")
	}
	if response.LastLoginAt == nil || !response.LastLoginAt.Equal(*user.LastLoginAt) {
		t.Error("Expected LastLoginAt to match")
	}
}

func TestUser_ToUserResponse_PendingVerification(t *testing.T) {
	user := createPendingTestUser()

	response := user.ToUserResponse(nil)

	if response.EmailVerified {
		t.Error("Expected EmailVerified to be false for pending verification user")
	}
}

func TestUser_ToUserResponse_Locked(t *testing.T) {
	user := createActiveTestUser()
	user.LockedUntil = timePtr(time.Now().Add(time.Hour))

	response := user.ToUserResponse(nil)

	if !response.AccountLocked {
		t.Error("Expected AccountLocked to be true for locked user")
	}
	if response.CanAuthenticate {
		t.Error("Expected CanAuthenticate to be false for locked user")
	}
}

func TestUser_ToDetailedUserResponse(t *testing.T) {
	user := createTestUser()
	user.LoginAttempts = 3
	user.LockedUntil = timePtr(time.Now().Add(time.Hour))
	user.HashedEmail = "abcdef1234567890"

	response := user.ToDetailedUserResponse(nil)

	// Verify it includes all UserResponse fields
	if response.ID != user.ID {
		t.Errorf("Expected ID %s, got %s", user.ID, response.ID)
	}
	if response.Status != user.Status {
		t.Errorf("Expected Status %s, got %s", user.Status, response.Status)
	}

	// Verify additional detailed fields
	if response.LoginAttempts != user.LoginAttempts {
		t.Errorf("Expected LoginAttempts %d, got %d", user.LoginAttempts, response.LoginAttempts)
	}
	if response.LockedUntil == nil || !response.LockedUntil.Equal(*user.LockedUntil) {
		t.Error("Expected LockedUntil to match")
	}

	// Verify hashed email preview
	expectedPreview := "abcdef12..."
	if response.HashedEmailPreview != expectedPreview {
		t.Errorf("Expected HashedEmailPreview %s, got %s", expectedPreview, response.HashedEmailPreview)
	}
}

func TestUser_ToDetailedUserResponse_ShortHashedEmail(t *testing.T) {
	user := createTestUser()
	user.HashedEmail = "abc123"

	response := user.ToDetailedUserResponse(nil)

	// For short hashed emails, should return the full value
	if response.HashedEmailPreview != user.HashedEmail {
		t.Errorf("Expected HashedEmailPreview %s, got %s", user.HashedEmail, response.HashedEmailPreview)
	}
}

func TestCreateUserRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		req     CreateUserRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid request",
			req: CreateUserRequest{
				FirstName:              "John",
				LastName:               "Doe",
				Email:                  "john.doe@example.com",
				Credentials:            map[string]interface{}{"password": "securepassword123"},
				AuthenticationProvider: auth.ProviderTypePassword,
			},
			wantErr: false,
		},
		{
			name: "missing first name",
			req: CreateUserRequest{
				LastName:               "Doe",
				Email:                  "john.doe@example.com",
				Credentials:            map[string]interface{}{"password": "securepassword123"},
				AuthenticationProvider: auth.ProviderTypePassword,
			},
			wantErr: true,
			errMsg:  "first name is required",
		},
		{
			name: "missing last name",
			req: CreateUserRequest{
				FirstName:              "John",
				Email:                  "john.doe@example.com",
				Credentials:            map[string]interface{}{"password": "securepassword123"},
				AuthenticationProvider: auth.ProviderTypePassword,
			},
			wantErr: true,
			errMsg:  "last name is required",
		},
		{
			name: "invalid email",
			req: CreateUserRequest{
				FirstName:              "John",
				LastName:               "Doe",
				Email:                  "invalid-email",
				Credentials:            map[string]interface{}{"password": "securepassword123"},
				AuthenticationProvider: auth.ProviderTypePassword,
			},
			wantErr: true,
			errMsg:  "invalid email format",
		},
		{
			name: "missing credentials",
			req: CreateUserRequest{
				FirstName:              "John",
				LastName:               "Doe",
				Email:                  "john.doe@example.com",
				AuthenticationProvider: auth.ProviderTypePassword,
			},
			wantErr: true,
			errMsg:  "credentials are required",
		},
		{
			name: "missing auth provider",
			req: CreateUserRequest{
				FirstName:   "John",
				LastName:    "Doe",
				Email:       "john.doe@example.com",
				Credentials: map[string]interface{}{"password": "securepassword123"},
			},
			wantErr: true,
			errMsg:  "authentication provider is required",
		},
		{
			name: "first name too long",
			req: CreateUserRequest{
				FirstName:              strings.Repeat("a", 101),
				LastName:               "Doe",
				Email:                  "john.doe@example.com",
				Credentials:            map[string]interface{}{"password": "securepassword123"},
				AuthenticationProvider: auth.ProviderTypePassword,
			},
			wantErr: true,
			errMsg:  "first name must be 100 characters or less",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateUserRequest.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("CreateUserRequest.Validate() error = %v, expected to contain %v", err, tt.errMsg)
				}
			}
		})
	}
}

func TestUpdateProfileRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		req     UpdateProfileRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid request with all fields",
			req: UpdateProfileRequest{
				FirstName: stringPtr("John"),
				LastName:  stringPtr("Doe"),
				Email:     stringPtr("john.doe@example.com"),
			},
			wantErr: false,
		},
		{
			name:    "empty request",
			req:     UpdateProfileRequest{},
			wantErr: false,
		},
		{
			name: "invalid email",
			req: UpdateProfileRequest{
				Email: stringPtr("invalid-email"),
			},
			wantErr: true,
			errMsg:  "invalid email format",
		},
		{
			name: "first name too long",
			req: UpdateProfileRequest{
				FirstName: stringPtr(strings.Repeat("a", 101)),
			},
			wantErr: true,
			errMsg:  "first name must be 100 characters or less",
		},
		{
			name: "empty first name",
			req: UpdateProfileRequest{
				FirstName: stringPtr(""),
			},
			wantErr: true,
			errMsg:  "first name is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("UpdateProfileRequest.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("UpdateProfileRequest.Validate() error = %v, expected to contain %v", err, tt.errMsg)
				}
			}
		})
	}
}

func TestUpdateCredentialsRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		req     UpdateCredentialsRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid request",
			req: UpdateCredentialsRequest{
				CurrentCredentials:     map[string]interface{}{"password": "oldpassword"},
				NewCredentials:         map[string]interface{}{"password": "newpassword"},
				AuthenticationProvider: auth.ProviderTypePassword,
			},
			wantErr: false,
		},
		{
			name: "missing current credentials",
			req: UpdateCredentialsRequest{
				NewCredentials:         map[string]interface{}{"password": "newpassword"},
				AuthenticationProvider: auth.ProviderTypePassword,
			},
			wantErr: true,
			errMsg:  "current credentials are required",
		},
		{
			name: "missing new credentials",
			req: UpdateCredentialsRequest{
				CurrentCredentials:     map[string]interface{}{"password": "oldpassword"},
				AuthenticationProvider: auth.ProviderTypePassword,
			},
			wantErr: true,
			errMsg:  "new credentials are required",
		},
		{
			name: "missing auth provider",
			req: UpdateCredentialsRequest{
				CurrentCredentials: map[string]interface{}{"password": "oldpassword"},
				NewCredentials:     map[string]interface{}{"password": "newpassword"},
			},
			wantErr: true,
			errMsg:  "authentication provider is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("UpdateCredentialsRequest.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("UpdateCredentialsRequest.Validate() error = %v, expected to contain %v", err, tt.errMsg)
				}
			}
		})
	}
}

func TestAuthenticateRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		req     AuthenticateRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid request",
			req: AuthenticateRequest{
				Email:                  "john.doe@example.com",
				Credentials:            map[string]interface{}{"password": "password123"},
				AuthenticationProvider: auth.ProviderTypePassword,
			},
			wantErr: false,
		},
		{
			name: "invalid email",
			req: AuthenticateRequest{
				Email:                  "invalid-email",
				Credentials:            map[string]interface{}{"password": "password123"},
				AuthenticationProvider: auth.ProviderTypePassword,
			},
			wantErr: true,
			errMsg:  "invalid email format",
		},
		{
			name: "missing credentials",
			req: AuthenticateRequest{
				Email:                  "john.doe@example.com",
				AuthenticationProvider: auth.ProviderTypePassword,
			},
			wantErr: true,
			errMsg:  "credentials are required",
		},
		{
			name: "missing auth provider",
			req: AuthenticateRequest{
				Email:       "john.doe@example.com",
				Credentials: map[string]interface{}{"password": "password123"},
			},
			wantErr: true,
			errMsg:  "authentication provider is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthenticateRequest.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("AuthenticateRequest.Validate() error = %v, expected to contain %v", err, tt.errMsg)
				}
			}
		})
	}
}

func TestListUsersRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		req     ListUsersRequest
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid request",
			req:     ListUsersRequest{Offset: 0, Limit: 50, Status: "active"},
			wantErr: false,
		},
		{
			name:    "valid request without status",
			req:     ListUsersRequest{Offset: 0, Limit: 50},
			wantErr: false,
		},
		{
			name:    "negative offset",
			req:     ListUsersRequest{Offset: -1, Limit: 50},
			wantErr: true,
			errMsg:  "offset must be non-negative",
		},
		{
			name:    "zero limit",
			req:     ListUsersRequest{Offset: 0, Limit: 0},
			wantErr: true,
			errMsg:  "limit must be positive",
		},
		{
			name:    "limit too high",
			req:     ListUsersRequest{Offset: 0, Limit: 1001},
			wantErr: true,
			errMsg:  "limit cannot exceed 1000",
		},
		{
			name:    "invalid status",
			req:     ListUsersRequest{Offset: 0, Limit: 50, Status: "invalid"},
			wantErr: true,
			errMsg:  "invalid status",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("ListUsersRequest.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ListUsersRequest.Validate() error = %v, expected to contain %v", err, tt.errMsg)
				}
			}
		})
	}
}

func TestListUsersResponse_Structure(t *testing.T) {
	users := []*UserResponse{
		createTestUser().ToUserResponse(nil),
		createTestUser().ToUserResponse(nil),
	}

	response := &ListUsersResponse{
		Users:      users,
		TotalCount: 100,
		Offset:     0,
		Limit:      50,
		HasMore:    true,
	}

	if len(response.Users) != 2 {
		t.Errorf("Expected 2 users, got %d", len(response.Users))
	}
	if response.TotalCount != 100 {
		t.Errorf("Expected TotalCount 100, got %d", response.TotalCount)
	}
	if response.Offset != 0 {
		t.Errorf("Expected Offset 0, got %d", response.Offset)
	}
	if response.Limit != 50 {
		t.Errorf("Expected Limit 50, got %d", response.Limit)
	}
	if !response.HasMore {
		t.Error("Expected HasMore to be true")
	}
}

func TestAuthenticationResponse_Structure(t *testing.T) {
	user := createTestUser()
	authResult := &auth.AuthenticationResult{
		UserID:       user.ID,
		ProviderType: auth.ProviderTypePassword,
		SessionData:  map[string]interface{}{"auth_time": time.Now()},
	}

	response := &AuthenticationResponse{
		User:       user.ToUserResponse(nil),
		AuthResult: authResult,
		Message:    "Authentication successful",
	}

	if response.User == nil {
		t.Error("Expected User to be set")
	}
	if response.AuthResult == nil {
		t.Error("Expected AuthResult to be set")
	}
	if response.Message == "" {
		t.Error("Expected Message to be set")
	}
	if response.User.ID != user.ID {
		t.Error("Expected User ID to match")
	}
	if response.AuthResult.UserID != user.ID {
		t.Error("Expected AuthResult UserID to match")
	}
}

func TestSessionData_Structure(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour)
	sessionData := &SessionData{
		Token:     "session_token_123",
		ExpiresAt: expiresAt,
	}

	if sessionData.Token == "" {
		t.Error("Expected Token to be set")
	}
	if sessionData.ExpiresAt.IsZero() {
		t.Error("Expected ExpiresAt to be set")
	}
	if !sessionData.ExpiresAt.Equal(expiresAt) {
		t.Error("Expected ExpiresAt to match")
	}
}

func TestPasswordResetRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		req     PasswordResetRequest
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid request",
			req:     PasswordResetRequest{Email: "john.doe@example.com"},
			wantErr: false,
		},
		{
			name:    "invalid email",
			req:     PasswordResetRequest{Email: "invalid-email"},
			wantErr: true,
			errMsg:  "invalid email format",
		},
		{
			name:    "missing email",
			req:     PasswordResetRequest{},
			wantErr: true,
			errMsg:  "email is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("PasswordResetRequest.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("PasswordResetRequest.Validate() error = %v, expected to contain %v", err, tt.errMsg)
				}
			}
		})
	}
}

func TestCompletePasswordResetRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		req     CompletePasswordResetRequest
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid request",
			req:     CompletePasswordResetRequest{Token: "reset_token_123", NewPassword: "newpassword123"},
			wantErr: false,
		},
		{
			name:    "missing token",
			req:     CompletePasswordResetRequest{NewPassword: "newpassword123"},
			wantErr: true,
			errMsg:  "token is required",
		},
		{
			name:    "password too short",
			req:     CompletePasswordResetRequest{Token: "reset_token_123", NewPassword: "short"},
			wantErr: true,
			errMsg:  "password must be at least 8 characters long",
		},
		{
			name:    "password too long",
			req:     CompletePasswordResetRequest{Token: "reset_token_123", NewPassword: strings.Repeat("a", 129)},
			wantErr: true,
			errMsg:  "password must be 128 characters or less",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("CompletePasswordResetRequest.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("CompletePasswordResetRequest.Validate() error = %v, expected to contain %v", err, tt.errMsg)
				}
			}
		})
	}
}

func TestVerifyEmailRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		req     VerifyEmailRequest
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid request",
			req:     VerifyEmailRequest{Token: "verification_token_123"},
			wantErr: false,
		},
		{
			name:    "missing token",
			req:     VerifyEmailRequest{},
			wantErr: true,
			errMsg:  "token is required",
		},
		{
			name:    "empty token",
			req:     VerifyEmailRequest{Token: "   "},
			wantErr: true,
			errMsg:  "token is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyEmailRequest.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("VerifyEmailRequest.Validate() error = %v, expected to contain %v", err, tt.errMsg)
				}
			}
		})
	}
}

func TestResendVerificationRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		req     ResendVerificationRequest
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid request",
			req:     ResendVerificationRequest{Email: "john.doe@example.com"},
			wantErr: false,
		},
		{
			name:    "invalid email",
			req:     ResendVerificationRequest{Email: "invalid-email"},
			wantErr: true,
			errMsg:  "invalid email format",
		},
		{
			name:    "missing email",
			req:     ResendVerificationRequest{},
			wantErr: true,
			errMsg:  "email is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("ResendVerificationRequest.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ResendVerificationRequest.Validate() error = %v, expected to contain %v", err, tt.errMsg)
				}
			}
		})
	}
}

func TestUserStatsResponse_Structure(t *testing.T) {
	stats := &UserStats{
		TotalUsers:               1000,
		ActiveUsers:              800,
		PendingVerificationUsers: 150,
		SuspendedUsers:           30,
		LockedUsers:              15,
		DeactivatedUsers:         5,
		UsersCreatedLast24h:      10,
		UsersCreatedLast7d:       50,
		UsersCreatedLast30d:      200,
	}

	updatedAt := time.Now()
	response := &UserStatsResponse{
		Stats:     stats,
		UpdatedAt: updatedAt,
	}

	if response.Stats == nil {
		t.Error("Expected Stats to be set")
	}
	if response.UpdatedAt.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}
	if response.Stats.TotalUsers != 1000 {
		t.Errorf("Expected TotalUsers 1000, got %d", response.Stats.TotalUsers)
	}
	if response.Stats.ActiveUsers != 800 {
		t.Errorf("Expected ActiveUsers 800, got %d", response.Stats.ActiveUsers)
	}
}
