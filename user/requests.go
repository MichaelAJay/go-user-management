package user

import (
	"time"

	"github.com/MichaelAJay/go-encrypter"
	"github.com/MichaelAJay/go-user-management/auth"
)

// CreateUserRequest represents the request to create a new user.
// This DTO ensures only the necessary fields are exposed for user creation.
type CreateUserRequest struct {
	FirstName              string            `json:"first_name" validate:"required,min=1,max=100"`
	LastName               string            `json:"last_name" validate:"required,min=1,max=100"`
	Email                  string            `json:"email" validate:"required,email,max=255"`
	Credentials            interface{}       `json:"credentials" validate:"required"`
	AuthenticationProvider auth.ProviderType `json:"authentication_provider" validate:"required"`
}

// UpdateProfileRequest represents the request to update user profile information.
// Only the fields that can be updated are included.
type UpdateProfileRequest struct {
	FirstName *string `json:"first_name,omitempty" validate:"omitempty,min=1,max=100"`
	LastName  *string `json:"last_name,omitempty" validate:"omitempty,min=1,max=100"`
	Email     *string `json:"email,omitempty" validate:"omitempty,email,max=255"`
}

// UpdateCredentialsRequest represents the request to update a user's authentication credentials.
type UpdateCredentialsRequest struct {
	CurrentCredentials     interface{}       `json:"current_credentials" validate:"required"`
	NewCredentials         interface{}       `json:"new_credentials" validate:"required"`
	AuthenticationProvider auth.ProviderType `json:"authentication_provider" validate:"required"`
}

// AuthenticateRequest represents the request to authenticate a user.
type AuthenticateRequest struct {
	Email                  string            `json:"email" validate:"required,email"`
	Credentials            interface{}       `json:"credentials" validate:"required"`
	AuthenticationProvider auth.ProviderType `json:"authentication_provider" validate:"required"`
}

// UserResponse represents a safe user response that excludes sensitive information.
// This is returned by API endpoints and excludes encrypted PII and internal fields.
type UserResponse struct {
	ID                     string              `json:"id"`
	Status                 UserStatus          `json:"status"`
	CreatedAt              time.Time           `json:"created_at"`
	UpdatedAt              time.Time           `json:"updated_at"`
	LastLoginAt            *time.Time          `json:"last_login_at,omitempty"`
	Version                int64               `json:"version"`
	DisplayName            string              `json:"display_name,omitempty"`
	EmailVerified          bool                `json:"email_verified"`
	AccountLocked          bool                `json:"account_locked"`
	CanAuthenticate        bool                `json:"can_authenticate"`
	PrimaryAuthProvider    auth.ProviderType   `json:"primary_auth_provider"`
	AvailableAuthProviders []auth.ProviderType `json:"available_auth_providers"`
}

// DetailedUserResponse represents a more detailed user response for admin operations.
// This includes additional metadata that might be useful for administrative purposes.
type DetailedUserResponse struct {
	UserResponse
	LoginAttempts      int        `json:"login_attempts"`
	LockedUntil        *time.Time `json:"locked_until,omitempty"`
	HashedEmailPreview string     `json:"hashed_email_preview,omitempty"` // First 8 chars for debugging
}

// AuthenticationResponse represents the response after successful authentication.
type AuthenticationResponse struct {
	User        *UserResponse              `json:"user"`
	SessionData *SessionData               `json:"session,omitempty"`
	AuthResult  *auth.AuthenticationResult `json:"auth_result,omitempty"`
	Message     string                     `json:"message"`
}

// SessionData represents minimal session information returned to the client.
// The actual session management is handled by the session package.
type SessionData struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ListUsersRequest represents the request parameters for listing users.
type ListUsersRequest struct {
	Offset int    `json:"offset" validate:"min=0"`
	Limit  int    `json:"limit" validate:"min=1,max=1000"`
	Status string `json:"status,omitempty" validate:"omitempty,oneof=active suspended pending_verification locked deactivated"`
}

// ListUsersResponse represents the response for listing users with pagination.
type ListUsersResponse struct {
	Users      []*UserResponse `json:"users"`
	TotalCount int64           `json:"total_count"`
	Offset     int             `json:"offset"`
	Limit      int             `json:"limit"`
	HasMore    bool            `json:"has_more"`
}

// PasswordResetRequest represents the request to initiate a password reset.
type PasswordResetRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// CompletePasswordResetRequest represents the request to complete a password reset.
type CompletePasswordResetRequest struct {
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8,max=128"`
}

// VerifyEmailRequest represents the request to verify an email address.
type VerifyEmailRequest struct {
	Token string `json:"token" validate:"required"`
}

// ResendVerificationRequest represents the request to resend email verification.
type ResendVerificationRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// UserStatsResponse represents the response for user statistics.
type UserStatsResponse struct {
	Stats     *UserStats `json:"stats"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// toUserResponse converts a User entity to a UserResponse DTO.
// This method excludes sensitive information and provides computed fields.
func (u *User) ToUserResponse(enc encrypter.Encrypter) *UserResponse {
	// Get available authentication providers
	availableProviders := make([]auth.ProviderType, 0, len(u.AuthenticationData))
	for providerType := range u.AuthenticationData {
		availableProviders = append(availableProviders, providerType)
	}

	return &UserResponse{
		ID:                     u.ID,
		Status:                 u.Status,
		CreatedAt:              u.CreatedAt,
		UpdatedAt:              u.UpdatedAt,
		LastLoginAt:            u.LastLoginAt,
		Version:                u.Version,
		DisplayName:            u.GetDisplayName(enc),
		EmailVerified:          u.Status != UserStatusPendingVerification,
		AccountLocked:          u.IsLocked(),
		CanAuthenticate:        u.CanAuthenticate(),
		PrimaryAuthProvider:    u.PrimaryAuthProvider,
		AvailableAuthProviders: availableProviders,
	}
}

// ToDetailedUserResponse converts a User entity to a DetailedUserResponse DTO.
// This method includes additional metadata for administrative operations.
func (u *User) ToDetailedUserResponse(enc encrypter.Encrypter) *DetailedUserResponse {
	response := &DetailedUserResponse{
		UserResponse:  *u.ToUserResponse(enc),
		LoginAttempts: u.LoginAttempts,
		LockedUntil:   u.LockedUntil,
	}

	// Add a preview of the hashed email for debugging (first 8 characters)
	if len(u.HashedEmail) >= 8 {
		response.HashedEmailPreview = u.HashedEmail[:8] + "..."
	} else {
		response.HashedEmailPreview = u.HashedEmail
	}

	return response
}

// IsEmpty checks if the UpdateProfileRequest has any fields to update.
func (r *UpdateProfileRequest) IsEmpty() bool {
	return r.FirstName == nil && r.LastName == nil && r.Email == nil
}

// HasEmailChange checks if the UpdateProfileRequest includes an email change.
func (r *UpdateProfileRequest) HasEmailChange() bool {
	return r.Email != nil
}
