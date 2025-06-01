package user

import (
	"time"

	"github.com/MichaelAJay/go-user-management/auth"
	"github.com/MichaelAJay/go-user-management/errors"
)

// CredentialStatus represents the lifecycle state of user credentials
type CredentialStatus int

const (
	// CredentialStatusActive indicates credentials are valid and can be used
	CredentialStatusActive CredentialStatus = iota
	// CredentialStatusExpired indicates credentials have expired and need renewal
	CredentialStatusExpired
	// CredentialStatusRevoked indicates credentials have been revoked for security reasons
	CredentialStatusRevoked
	// CredentialStatusPendingValidation indicates credentials are pending validation (e.g., email verification)
	CredentialStatusPendingValidation
	// CredentialStatusSuspended indicates credentials are temporarily suspended
	CredentialStatusSuspended
)

// String returns the string representation of CredentialStatus
func (cs CredentialStatus) String() string {
	switch cs {
	case CredentialStatusActive:
		return "active"
	case CredentialStatusExpired:
		return "expired"
	case CredentialStatusRevoked:
		return "revoked"
	case CredentialStatusPendingValidation:
		return "pending_validation"
	case CredentialStatusSuspended:
		return "suspended"
	default:
		return "unknown"
	}
}

// IsValid returns true if the CredentialStatus is a valid value
func (cs CredentialStatus) IsValid() bool {
	return cs >= CredentialStatusActive && cs <= CredentialStatusSuspended
}

// CanAuthenticate returns true if credentials with this status can be used for authentication
func (cs CredentialStatus) CanAuthenticate() bool {
	return cs == CredentialStatusActive
}

// UserCredentials represents authentication data for a specific provider.
// This entity follows the principle of storing provider-specific auth data separately
// from user profile data, enabling proper domain separation and security isolation.
//
// Primary Key: (UserID, ProviderType) - ensures one credential per provider per user
type UserCredentials struct {
	// UserID is the foreign key reference to the User entity
	// This establishes the relationship: User 1 -> N UserCredentials
	UserID string `json:"user_id" db:"user_id"`

	// ProviderType identifies which authentication provider these credentials belong to
	// Examples: "password", "google_oauth", "saml", "auth0"
	ProviderType auth.ProviderType `json:"provider_type" db:"provider_type"`

	// EncryptedAuthData contains the provider-specific authentication data as encrypted JSON
	// - For password provider: contains hashed password and salt
	// - For OAuth provider: contains access/refresh tokens
	// - For SAML provider: contains SAML assertion data
	// Using []byte ensures data-at-rest encryption and prevents accidental logging
	EncryptedAuthData []byte `json:"-" db:"encrypted_auth_data"`

	// Status indicates the current lifecycle state of these credentials
	// Used for credential rotation, revocation, and lifecycle management
	Status CredentialStatus `json:"status" db:"status"`

	// CreatedAt tracks when these credentials were first created
	// Important for security auditing and credential age policies
	CreatedAt time.Time `json:"created_at" db:"created_at"`

	// UpdatedAt tracks when these credentials were last modified
	// Updated on any change to auth data, status, or expiration
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`

	// ExpiresAt optionally defines when these credentials expire
	// Used for temporary credentials, OAuth tokens, or password expiration policies
	// Nil value means credentials don't expire
	ExpiresAt *time.Time `json:"expires_at,omitempty" db:"expires_at"`

	// LastUsedAt tracks when these credentials were last used for authentication
	// Useful for identifying stale credentials and security monitoring
	LastUsedAt *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`

	// FailedAttempts tracks consecutive failed authentication attempts for these specific credentials
	// Different from User.LoginAttempts which tracks overall user login attempts
	FailedAttempts int `json:"failed_attempts" db:"failed_attempts"`

	// Version enables optimistic locking for concurrent credential updates
	// Prevents race conditions when multiple processes update the same credentials
	Version int64 `json:"version" db:"version"`
}

// NewUserCredentials creates a new UserCredentials instance with default values
func NewUserCredentials(userID string, providerType auth.ProviderType, encryptedAuthData []byte) *UserCredentials {
	now := time.Now()
	return &UserCredentials{
		UserID:            userID,
		ProviderType:      providerType,
		EncryptedAuthData: encryptedAuthData,
		Status:            CredentialStatusActive,
		CreatedAt:         now,
		UpdatedAt:         now,
		FailedAttempts:    0,
		Version:           1,
	}
}

// IsExpired returns true if the credentials have expired
func (uc *UserCredentials) IsExpired() bool {
	return uc.ExpiresAt != nil && time.Now().After(*uc.ExpiresAt)
}

// CanAuthenticate returns true if these credentials can be used for authentication
func (uc *UserCredentials) CanAuthenticate() bool {
	return uc.Status.CanAuthenticate() && !uc.IsExpired()
}

// UpdateAuthData updates the encrypted authentication data and resets failure tracking
// This method encapsulates the business rule that credential updates reset failure counters
func (uc *UserCredentials) UpdateAuthData(encryptedAuthData []byte) error {
	if len(encryptedAuthData) == 0 {
		return errors.NewValidationError("auth_data", "encrypted authentication data cannot be empty")
	}

	uc.EncryptedAuthData = encryptedAuthData
	uc.FailedAttempts = 0 // Reset failures on successful update
	uc.updateMetadata()
	return nil
}

// RecordFailedAttempt increments the failed attempts counter
func (uc *UserCredentials) RecordFailedAttempt() {
	uc.FailedAttempts++
	uc.updateMetadata()
}

// ResetFailedAttempts clears the failed attempts counter
func (uc *UserCredentials) ResetFailedAttempts() {
	uc.FailedAttempts = 0
	uc.updateMetadata()
}

// MarkAsUsed updates the last used timestamp
func (uc *UserCredentials) MarkAsUsed() {
	now := time.Now()
	uc.LastUsedAt = &now
	uc.updateMetadata()
}

// Expire marks the credentials as expired by setting the status
func (uc *UserCredentials) Expire() {
	uc.Status = CredentialStatusExpired
	uc.updateMetadata()
}

// Revoke marks the credentials as revoked (cannot be reactivated)
func (uc *UserCredentials) Revoke() {
	uc.Status = CredentialStatusRevoked
	uc.updateMetadata()
}

// Suspend temporarily suspends the credentials
func (uc *UserCredentials) Suspend() {
	uc.Status = CredentialStatusSuspended
	uc.updateMetadata()
}

// Activate marks the credentials as active and usable
func (uc *UserCredentials) Activate() {
	uc.Status = CredentialStatusActive
	uc.updateMetadata()
}

// SetExpiration sets an expiration time for the credentials
func (uc *UserCredentials) SetExpiration(expiresAt time.Time) error {
	if expiresAt.Before(time.Now()) {
		return errors.NewValidationError("expires_at", "expiration time must be in the future")
	}
	uc.ExpiresAt = &expiresAt
	uc.updateMetadata()
	return nil
}

// ClearExpiration removes the expiration time (credentials won't expire)
func (uc *UserCredentials) ClearExpiration() {
	uc.ExpiresAt = nil
	uc.updateMetadata()
}

// Validate performs comprehensive validation on the UserCredentials entity
func (uc *UserCredentials) Validate() error {
	if uc.UserID == "" {
		return errors.NewValidationError("user_id", "user ID is required")
	}

	if uc.ProviderType == "" {
		return errors.NewValidationError("provider_type", "provider type is required")
	}

	if len(uc.EncryptedAuthData) == 0 {
		return errors.NewValidationError("encrypted_auth_data", "encrypted authentication data is required")
	}

	if !uc.Status.IsValid() {
		return errors.NewValidationError("status", "invalid credential status")
	}

	if uc.Version <= 0 {
		return errors.NewValidationError("version", "version must be positive")
	}

	if uc.FailedAttempts < 0 {
		return errors.NewValidationError("failed_attempts", "failed attempts cannot be negative")
	}

	return nil
}

// Clone creates a deep copy of the UserCredentials for safe concurrent operations
func (uc *UserCredentials) Clone() *UserCredentials {
	clone := *uc

	// Deep copy the encrypted auth data
	if uc.EncryptedAuthData != nil {
		clone.EncryptedAuthData = make([]byte, len(uc.EncryptedAuthData))
		copy(clone.EncryptedAuthData, uc.EncryptedAuthData)
	}

	// Deep copy time pointers
	if uc.ExpiresAt != nil {
		expiresAt := *uc.ExpiresAt
		clone.ExpiresAt = &expiresAt
	}

	if uc.LastUsedAt != nil {
		lastUsedAt := *uc.LastUsedAt
		clone.LastUsedAt = &lastUsedAt
	}

	return &clone
}

// updateMetadata ensures consistent metadata updates for all state changes
// This private helper centralizes version increment and timestamp updates
func (uc *UserCredentials) updateMetadata() {
	uc.UpdatedAt = time.Now()
	uc.Version++
}
