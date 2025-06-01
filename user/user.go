package user

import (
	"time"

	"github.com/MichaelAJay/go-encrypter"
	"github.com/MichaelAJay/go-logger"
	"github.com/MichaelAJay/go-user-management/auth"
	"github.com/MichaelAJay/go-user-management/errors"
	"github.com/google/uuid"
)

// UserStatus represents the current status of a user account
type UserStatus int

const (
	// UserStatusActive indicates an active user account
	UserStatusActive UserStatus = iota
	// UserStatusSuspended indicates a suspended user account
	UserStatusSuspended
	// UserStatusPendingVerification indicates a user account pending email verification
	UserStatusPendingVerification
	// UserStatusLocked indicates a locked user account (due to too many failed login attempts)
	UserStatusLocked
	// UserStatusDeactivated indicates a deactivated user account
	UserStatusDeactivated
)

// String returns the string representation of UserStatus
// This implements the Stringer interface for better logging and debugging
func (s UserStatus) String() string {
	switch s {
	case UserStatusActive:
		return "active"
	case UserStatusSuspended:
		return "suspended"
	case UserStatusPendingVerification:
		return "pending_verification"
	case UserStatusLocked:
		return "locked"
	case UserStatusDeactivated:
		return "deactivated"
	default:
		return "unknown"
	}
}

// IsValid returns true if the UserStatus is a valid value
func (s UserStatus) IsValid() bool {
	return s >= UserStatusActive && s <= UserStatusDeactivated
}

// CanAuthenticate returns true if the user status allows authentication
func (s UserStatus) CanAuthenticate() bool {
	return s == UserStatusActive
}

// User represents a user entity focused on profile and account management.
// Authentication data and security state are handled by separate entities:
// - UserCredentials: handles provider-specific authentication data
// - UserSecurity: handles security state, login attempts, and risk assessment
//
// This separation follows the Single Responsibility Principle and enables
// different access patterns, caching strategies, and security policies.
type User struct {
	// ID is the unique identifier for the user (UUID)
	ID string `json:"id" db:"id"`

	// FirstName is the user's first name (encrypted)
	FirstName []byte `json:"-" db:"encrypted_first_name"`

	// LastName is the user's last name (encrypted)
	LastName []byte `json:"-" db:"encrypted_last_name"`

	// Email is the user's email address (encrypted)
	Email []byte `json:"-" db:"encrypted_email"`

	// HashedEmail is the hashed version of the email for database lookups
	// This allows efficient querying without exposing the actual email
	HashedEmail string `json:"-" db:"hashed_email"`

	// PrimaryAuthProvider indicates the primary authentication provider for this user
	// This is kept in the User entity for UX convenience (showing login options)
	// while actual credential data is stored in UserCredentials
	PrimaryAuthProvider auth.ProviderType `json:"primary_auth_provider" db:"primary_auth_provider"`

	// Status represents the current status of the user account
	Status UserStatus `json:"status" db:"status"`

	// CreatedAt is the timestamp when the user account was created
	CreatedAt time.Time `json:"created_at" db:"created_at"`

	// UpdatedAt is the timestamp when the user account was last updated
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`

	// Version is used for optimistic locking to prevent race conditions
	// Should be incremented on every update
	Version int64 `json:"version" db:"version"`
}

// NewUser creates a new User instance with required fields
func NewUser(firstName, lastName, email, hashedEmail string, primaryProvider auth.ProviderType) *User {
	now := time.Now()

	return &User{
		ID:                  uuid.New().String(),
		HashedEmail:         hashedEmail,
		PrimaryAuthProvider: primaryProvider,
		Status:              UserStatusPendingVerification, // Default to pending verification
		CreatedAt:           now,
		UpdatedAt:           now,
		Version:             1,
	}
}

// GetID returns the user's ID
// This method provides a consistent interface for accessing the ID
func (u *User) GetID() string {
	return u.ID
}

// IsActive returns true if the user account is active and can authenticate
func (u *User) IsActive() bool {
	return u.Status == UserStatusActive
}

// CanAuthenticate returns true if the user can currently authenticate
// Note: This only checks the user status, security state should be checked separately
func (u *User) CanAuthenticate() bool {
	return u.Status.CanAuthenticate()
}

// UpdateProfileData updates the user's profile data with encrypted values
// This method encapsulates the business rule that email changes require re-verification
func (u *User) UpdateProfileData(encryptedFirstName, encryptedLastName, encryptedEmail []byte, newHashedEmail string) error {
	// Validate that at least one field is being updated
	if encryptedFirstName == nil && encryptedLastName == nil && encryptedEmail == nil {
		return errors.NewValidationError("profile_data", "at least one field must be updated")
	}

	// Validate email consistency - if email is provided, hashed email must also be provided
	if (encryptedEmail != nil && newHashedEmail == "") || (encryptedEmail == nil && newHashedEmail != "") {
		return errors.NewValidationError("email_data", "encrypted email and hashed email must be provided together")
	}

	emailChanged := false

	if encryptedFirstName != nil {
		u.FirstName = encryptedFirstName
	}

	if encryptedLastName != nil {
		u.LastName = encryptedLastName
	}

	if encryptedEmail != nil && newHashedEmail != "" {
		u.Email = encryptedEmail
		u.HashedEmail = newHashedEmail
		emailChanged = true
	}

	// Business rule: email change requires re-verification for active users
	if emailChanged && u.Status == UserStatusActive {
		u.Status = UserStatusPendingVerification
	}

	u.updateMetadata()
	return nil
}

// ActivateAccount activates the user account
func (u *User) ActivateAccount() error {
	// Business rule: cannot activate deactivated users
	if u.Status == UserStatusDeactivated {
		return errors.NewAppError(errors.CodeUserDeactivated, "Cannot activate deactivated user")
	}

	// Business rule: cannot activate suspended users
	if u.Status == UserStatusSuspended {
		return errors.NewAppError(errors.CodeUserSuspended, "Cannot activate suspended user")
	}

	// Already active - no error, but no change needed
	if u.Status == UserStatusActive {
		return nil
	}

	u.Status = UserStatusActive
	u.updateMetadata()
	return nil
}

// SuspendAccount suspends the user account
func (u *User) SuspendAccount(reason string) error {
	// Business rule: cannot suspend deactivated users
	if u.Status == UserStatusDeactivated {
		return errors.NewAppError(errors.CodeUserDeactivated, "Cannot suspend deactivated user")
	}

	// Already suspended - no error, but no change needed
	if u.Status == UserStatusSuspended {
		return nil
	}

	u.Status = UserStatusSuspended
	u.updateMetadata()
	return nil
}

// DeactivateAccount deactivates the user account
func (u *User) DeactivateAccount(reason string) error {
	// Already deactivated - no error, but no change needed
	if u.Status == UserStatusDeactivated {
		return nil
	}

	u.Status = UserStatusDeactivated
	u.updateMetadata()
	return nil
}

// LockAccountPermanently locks the account permanently by changing status
func (u *User) LockAccountPermanently() error {
	// Business rule: cannot lock deactivated users
	if u.Status == UserStatusDeactivated {
		return errors.NewAppError(errors.CodeUserDeactivated, "Cannot lock deactivated user")
	}

	// Already permanently locked - no error, but no change needed
	if u.Status == UserStatusLocked {
		return nil
	}

	u.Status = UserStatusLocked
	u.updateMetadata()
	return nil
}

// UnlockAccount unlocks a permanently locked account
// Note: For temporary locks, use UserSecurity.UnlockAccount()
func (u *User) UnlockAccount() {
	if u.Status == UserStatusLocked {
		u.Status = UserStatusActive
		u.updateMetadata()
	}
}

// GetDisplayNameWithLogging returns a formatted display name for the user
func (u *User) GetDisplayName(enc encrypter.Encrypter, log logger.Logger) string {
	if enc == nil {
		// Fallback to ID-based display name if encrypter is not provided
		if len(u.ID) >= 8 {
			return "User " + u.ID[:8] // placeholder
		}
		return "User " + u.ID // Use full ID if shorter than 8 chars
	}

	// Decrypt only FirstName
	decryptedFirstName, err := enc.Decrypt(u.FirstName)
	if err != nil {
		// This could indicate security issues, data corruption, or key rotation problems
		if log != nil {
			log.Warn("Failed to decrypt user first name for display",
				logger.Field{Key: "user_id", Value: u.ID},
				logger.Field{Key: "error", Value: err.Error()},
				logger.Field{Key: "data_length", Value: len(u.FirstName)},
				logger.Field{Key: "status", Value: u.Status.String()},
				logger.Field{Key: "version", Value: u.Version},
			)
		}

		// Graceful degradation: return safe fallback
		if len(u.ID) >= 8 {
			return "User " + u.ID[:8] // placeholder
		}
		return "User " + u.ID
	}

	return string(decryptedFirstName)
}

// Clone creates a deep copy of the user
// This is useful for optimistic locking scenarios where you need to compare versions
func (u *User) Clone() *User {
	clone := *u

	// Deep copy slices
	if u.FirstName != nil {
		clone.FirstName = make([]byte, len(u.FirstName))
		copy(clone.FirstName, u.FirstName)
	}

	if u.LastName != nil {
		clone.LastName = make([]byte, len(u.LastName))
		copy(clone.LastName, u.LastName)
	}

	if u.Email != nil {
		clone.Email = make([]byte, len(u.Email))
		copy(clone.Email, u.Email)
	}

	return &clone
}

// Validate performs basic validation on the user entity
// This ensures the user data is in a valid state
func (u *User) Validate() error {
	// Validate required fields
	if u.ID == "" {
		return errors.ErrInvalidUserID
	}

	if u.HashedEmail == "" {
		return errors.ErrInvalidEmail
	}

	// Validate status
	if !u.Status.IsValid() {
		return errors.ErrInvalidUserStatus
	}

	// Validate UUID format
	if _, err := uuid.Parse(u.ID); err != nil {
		return errors.ErrInvalidUserID
	}

	// Validate version is positive
	if u.Version <= 0 {
		return errors.ErrInvalidVersion
	}

	return nil
}

// updateMetadata ensures consistent metadata updates for all state changes
// This private helper centralizes version increment and timestamp updates
func (u *User) updateMetadata() {
	u.UpdatedAt = time.Now()
	u.Version++
}
