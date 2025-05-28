package user

import (
	"time"

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

// User represents a user entity in the system
// All PII fields are encrypted using go-encrypter for security
type User struct {
	// ID is the unique identifier for the user (UUID)
	ID string `json:"id"`

	// FirstName is the user's first name (encrypted)
	FirstName []byte `json:"-"` // Hidden from JSON serialization for security

	// LastName is the user's last name (encrypted)
	LastName []byte `json:"-"` // Hidden from JSON serialization for security

	// Email is the user's email address (encrypted)
	Email []byte `json:"-"` // Hidden from JSON serialization for security

	// HashedEmail is the hashed version of the email for database lookups
	// This allows efficient querying without exposing the actual email
	HashedEmail string `json:"-"` // Hidden from JSON serialization

	// AuthenticationData stores provider-specific authentication data
	// This replaces the Password field to support multiple authentication providers
	AuthenticationData map[auth.ProviderType]interface{} `json:"-"` // Hidden from JSON serialization for security

	// PrimaryAuthProvider indicates the primary authentication provider for this user
	PrimaryAuthProvider auth.ProviderType `json:"primary_auth_provider"`

	// Status represents the current status of the user account
	Status UserStatus `json:"status"`

	// CreatedAt is the timestamp when the user account was created
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is the timestamp when the user account was last updated
	UpdatedAt time.Time `json:"updated_at"`

	// LastLoginAt is the timestamp when the user last logged in
	// Pointer allows for nil value when user has never logged in
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`

	// LoginAttempts tracks the number of consecutive failed login attempts
	// Used for account lockout logic
	LoginAttempts int `json:"-"` // Hidden from JSON serialization

	// LockedUntil is the timestamp until which the account is locked
	// Pointer allows for nil value when account is not locked
	LockedUntil *time.Time `json:"-"` // Hidden from JSON serialization

	// Version is used for optimistic locking to prevent race conditions
	// Should be incremented on every update
	Version int64 `json:"version"`
}

// NewUser creates a new User instance with required fields
// Returns a User with a new UUID and default values
func NewUser(firstName, lastName, email, hashedEmail string, primaryProvider auth.ProviderType, authData interface{}) *User {
	now := time.Now()

	authenticationData := make(map[auth.ProviderType]interface{})
	authenticationData[primaryProvider] = authData

	return &User{
		ID:                  uuid.New().String(),
		HashedEmail:         hashedEmail,
		AuthenticationData:  authenticationData,
		PrimaryAuthProvider: primaryProvider,
		Status:              UserStatusPendingVerification, // Default to pending verification
		CreatedAt:           now,
		UpdatedAt:           now,
		LoginAttempts:       0,
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

// IsLocked returns true if the user account is currently locked
func (u *User) IsLocked() bool {
	if u.Status == UserStatusLocked {
		return true
	}

	// Check if temporary lockout has expired
	if u.LockedUntil != nil && time.Now().Before(*u.LockedUntil) {
		return true
	}

	return false
}

// CanAuthenticate returns true if the user can currently authenticate
// This checks both the status and any temporary lockouts
func (u *User) CanAuthenticate() bool {
	return u.Status.CanAuthenticate() && !u.IsLocked()
}

// IncrementLoginAttempts increments the login attempt counter
// This method is used when a login attempt fails
func (u *User) IncrementLoginAttempts() {
	u.LoginAttempts++
	u.UpdatedAt = time.Now()
	u.Version++
}

// ResetLoginAttempts resets the login attempt counter to zero
// This method is used when a login succeeds or when unlocking an account
func (u *User) ResetLoginAttempts() {
	u.LoginAttempts = 0
	u.LockedUntil = nil
	u.UpdatedAt = time.Now()
	u.Version++
}

// LockAccount locks the user account until the specified time
// If duration is 0, the account is locked indefinitely (status becomes locked)
func (u *User) LockAccount(until *time.Time) {
	if until == nil {
		// Permanent lock - change status
		u.Status = UserStatusLocked
	} else {
		// Temporary lock - set until time
		u.LockedUntil = until
	}
	u.UpdatedAt = time.Now()
	u.Version++
}

// UnlockAccount unlocks the user account and resets login attempts
func (u *User) UnlockAccount() {
	if u.Status == UserStatusLocked {
		u.Status = UserStatusActive
	}
	u.LockedUntil = nil
	u.ResetLoginAttempts()
}

// UpdateLastLogin updates the last login timestamp
// This should be called when a user successfully authenticates
func (u *User) UpdateLastLogin() {
	now := time.Now()
	u.LastLoginAt = &now
	u.UpdatedAt = now
	u.Version++
}

// Activate activates the user account
// This is typically called after email verification
func (u *User) Activate() {
	u.Status = UserStatusActive
	u.UpdatedAt = time.Now()
	u.Version++
}

// Suspend suspends the user account
func (u *User) Suspend() {
	u.Status = UserStatusSuspended
	u.UpdatedAt = time.Now()
	u.Version++
}

// Deactivate deactivates the user account
func (u *User) Deactivate() {
	u.Status = UserStatusDeactivated
	u.UpdatedAt = time.Now()
	u.Version++
}

// UpdateProfile updates the user's profile information
// This method handles version increment for optimistic locking
func (u *User) UpdateProfile() {
	u.UpdatedAt = time.Now()
	u.Version++
}

// UpdateAuthenticationData updates the user's authentication data for a specific provider
// This method also increments the version for optimistic locking
func (u *User) UpdateAuthenticationData(providerType auth.ProviderType, authData interface{}) {
	if u.AuthenticationData == nil {
		u.AuthenticationData = make(map[auth.ProviderType]interface{})
	}
	u.AuthenticationData[providerType] = authData
	u.UpdatedAt = time.Now()
	u.Version++
}

// GetAuthenticationData returns the authentication data for a specific provider
func (u *User) GetAuthenticationData(providerType auth.ProviderType) (interface{}, bool) {
	if u.AuthenticationData == nil {
		return nil, false
	}
	data, exists := u.AuthenticationData[providerType]
	return data, exists
}

// HasAuthenticationProvider checks if the user has authentication data for a specific provider
func (u *User) HasAuthenticationProvider(providerType auth.ProviderType) bool {
	_, exists := u.GetAuthenticationData(providerType)
	return exists
}

// AddAuthenticationProvider adds a new authentication provider to the user
func (u *User) AddAuthenticationProvider(providerType auth.ProviderType, authData interface{}) {
	if u.AuthenticationData == nil {
		u.AuthenticationData = make(map[auth.ProviderType]interface{})
	}
	u.AuthenticationData[providerType] = authData
	u.UpdatedAt = time.Now()
	u.Version++
}

// RemoveAuthenticationProvider removes an authentication provider from the user
func (u *User) RemoveAuthenticationProvider(providerType auth.ProviderType) {
	if u.AuthenticationData != nil {
		delete(u.AuthenticationData, providerType)
		u.UpdatedAt = time.Now()
		u.Version++
	}
}

// GetDisplayName returns a formatted display name for the user
func (u *User) GetDisplayName() string {
	// TODO: Implement with encrypter service to decrypt FirstName and LastName
	// For now, return a placeholder
	if len(u.ID) >= 8 {
		return "User " + u.ID[:8] // Use first 8 chars of ID as placeholder
	}
	return "User " + u.ID // Use full ID if shorter than 8 chars
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

	// Deep copy authentication data map
	if u.AuthenticationData != nil {
		clone.AuthenticationData = make(map[auth.ProviderType]interface{})
		for k, v := range u.AuthenticationData {
			clone.AuthenticationData[k] = v
		}
	}

	// Deep copy time pointers
	if u.LastLoginAt != nil {
		lastLogin := *u.LastLoginAt
		clone.LastLoginAt = &lastLogin
	}

	if u.LockedUntil != nil {
		lockedUntil := *u.LockedUntil
		clone.LockedUntil = &lockedUntil
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

	if u.AuthenticationData == nil || len(u.AuthenticationData) == 0 {
		return errors.ErrInvalidPassword
	}

	// Validate that primary auth provider exists in authentication data
	if _, exists := u.AuthenticationData[u.PrimaryAuthProvider]; !exists {
		return errors.ErrInvalidPassword
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
