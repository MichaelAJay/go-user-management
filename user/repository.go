package user

import (
	"context"
	"time"
)

// UserRepository defines the interface for user data storage operations.
// This interface follows the Repository pattern, allowing different storage
// implementations (PostgreSQL, MySQL, MongoDB, etc.) to be used without
// changing the business logic.
//
// All methods should be implemented by storage providers and should handle:
// - Context cancellation and timeouts
// - Optimistic locking using the Version field
// - Proper error handling and wrapping
// - Thread-safe operations for concurrent access
type UserRepository interface {
	// Create stores a new user in the repository.
	// The user's Version should be set to 1 before calling this method.
	// Returns ErrDuplicateEmail if a user with the same HashedEmail already exists.
	Create(ctx context.Context, user *User) error

	// GetByHashhedEmail retrieves a user by their hashed email address.
	// This is the primary lookup method for authentication.
	// Returns ErrUserNotFound if no user exists with the given hashed email.
	GetByHashedEmail(ctx context.Context, hashedEmail string) (*User, error)

	// GetByID retrieves a user by their unique ID.
	// Returns ErrUserNotFound if no user exists with the given ID.
	GetByID(ctx context.Context, id string) (*User, error)

	// Update modifies an existing user in the repository.
	// This method should implement optimistic locking by checking the Version field.
	// The Version should be incremented automatically by this method.
	// Returns ErrVersionMismatch if the user's version doesn't match the stored version.
	// Returns ErrUserNotFound if the user doesn't exist.
	Update(ctx context.Context, user *User) error

	// Delete removes a user from the repository by their ID.
	// This is a hard delete operation. Consider implementing soft delete
	// in your implementation if required for audit/compliance purposes.
	// Returns ErrUserNotFound if the user doesn't exist.
	Delete(ctx context.Context, id string) error

	// UpdateLoginAttempts atomically increments the login attempts counter
	// and updates the UpdatedAt timestamp for the user with the given hashed email.
	// This method is optimized for high-frequency authentication operations.
	// Returns ErrUserNotFound if no user exists with the given hashed email.
	UpdateLoginAttempts(ctx context.Context, hashedEmail string, attempts int) error

	// ResetLoginAttempts atomically resets the login attempts counter to zero,
	// clears any LockedUntil timestamp, and updates the UpdatedAt timestamp.
	// This method is called after successful authentication or manual unlock.
	// Returns ErrUserNotFound if no user exists with the given hashed email.
	ResetLoginAttempts(ctx context.Context, hashedEmail string) error

	// LockAccount sets the account lock status for the user with the given hashed email.
	// If until is nil, the account is permanently locked (status becomes UserStatusLocked).
	// If until is provided, a temporary lock is set using the LockedUntil field.
	// Returns ErrUserNotFound if no user exists with the given hashed email.
	LockAccount(ctx context.Context, hashedEmail string, until *time.Time) error

	// ListUsers retrieves users with pagination support.
	// This method is useful for admin interfaces and bulk operations.
	// The offset is 0-based and limit should be reasonable (e.g., max 1000).
	// Returns a slice of users and the total count for pagination.
	ListUsers(ctx context.Context, offset, limit int) ([]*User, int64, error)

	// GetUserStats returns aggregated statistics about users.
	// This can be used for monitoring and admin dashboards.
	GetUserStats(ctx context.Context) (*UserStats, error)
}

// UserStats represents aggregated statistics about users in the system.
// This is useful for monitoring, reporting, and admin dashboards.
type UserStats struct {
	// TotalUsers is the total number of users in the system
	TotalUsers int64 `json:"total_users"`

	// ActiveUsers is the number of users with UserStatusActive
	ActiveUsers int64 `json:"active_users"`

	// PendingVerificationUsers is the number of users with UserStatusPendingVerification
	PendingVerificationUsers int64 `json:"pending_verification_users"`

	// SuspendedUsers is the number of users with UserStatusSuspended
	SuspendedUsers int64 `json:"suspended_users"`

	// LockedUsers is the number of users with UserStatusLocked
	LockedUsers int64 `json:"locked_users"`

	// DeactivatedUsers is the number of users with UserStatusDeactivated
	DeactivatedUsers int64 `json:"deactivated_users"`

	// UsersCreatedLast24h is the number of users created in the last 24 hours
	UsersCreatedLast24h int64 `json:"users_created_last_24h"`

	// UsersCreatedLast7d is the number of users created in the last 7 days
	UsersCreatedLast7d int64 `json:"users_created_last_7d"`

	// UsersCreatedLast30d is the number of users created in the last 30 days
	UsersCreatedLast30d int64 `json:"users_created_last_30d"`
}
