// user/repository_interfaces.go
package user

import (
	"context"
	"time"

	"github.com/MichaelAJay/go-user-management/auth"
)

type CreateUserParams struct {
	FirstName           []byte
	LastName            []byte
	Email               []byte
	HashedEmail         string
	PrimaryAuthProvider auth.ProviderType
}

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
	Create(ctx context.Context, user *CreateUserParams) error

	// GetByHashedEmail retrieves a user by their hashed email address.
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
	// DEPRECATED: Use UserSecurityRepository instead
	UpdateLoginAttempts(ctx context.Context, hashedEmail string, attempts int) error

	// ResetLoginAttempts atomically resets the login attempts counter to zero
	// DEPRECATED: Use UserSecurityRepository instead
	ResetLoginAttempts(ctx context.Context, hashedEmail string) error

	// LockAccount sets the account lock status for the user
	// DEPRECATED: Use UserSecurityRepository instead
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

// AuthenticationRepository manages credential storage and retrieval.
// This repository is focused solely on authentication data CRUD operations.
// Following the Single Responsibility Principle, this repository handles
// only credential-related data operations.
type AuthenticationRepository interface {
	// Credential management - Core CRUD operations
	CreateCredentials(ctx context.Context, creds *UserCredentials) error
	GetCredentials(ctx context.Context, userID string, providerType auth.ProviderType) (*UserCredentials, error)
	UpdateCredentials(ctx context.Context, creds *UserCredentials) error
	DeleteCredentials(ctx context.Context, userID string, providerType auth.ProviderType) error

	// Multi-provider operations for users with multiple auth methods
	GetAllCredentials(ctx context.Context, userID string) ([]*UserCredentials, error)
	GetActiveProviders(ctx context.Context, userID string) ([]auth.ProviderType, error)

	// Batch operations for efficiency in bulk operations
	GetCredentialsBatch(ctx context.Context, userIDs []string, providerType auth.ProviderType) (map[string]*UserCredentials, error)

	// Credential lifecycle management
	ExpireCredentials(ctx context.Context, userID string, providerType auth.ProviderType) error
	RevokeCredentials(ctx context.Context, userID string, providerType auth.ProviderType) error

	// Cleanup operations for maintenance
	DeleteExpiredCredentials(ctx context.Context, before time.Time) (int64, error)
	DeleteUserCredentials(ctx context.Context, userID string) error

	// Record usage for security tracking
	RecordCredentialUsage(ctx context.Context, userID string, providerType auth.ProviderType) error
	RecordFailedAttempt(ctx context.Context, userID string, providerType auth.ProviderType) error
}

// UserSecurityRepository manages security state separate from profile data.
// This repository focuses solely on security-related operations like login tracking,
// account locking, risk assessment, and security event management.
type UserSecurityRepository interface {
	// Security state management - Core CRUD operations
	CreateSecurity(ctx context.Context, security *UserSecurity) error
	GetSecurity(ctx context.Context, userID string) (*UserSecurity, error)
	UpdateSecurity(ctx context.Context, security *UserSecurity) error
	DeleteSecurity(ctx context.Context, userID string) error

	// Login attempt tracking - High-frequency operations
	IncrementLoginAttempts(ctx context.Context, userID string) error
	ResetLoginAttempts(ctx context.Context, userID string) error
	RecordSuccessfulLogin(ctx context.Context, userID string, ipAddress string) error

	// Account lockout operations
	LockAccount(ctx context.Context, userID string, until *time.Time, reason string) error
	UnlockAccount(ctx context.Context, userID string) error
	GetLockedAccounts(ctx context.Context) ([]*UserSecurity, error)

	// Risk assessment operations
	UpdateRiskScore(ctx context.Context, userID string, score float64, factors []RiskFactor) error
	GetHighRiskUsers(ctx context.Context, threshold float64) ([]*UserSecurity, error)

	// Security event management
	AddSecurityEvent(ctx context.Context, userID string, event SecurityEvent) error
	GetSecurityEvents(ctx context.Context, userID string, since time.Time) ([]SecurityEvent, error)

	// Batch operations for efficiency
	GetSecurityBatch(ctx context.Context, userIDs []string) (map[string]*UserSecurity, error)
	UpdateSecurityBatch(ctx context.Context, securities []*UserSecurity) error

	// Maintenance operations
	CleanupOldEvents(ctx context.Context, before time.Time) (int64, error)
	GetSecurityStats(ctx context.Context) (*SecurityStats, error)
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

// SecurityStats represents aggregated security statistics
type SecurityStats struct {
	TotalUsers           int64     `json:"total_users"`
	LockedUsers          int64     `json:"locked_users"`
	HighRiskUsers        int64     `json:"high_risk_users"`
	RecentFailedAttempts int64     `json:"recent_failed_attempts"`
	AverageRiskScore     float64   `json:"average_risk_score"`
	UpdatedAt            time.Time `json:"updated_at"`
}
