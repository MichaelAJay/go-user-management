package user

import (
	"context"
	"time"

	"github.com/MichaelAJay/go-user-management/auth"
)

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
