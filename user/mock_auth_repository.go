package user

import (
	"context"
	"sync"
	"time"

	"github.com/MichaelAJay/go-user-management/auth"
	"github.com/MichaelAJay/go-user-management/errors"
)

// InMemoryAuthRepository provides an in-memory implementation of AuthenticationRepository
// for testing purposes. This follows Go best practice of using concrete implementations
// for testing rather than external mocking frameworks.
type InMemoryAuthRepository struct {
	// Map: userID -> providerType -> credentials
	credentials map[string]map[auth.ProviderType]*UserCredentials
	mu          sync.RWMutex
}

// NewInMemoryAuthRepository creates a new in-memory authentication repository
func NewInMemoryAuthRepository() AuthenticationRepository {
	return &InMemoryAuthRepository{
		credentials: make(map[string]map[auth.ProviderType]*UserCredentials),
	}
}

// CreateCredentials stores new credentials for a user and provider
func (r *InMemoryAuthRepository) CreateCredentials(ctx context.Context, creds *UserCredentials) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.credentials[creds.UserID] == nil {
		r.credentials[creds.UserID] = make(map[auth.ProviderType]*UserCredentials)
	}

	if _, exists := r.credentials[creds.UserID][creds.ProviderType]; exists {
		return errors.NewAppError(errors.CodeDuplicateEmail, "credentials already exist")
	}

	// Clone to avoid mutations
	credsCopy := *creds
	credsCopy.CreatedAt = time.Now()
	credsCopy.UpdatedAt = time.Now()
	credsCopy.Version = 1

	r.credentials[creds.UserID][creds.ProviderType] = &credsCopy
	return nil
}

// GetCredentials retrieves credentials for a user and provider
func (r *InMemoryAuthRepository) GetCredentials(ctx context.Context, userID string, providerType auth.ProviderType) (*UserCredentials, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	userCreds, exists := r.credentials[userID]
	if !exists {
		return nil, errors.ErrUserNotFound
	}

	creds, exists := userCreds[providerType]
	if !exists {
		return nil, errors.ErrUserNotFound
	}

	// Return copy to avoid mutations
	credsCopy := *creds
	return &credsCopy, nil
}

// UpdateCredentials updates existing credentials
func (r *InMemoryAuthRepository) UpdateCredentials(ctx context.Context, creds *UserCredentials) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	userCreds, exists := r.credentials[creds.UserID]
	if !exists {
		return errors.ErrUserNotFound
	}

	existing, exists := userCreds[creds.ProviderType]
	if !exists {
		return errors.ErrUserNotFound
	}

	// Check version for optimistic locking
	if existing.Version != creds.Version-1 {
		return errors.ErrVersionMismatch
	}

	// Update credentials
	credsCopy := *creds
	credsCopy.UpdatedAt = time.Now()
	r.credentials[creds.UserID][creds.ProviderType] = &credsCopy
	return nil
}

// DeleteCredentials removes credentials for a user and provider
func (r *InMemoryAuthRepository) DeleteCredentials(ctx context.Context, userID string, providerType auth.ProviderType) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	userCreds, exists := r.credentials[userID]
	if !exists {
		return errors.ErrUserNotFound
	}

	if _, exists := userCreds[providerType]; !exists {
		return errors.ErrUserNotFound
	}

	delete(userCreds, providerType)
	if len(userCreds) == 0 {
		delete(r.credentials, userID)
	}
	return nil
}

// GetAllCredentials retrieves all credentials for a user
func (r *InMemoryAuthRepository) GetAllCredentials(ctx context.Context, userID string) ([]*UserCredentials, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	userCreds, exists := r.credentials[userID]
	if !exists {
		return []*UserCredentials{}, nil
	}

	result := make([]*UserCredentials, 0, len(userCreds))
	for _, creds := range userCreds {
		credsCopy := *creds
		result = append(result, &credsCopy)
	}
	return result, nil
}

// GetActiveProviders returns list of active providers for a user
func (r *InMemoryAuthRepository) GetActiveProviders(ctx context.Context, userID string) ([]auth.ProviderType, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	userCreds, exists := r.credentials[userID]
	if !exists {
		return []auth.ProviderType{}, nil
	}

	providers := make([]auth.ProviderType, 0, len(userCreds))
	for providerType, creds := range userCreds {
		// Only include active credentials
		if creds.Status == CredentialStatusActive {
			providers = append(providers, providerType)
		}
	}
	return providers, nil
}

// GetCredentialsBatch retrieves credentials for multiple users
func (r *InMemoryAuthRepository) GetCredentialsBatch(ctx context.Context, userIDs []string, providerType auth.ProviderType) (map[string]*UserCredentials, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]*UserCredentials)
	for _, userID := range userIDs {
		if userCreds, exists := r.credentials[userID]; exists {
			if creds, exists := userCreds[providerType]; exists {
				credsCopy := *creds
				result[userID] = &credsCopy
			}
		}
	}
	return result, nil
}

// ExpireCredentials marks credentials as expired
func (r *InMemoryAuthRepository) ExpireCredentials(ctx context.Context, userID string, providerType auth.ProviderType) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	userCreds, exists := r.credentials[userID]
	if !exists {
		return errors.ErrUserNotFound
	}

	creds, exists := userCreds[providerType]
	if !exists {
		return errors.ErrUserNotFound
	}

	creds.Status = CredentialStatusExpired
	creds.UpdatedAt = time.Now()
	creds.Version++
	return nil
}

// RevokeCredentials marks credentials as revoked
func (r *InMemoryAuthRepository) RevokeCredentials(ctx context.Context, userID string, providerType auth.ProviderType) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	userCreds, exists := r.credentials[userID]
	if !exists {
		return errors.ErrUserNotFound
	}

	creds, exists := userCreds[providerType]
	if !exists {
		return errors.ErrUserNotFound
	}

	creds.Status = CredentialStatusRevoked
	creds.UpdatedAt = time.Now()
	creds.Version++
	return nil
}

// DeleteExpiredCredentials removes credentials that expired before the given time
func (r *InMemoryAuthRepository) DeleteExpiredCredentials(ctx context.Context, before time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var deleted int64
	for userID, userCreds := range r.credentials {
		for providerType, creds := range userCreds {
			if creds.ExpiresAt != nil && creds.ExpiresAt.Before(before) {
				delete(userCreds, providerType)
				deleted++
			}
		}
		if len(userCreds) == 0 {
			delete(r.credentials, userID)
		}
	}
	return deleted, nil
}

// DeleteUserCredentials removes all credentials for a user
func (r *InMemoryAuthRepository) DeleteUserCredentials(ctx context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.credentials, userID)
	return nil
}

// RecordCredentialUsage records that credentials were used
func (r *InMemoryAuthRepository) RecordCredentialUsage(ctx context.Context, userID string, providerType auth.ProviderType) error {
	// In memory implementation - just update timestamp
	r.mu.Lock()
	defer r.mu.Unlock()

	userCreds, exists := r.credentials[userID]
	if !exists {
		return errors.ErrUserNotFound
	}

	creds, exists := userCreds[providerType]
	if !exists {
		return errors.ErrUserNotFound
	}

	creds.UpdatedAt = time.Now()
	return nil
}

// RecordFailedAttempt records a failed authentication attempt
func (r *InMemoryAuthRepository) RecordFailedAttempt(ctx context.Context, userID string, providerType auth.ProviderType) error {
	// In memory implementation - just update timestamp
	r.mu.Lock()
	defer r.mu.Unlock()

	userCreds, exists := r.credentials[userID]
	if !exists {
		return errors.ErrUserNotFound
	}

	creds, exists := userCreds[providerType]
	if !exists {
		return errors.ErrUserNotFound
	}

	creds.UpdatedAt = time.Now()
	return nil
}
