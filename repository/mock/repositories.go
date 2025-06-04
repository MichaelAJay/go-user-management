// repository/mock/repositories.go
package mock

import (
	"context"
	"sync"
	"time"

	"github.com/MichaelAJay/go-user-management/auth"
	"github.com/MichaelAJay/go-user-management/errors"
	"github.com/MichaelAJay/go-user-management/repository"
	"github.com/MichaelAJay/go-user-management/user"
)

// MockProvider implements repository.Provider for testing
type MockProvider struct {
	userRepo     repository.UserRepository
	authRepo     repository.AuthenticationRepository
	securityRepo repository.UserSecurityRepository
}

// NewMockProvider creates a new mock repository provider
func NewMockProvider() repository.Provider {
	return &MockProvider{
		userRepo:     NewMockUserRepository(),
		authRepo:     NewMockAuthRepository(),
		securityRepo: NewMockSecurityRepository(),
	}
}

// GetUserRepository returns the mock user repository
func (p *MockProvider) GetUserRepository() repository.UserRepository {
	return p.userRepo
}

// GetAuthRepository returns the mock auth repository
func (p *MockProvider) GetAuthRepository() repository.AuthenticationRepository {
	return p.authRepo
}

// GetSecurityRepository returns the mock security repository
func (p *MockProvider) GetSecurityRepository() repository.UserSecurityRepository {
	return p.securityRepo
}

// Close is a no-op for mock provider
func (p *MockProvider) Close() error {
	return nil
}

// Ping always returns nil for mock provider
func (p *MockProvider) Ping() error {
	return nil
}

// MockUserRepository implements repository.UserRepository for testing
type MockUserRepository struct {
	users        map[string]*user.User
	emailHashes  map[string]string // hashedEmail -> userID
	mu           sync.RWMutex
	shouldFail   bool
	failOnMethod string
}

// NewMockUserRepository creates a new mock user repository
func NewMockUserRepository() repository.UserRepository {
	return &MockUserRepository{
		users:       make(map[string]*user.User),
		emailHashes: make(map[string]string),
	}
}

// SetShouldFail configures the mock to fail on specific methods
func (m *MockUserRepository) SetShouldFail(method string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldFail = true
	m.failOnMethod = method
}

// Create stores a new user
func (m *MockUserRepository) Create(ctx context.Context, u *user.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.shouldFail && m.failOnMethod == "Create" {
		return errors.NewAppError(errors.CodeInternalError, "mock create failed")
	}

	// Check for duplicate email
	if _, exists := m.emailHashes[u.HashedEmail]; exists {
		return errors.NewDuplicateEmailError("user with this email already exists")
	}

	// Clone to avoid mutations
	userCopy := u.Clone()
	userCopy.CreatedAt = time.Now()
	userCopy.UpdatedAt = time.Now()
	userCopy.Version = 1

	m.users[u.ID] = userCopy
	m.emailHashes[u.HashedEmail] = u.ID
	return nil
}

// GetByHashedEmail retrieves a user by hashed email
func (m *MockUserRepository) GetByHashedEmail(ctx context.Context, hashedEmail string) (*user.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.shouldFail && m.failOnMethod == "GetByHashedEmail" {
		return nil, errors.NewAppError(errors.CodeInternalError, "mock get failed")
	}

	if userID, exists := m.emailHashes[hashedEmail]; exists {
		if user, found := m.users[userID]; found {
			return user.Clone(), nil
		}
	}
	return nil, errors.ErrUserNotFound
}

// GetByID retrieves a user by ID
func (m *MockUserRepository) GetByID(ctx context.Context, id string) (*user.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.shouldFail && m.failOnMethod == "GetByID" {
		return nil, errors.NewAppError(errors.CodeInternalError, "mock get failed")
	}

	if user, exists := m.users[id]; exists {
		return user.Clone(), nil
	}
	return nil, errors.ErrUserNotFound
}

// Update modifies an existing user
func (m *MockUserRepository) Update(ctx context.Context, u *user.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.shouldFail && m.failOnMethod == "Update" {
		return errors.NewAppError(errors.CodeInternalError, "mock update failed")
	}

	existing, exists := m.users[u.ID]
	if !exists {
		return errors.ErrUserNotFound
	}

	// Check version for optimistic locking
	if existing.Version != u.Version-1 {
		return errors.ErrVersionMismatch
	}

	// Update user (clone to avoid mutations)
	userCopy := u.Clone()
	userCopy.UpdatedAt = time.Now()

	// Update email mapping if email changed
	if existing.HashedEmail != u.HashedEmail {
		delete(m.emailHashes, existing.HashedEmail)
		m.emailHashes[u.HashedEmail] = u.ID
	}

	m.users[u.ID] = userCopy
	return nil
}

// Delete removes a user
func (m *MockUserRepository) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.shouldFail && m.failOnMethod == "Delete" {
		return errors.NewAppError(errors.CodeInternalError, "mock delete failed")
	}

	user, exists := m.users[id]
	if !exists {
		return errors.ErrUserNotFound
	}

	delete(m.emailHashes, user.HashedEmail)
	delete(m.users, id)
	return nil
}

// UpdateLoginAttempts is deprecated - returns not implemented
func (m *MockUserRepository) UpdateLoginAttempts(ctx context.Context, hashedEmail string, attempts int) error {
	return errors.NewAppError(errors.CodeNotImplemented, "Login attempts managed by UserSecurityRepository")
}

// ResetLoginAttempts is deprecated - returns not implemented
func (m *MockUserRepository) ResetLoginAttempts(ctx context.Context, hashedEmail string) error {
	return errors.NewAppError(errors.CodeNotImplemented, "Login attempts managed by UserSecurityRepository")
}

// LockAccount is deprecated - returns not implemented
func (m *MockUserRepository) LockAccount(ctx context.Context, hashedEmail string, until *time.Time) error {
	return errors.NewAppError(errors.CodeNotImplemented, "Account locking managed by UserSecurityRepository")
}

// ListUsers retrieves users with pagination
func (m *MockUserRepository) ListUsers(ctx context.Context, offset, limit int) ([]*user.User, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.shouldFail && m.failOnMethod == "ListUsers" {
		return nil, 0, errors.NewAppError(errors.CodeInternalError, "mock list failed")
	}

	users := make([]*user.User, 0, len(m.users))
	for _, u := range m.users {
		users = append(users, u.Clone())
	}

	// Simple pagination simulation
	total := int64(len(users))
	start := offset
	end := offset + limit

	if start > len(users) {
		return []*user.User{}, total, nil
	}
	if end > len(users) {
		end = len(users)
	}

	return users[start:end], total, nil
}

// GetUserStats returns user statistics
func (m *MockUserRepository) GetUserStats(ctx context.Context) (*user.UserStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.shouldFail && m.failOnMethod == "GetUserStats" {
		return nil, errors.NewAppError(errors.CodeInternalError, "mock stats failed")
	}

	stats := &user.UserStats{
		TotalUsers: int64(len(m.users)),
	}

	for _, u := range m.users {
		switch u.Status {
		case user.UserStatusActive:
			stats.ActiveUsers++
		case user.UserStatusSuspended:
			stats.SuspendedUsers++
		case user.UserStatusPendingVerification:
			stats.PendingVerificationUsers++
		case user.UserStatusDeactivated:
			stats.DeactivatedUsers++
		}

		// Simple time-based counting (last 24h, 7d, 30d)
		now := time.Now()
		if u.CreatedAt.After(now.Add(-24 * time.Hour)) {
			stats.UsersCreatedLast24h++
		}
		if u.CreatedAt.After(now.Add(-7 * 24 * time.Hour)) {
			stats.UsersCreatedLast7d++
		}
		if u.CreatedAt.After(now.Add(-30 * 24 * time.Hour)) {
			stats.UsersCreatedLast30d++
		}
	}

	return stats, nil
}

// MockAuthRepository implements repository.AuthenticationRepository for testing
type MockAuthRepository struct {
	credentials  map[string]map[auth.ProviderType]*user.UserCredentials // userID -> providerType -> credentials
	mu           sync.RWMutex
	shouldFail   bool
	failOnMethod string
}

// NewMockAuthRepository creates a new mock auth repository
func NewMockAuthRepository() repository.AuthenticationRepository {
	return &MockAuthRepository{
		credentials: make(map[string]map[auth.ProviderType]*user.UserCredentials),
	}
}

// SetShouldFail configures the mock to fail on specific methods
func (m *MockAuthRepository) SetShouldFail(method string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldFail = true
	m.failOnMethod = method
}

// CreateCredentials stores new credentials
func (m *MockAuthRepository) CreateCredentials(ctx context.Context, creds *user.UserCredentials) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.shouldFail && m.failOnMethod == "CreateCredentials" {
		return errors.NewAppError(errors.CodeInternalError, "mock create credentials failed")
	}

	if m.credentials[creds.UserID] == nil {
		m.credentials[creds.UserID] = make(map[auth.ProviderType]*user.UserCredentials)
	}

	if _, exists := m.credentials[creds.UserID][creds.ProviderType]; exists {
		return errors.NewAppError(errors.CodeDuplicateEmail, "credentials already exist")
	}

	// Clone to avoid mutations
	credsCopy := creds.Clone()
	credsCopy.CreatedAt = time.Now()
	credsCopy.UpdatedAt = time.Now()
	credsCopy.Version = 1

	m.credentials[creds.UserID][creds.ProviderType] = credsCopy
	return nil
}

// GetCredentials retrieves credentials
func (m *MockAuthRepository) GetCredentials(ctx context.Context, userID string, providerType auth.ProviderType) (*user.UserCredentials, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.shouldFail && m.failOnMethod == "GetCredentials" {
		return nil, errors.NewAppError(errors.CodeInternalError, "mock get credentials failed")
	}

	userCreds, exists := m.credentials[userID]
	if !exists {
		return nil, errors.ErrUserNotFound
	}

	creds, exists := userCreds[providerType]
	if !exists {
		return nil, errors.ErrUserNotFound
	}

	return creds.Clone(), nil
}

// UpdateCredentials updates existing credentials
func (m *MockAuthRepository) UpdateCredentials(ctx context.Context, creds *user.UserCredentials) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.shouldFail && m.failOnMethod == "UpdateCredentials" {
		return errors.NewAppError(errors.CodeInternalError, "mock update credentials failed")
	}

	userCreds, exists := m.credentials[creds.UserID]
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
	credsCopy := creds.Clone()
	credsCopy.UpdatedAt = time.Now()
	m.credentials[creds.UserID][creds.ProviderType] = credsCopy
	return nil
}

// DeleteCredentials removes credentials
func (m *MockAuthRepository) DeleteCredentials(ctx context.Context, userID string, providerType auth.ProviderType) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.shouldFail && m.failOnMethod == "DeleteCredentials" {
		return errors.NewAppError(errors.CodeInternalError, "mock delete credentials failed")
	}

	userCreds, exists := m.credentials[userID]
	if !exists {
		return errors.ErrUserNotFound
	}

	if _, exists := userCreds[providerType]; !exists {
		return errors.ErrUserNotFound
	}

	delete(userCreds, providerType)
	if len(userCreds) == 0 {
		delete(m.credentials, userID)
	}
	return nil
}

// GetAllCredentials retrieves all credentials for a user
func (m *MockAuthRepository) GetAllCredentials(ctx context.Context, userID string) ([]*user.UserCredentials, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	userCreds, exists := m.credentials[userID]
	if !exists {
		return []*user.UserCredentials{}, nil
	}

	result := make([]*user.UserCredentials, 0, len(userCreds))
	for _, creds := range userCreds {
		result = append(result, creds.Clone())
	}
	return result, nil
}

// GetActiveProviders returns active providers for a user
func (m *MockAuthRepository) GetActiveProviders(ctx context.Context, userID string) ([]auth.ProviderType, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	userCreds, exists := m.credentials[userID]
	if !exists {
		return []auth.ProviderType{}, nil
	}

	providers := make([]auth.ProviderType, 0, len(userCreds))
	for providerType, creds := range userCreds {
		if creds.Status == user.CredentialStatusActive {
			providers = append(providers, providerType)
		}
	}
	return providers, nil
}

// GetCredentialsBatch retrieves credentials for multiple users
func (m *MockAuthRepository) GetCredentialsBatch(ctx context.Context, userIDs []string, providerType auth.ProviderType) (map[string]*user.UserCredentials, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*user.UserCredentials)
	for _, userID := range userIDs {
		if userCreds, exists := m.credentials[userID]; exists {
			if creds, exists := userCreds[providerType]; exists {
				result[userID] = creds.Clone()
			}
		}
	}
	return result, nil
}

// ExpireCredentials marks credentials as expired
func (m *MockAuthRepository) ExpireCredentials(ctx context.Context, userID string, providerType auth.ProviderType) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	userCreds, exists := m.credentials[userID]
	if !exists {
		return errors.ErrUserNotFound
	}

	creds, exists := userCreds[providerType]
	if !exists {
		return errors.ErrUserNotFound
	}

	creds.Status = user.CredentialStatusExpired
	creds.UpdatedAt = time.Now()
	creds.Version++
	return nil
}

// RevokeCredentials marks credentials as revoked
func (m *MockAuthRepository) RevokeCredentials(ctx context.Context, userID string, providerType auth.ProviderType) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	userCreds, exists := m.credentials[userID]
	if !exists {
		return errors.ErrUserNotFound
	}

	creds, exists := userCreds[providerType]
	if !exists {
		return errors.ErrUserNotFound
	}

	creds.Status = user.CredentialStatusRevoked
	creds.UpdatedAt = time.Now()
	creds.Version++
	return nil
}

// DeleteExpiredCredentials removes expired credentials
func (m *MockAuthRepository) DeleteExpiredCredentials(ctx context.Context, before time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var deleted int64
	for userID, userCreds := range m.credentials {
		for providerType, creds := range userCreds {
			if creds.ExpiresAt != nil && creds.ExpiresAt.Before(before) {
				delete(userCreds, providerType)
				deleted++
			}
		}
		if len(userCreds) == 0 {
			delete(m.credentials, userID)
		}
	}
	return deleted, nil
}

// DeleteUserCredentials removes all credentials for a user
func (m *MockAuthRepository) DeleteUserCredentials(ctx context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.credentials, userID)
	return nil
}

// RecordCredentialUsage records credential usage
func (m *MockAuthRepository) RecordCredentialUsage(ctx context.Context, userID string, providerType auth.ProviderType) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	userCreds, exists := m.credentials[userID]
	if !exists {
		return errors.ErrUserNotFound
	}

	creds, exists := userCreds[providerType]
	if !exists {
		return errors.ErrUserNotFound
	}

	now := time.Now()
	creds.LastUsedAt = &now
	creds.UpdatedAt = time.Now()
	return nil
}

// RecordFailedAttempt records a failed attempt
func (m *MockAuthRepository) RecordFailedAttempt(ctx context.Context, userID string, providerType auth.ProviderType) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	userCreds, exists := m.credentials[userID]
	if !exists {
		return errors.ErrUserNotFound
	}

	creds, exists := userCreds[providerType]
	if !exists {
		return errors.ErrUserNotFound
	}

	creds.FailedAttempts++
	creds.UpdatedAt = time.Now()
	return nil
}

// MockSecurityRepository implements repository.UserSecurityRepository for testing
type MockSecurityRepository struct {
	securities   map[string]*user.UserSecurity
	mu           sync.RWMutex
	shouldFail   bool
	failOnMethod string
}

// NewMockSecurityRepository creates a new mock security repository
func NewMockSecurityRepository() repository.UserSecurityRepository {
	return &MockSecurityRepository{
		securities: make(map[string]*user.UserSecurity),
	}
}

// SetShouldFail configures the mock to fail on specific methods
func (m *MockSecurityRepository) SetShouldFail(method string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldFail = true
	m.failOnMethod = method
}

// CreateSecurity creates a new security record
func (m *MockSecurityRepository) CreateSecurity(ctx context.Context, security *user.UserSecurity) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.shouldFail && m.failOnMethod == "CreateSecurity" {
		return errors.NewAppError(errors.CodeInternalError, "mock create security failed")
	}

	if _, exists := m.securities[security.UserID]; exists {
		return errors.NewAppError(errors.CodeDuplicateEmail, "security record already exists")
	}

	// Clone to avoid mutations
	securityCopy := security.Clone()
	securityCopy.CreatedAt = time.Now()
	securityCopy.UpdatedAt = time.Now()
	securityCopy.Version = 1

	m.securities[security.UserID] = securityCopy
	return nil
}

// GetSecurity retrieves security information
func (m *MockSecurityRepository) GetSecurity(ctx context.Context, userID string) (*user.UserSecurity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.shouldFail && m.failOnMethod == "GetSecurity" {
		return nil, errors.NewAppError(errors.CodeInternalError, "mock get security failed")
	}

	security, exists := m.securities[userID]
	if !exists {
		return nil, errors.ErrUserNotFound
	}

	return security.Clone(), nil
}

// UpdateSecurity updates existing security information
func (m *MockSecurityRepository) UpdateSecurity(ctx context.Context, security *user.UserSecurity) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.shouldFail && m.failOnMethod == "UpdateSecurity" {
		return errors.NewAppError(errors.CodeInternalError, "mock update security failed")
	}

	existing, exists := m.securities[security.UserID]
	if !exists {
		return errors.ErrUserNotFound
	}

	// Check version for optimistic locking
	if existing.Version != security.Version-1 {
		return errors.ErrVersionMismatch
	}

	// Update security record
	securityCopy := security.Clone()
	securityCopy.UpdatedAt = time.Now()
	m.securities[security.UserID] = securityCopy
	return nil
}

// DeleteSecurity removes security information
func (m *MockSecurityRepository) DeleteSecurity(ctx context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.securities[userID]; !exists {
		return errors.ErrUserNotFound
	}

	delete(m.securities, userID)
	return nil
}

// Implement remaining methods with simple mock behavior...
// (I'll implement the key ones, but can add more if needed)

func (m *MockSecurityRepository) IncrementLoginAttempts(ctx context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	security, exists := m.securities[userID]
	if !exists {
		return errors.ErrUserNotFound
	}

	security.LoginAttempts++
	security.TotalLoginAttempts++
	security.UpdatedAt = time.Now()
	security.Version++
	return nil
}

func (m *MockSecurityRepository) ResetLoginAttempts(ctx context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	security, exists := m.securities[userID]
	if !exists {
		return errors.ErrUserNotFound
	}

	security.LoginAttempts = 0
	security.LockedUntil = nil
	security.LockReason = ""
	security.UpdatedAt = time.Now()
	security.Version++
	return nil
}

func (m *MockSecurityRepository) RecordSuccessfulLogin(ctx context.Context, userID string, ipAddress string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	security, exists := m.securities[userID]
	if !exists {
		return errors.ErrUserNotFound
	}

	now := time.Now()
	security.LoginAttempts = 0
	security.SuccessfulLogins++
	security.LastLoginAt = &now
	security.LastLoginIP = ipAddress
	security.LockedUntil = nil
	security.LockReason = ""
	security.UpdatedAt = time.Now()
	security.Version++
	return nil
}

func (m *MockSecurityRepository) LockAccount(ctx context.Context, userID string, until *time.Time, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	security, exists := m.securities[userID]
	if !exists {
		return errors.ErrUserNotFound
	}

	security.LockedUntil = until
	security.LockReason = reason
	security.UpdatedAt = time.Now()
	security.Version++
	return nil
}

func (m *MockSecurityRepository) UnlockAccount(ctx context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	security, exists := m.securities[userID]
	if !exists {
		return errors.ErrUserNotFound
	}

	security.LockedUntil = nil
	security.LockReason = ""
	security.LoginAttempts = 0
	security.UpdatedAt = time.Now()
	security.Version++
	return nil
}

// Simplified implementations for other methods
func (m *MockSecurityRepository) GetLockedAccounts(ctx context.Context) ([]*user.UserSecurity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var locked []*user.UserSecurity
	now := time.Now()
	for _, security := range m.securities {
		if security.IsLocked() || (security.LockedUntil != nil && security.LockedUntil.After(now)) {
			locked = append(locked, security.Clone())
		}
	}
	return locked, nil
}

func (m *MockSecurityRepository) UpdateRiskScore(ctx context.Context, userID string, score float64, factors []user.RiskFactor) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	security, exists := m.securities[userID]
	if !exists {
		return errors.ErrUserNotFound
	}

	security.RiskScore = score
	security.RiskFactors = factors
	security.UpdatedAt = time.Now()
	security.Version++
	return nil
}

func (m *MockSecurityRepository) GetHighRiskUsers(ctx context.Context, threshold float64) ([]*user.UserSecurity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var highRisk []*user.UserSecurity
	for _, security := range m.securities {
		if security.RiskScore >= threshold {
			highRisk = append(highRisk, security.Clone())
		}
	}
	return highRisk, nil
}

func (m *MockSecurityRepository) AddSecurityEvent(ctx context.Context, userID string, event user.SecurityEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	security, exists := m.securities[userID]
	if !exists {
		return errors.ErrUserNotFound
	}

	security.SecurityEvents = append(security.SecurityEvents, event)

	// Keep only the last 100 events
	if len(security.SecurityEvents) > 100 {
		security.SecurityEvents = security.SecurityEvents[len(security.SecurityEvents)-100:]
	}

	security.UpdatedAt = time.Now()
	security.Version++
	return nil
}

func (m *MockSecurityRepository) GetSecurityEvents(ctx context.Context, userID string, since time.Time) ([]user.SecurityEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	security, exists := m.securities[userID]
	if !exists {
		return nil, errors.ErrUserNotFound
	}

	var events []user.SecurityEvent
	for _, event := range security.SecurityEvents {
		if event.Timestamp.After(since) {
			events = append(events, event)
		}
	}
	return events, nil
}

func (m *MockSecurityRepository) GetSecurityBatch(ctx context.Context, userIDs []string) (map[string]*user.UserSecurity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*user.UserSecurity)
	for _, userID := range userIDs {
		if security, exists := m.securities[userID]; exists {
			result[userID] = security.Clone()
		}
	}
	return result, nil
}

func (m *MockSecurityRepository) UpdateSecurityBatch(ctx context.Context, securities []*user.UserSecurity) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, security := range securities {
		existing, exists := m.securities[security.UserID]
		if !exists {
			continue // Skip non-existent records
		}

		// Check version for optimistic locking
		if existing.Version != security.Version-1 {
			return errors.ErrVersionMismatch
		}

		securityCopy := security.Clone()
		securityCopy.UpdatedAt = time.Now()
		m.securities[security.UserID] = securityCopy
	}
	return nil
}

func (m *MockSecurityRepository) CleanupOldEvents(ctx context.Context, before time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var cleaned int64
	for _, security := range m.securities {
		var filteredEvents []user.SecurityEvent
		for _, event := range security.SecurityEvents {
			if event.Timestamp.After(before) {
				filteredEvents = append(filteredEvents, event)
			} else {
				cleaned++
			}
		}
		security.SecurityEvents = filteredEvents
		if len(filteredEvents) != len(security.SecurityEvents) {
			security.UpdatedAt = time.Now()
			security.Version++
		}
	}
	return cleaned, nil
}

func (m *MockSecurityRepository) GetSecurityStats(ctx context.Context) (*user.SecurityStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := &user.SecurityStats{
		TotalUsers:           int64(len(m.securities)),
		LockedUsers:          0,
		HighRiskUsers:        0,
		RecentFailedAttempts: 0,
		AverageRiskScore:     0.0,
		UpdatedAt:            time.Now(),
	}

	var totalRiskScore float64
	now := time.Now()
	oneDayAgo := now.Add(-24 * time.Hour)

	for _, security := range m.securities {
		// Count locked users
		if security.IsLocked() {
			stats.LockedUsers++
		}

		// Count high risk users (>= 70.0)
		if security.RiskScore >= 70.0 {
			stats.HighRiskUsers++
		}

		// Sum risk scores for average
		totalRiskScore += security.RiskScore

		// Count recent failed attempts
		if security.LastFailedAt != nil && security.LastFailedAt.After(oneDayAgo) {
			stats.RecentFailedAttempts += int64(security.LoginAttempts)
		}
	}

	// Calculate average risk score
	if len(m.securities) > 0 {
		stats.AverageRiskScore = totalRiskScore / float64(len(m.securities))
	}

	return stats, nil
}
