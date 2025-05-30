package user

import (
	"context"
	"time"

	"github.com/MichaelAJay/go-cache"
	"github.com/MichaelAJay/go-config"
	"github.com/MichaelAJay/go-logger"
	"github.com/MichaelAJay/go-metrics"
	"github.com/MichaelAJay/go-user-management/auth"
	"github.com/MichaelAJay/go-user-management/auth/providers/password"
	"github.com/MichaelAJay/go-user-management/errors"
)

// Test helper functions (consolidating from existing test files)

func createTestUser() *User {
	return NewUser(
		"John",
		"Doe",
		"john.doe@example.com",
		"hashed_email",
		auth.ProviderTypePassword,
		map[string]interface{}{"password": "hashed_password"},
	)
}

func stringPtr(s string) *string {
	return &s
}

func timePtr(t time.Time) *time.Time {
	return &t
}

// Mock Repository Implementation
type mockRepository struct {
	users          map[string]*User
	emailIndex     map[string]string // hashedEmail -> userID
	createFunc     func(context.Context, *User) error
	updateFunc     func(context.Context, *User) error
	getByIDFunc    func(context.Context, string) (*User, error)
	getByEmailFunc func(context.Context, string) (*User, error)
}

func newMockRepository() *mockRepository {
	return &mockRepository{
		users:      make(map[string]*User),
		emailIndex: make(map[string]string),
	}
}

func (m *mockRepository) Create(ctx context.Context, user *User) error {
	if m.createFunc != nil {
		return m.createFunc(ctx, user)
	}

	// Check for duplicate email
	if _, exists := m.emailIndex[user.HashedEmail]; exists {
		return errors.NewDuplicateEmailError("email already exists")
	}

	m.users[user.ID] = user.Clone()
	m.emailIndex[user.HashedEmail] = user.ID
	return nil
}

func (m *mockRepository) GetByHashedEmail(ctx context.Context, hashedEmail string) (*User, error) {
	if m.getByEmailFunc != nil {
		return m.getByEmailFunc(ctx, hashedEmail)
	}

	userID, exists := m.emailIndex[hashedEmail]
	if !exists {
		return nil, errors.ErrUserNotFound
	}
	user, exists := m.users[userID]
	if !exists {
		return nil, errors.ErrUserNotFound
	}
	return user.Clone(), nil
}

func (m *mockRepository) GetByID(ctx context.Context, id string) (*User, error) {
	if m.getByIDFunc != nil {
		return m.getByIDFunc(ctx, id)
	}

	user, exists := m.users[id]
	if !exists {
		return nil, errors.ErrUserNotFound
	}
	return user.Clone(), nil
}

func (m *mockRepository) Update(ctx context.Context, user *User) error {
	if m.updateFunc != nil {
		return m.updateFunc(ctx, user)
	}

	existing, exists := m.users[user.ID]
	if !exists {
		return errors.ErrUserNotFound
	}

	// Check version for optimistic locking
	if existing.Version != user.Version-1 {
		return errors.ErrVersionMismatch
	}

	// Update email index if email changed
	if existing.HashedEmail != user.HashedEmail {
		delete(m.emailIndex, existing.HashedEmail)
		m.emailIndex[user.HashedEmail] = user.ID
	}

	m.users[user.ID] = user.Clone()
	return nil
}

func (m *mockRepository) Delete(ctx context.Context, id string) error {
	user, exists := m.users[id]
	if !exists {
		return errors.ErrUserNotFound
	}

	delete(m.users, id)
	delete(m.emailIndex, user.HashedEmail)
	return nil
}

func (m *mockRepository) UpdateLoginAttempts(ctx context.Context, hashedEmail string, attempts int) error {
	userID, exists := m.emailIndex[hashedEmail]
	if !exists {
		return errors.ErrUserNotFound
	}
	user := m.users[userID]
	user.LoginAttempts = attempts
	user.UpdatedAt = time.Now()
	user.Version++
	return nil
}

func (m *mockRepository) ResetLoginAttempts(ctx context.Context, hashedEmail string) error {
	userID, exists := m.emailIndex[hashedEmail]
	if !exists {
		return errors.ErrUserNotFound
	}
	user := m.users[userID]
	user.LoginAttempts = 0
	user.LockedUntil = nil
	user.UpdatedAt = time.Now()
	user.Version++
	return nil
}

func (m *mockRepository) LockAccount(ctx context.Context, hashedEmail string, until *time.Time) error {
	userID, exists := m.emailIndex[hashedEmail]
	if !exists {
		return errors.ErrUserNotFound
	}
	user := m.users[userID]
	user.LockAccount(until)
	return nil
}

func (m *mockRepository) ListUsers(ctx context.Context, offset, limit int) ([]*User, int64, error) {
	users := make([]*User, 0, len(m.users))
	for _, user := range m.users {
		users = append(users, user.Clone())
	}

	total := int64(len(users))
	start := offset
	end := offset + limit

	if start >= len(users) {
		return []*User{}, total, nil
	}
	if end > len(users) {
		end = len(users)
	}

	return users[start:end], total, nil
}

func (m *mockRepository) GetUserStats(ctx context.Context) (*UserStats, error) {
	stats := &UserStats{
		TotalUsers:               int64(len(m.users)),
		ActiveUsers:              0,
		PendingVerificationUsers: 0,
		SuspendedUsers:           0,
		LockedUsers:              0,
		DeactivatedUsers:         0,
	}

	for _, user := range m.users {
		switch user.Status {
		case UserStatusActive:
			stats.ActiveUsers++
		case UserStatusPendingVerification:
			stats.PendingVerificationUsers++
		case UserStatusSuspended:
			stats.SuspendedUsers++
		case UserStatusLocked:
			stats.LockedUsers++
		case UserStatusDeactivated:
			stats.DeactivatedUsers++
		}
	}

	return stats, nil
}

// Mock Encrypter Implementation
type mockEncrypter struct{}

func (m *mockEncrypter) Encrypt(data []byte) ([]byte, error) {
	// Simple mock encryption - just return the data with prefix
	return append([]byte("encrypted:"), data...), nil
}

func (m *mockEncrypter) EncryptWithAAD(data, additionalData []byte) ([]byte, error) {
	// Simple mock encryption with AAD - just return the data with prefix
	return append([]byte("encrypted:"), data...), nil
}

func (m *mockEncrypter) Decrypt(encryptedData []byte) ([]byte, error) {
	// Simple mock decryption - remove prefix
	if len(encryptedData) < 10 || string(encryptedData[:10]) != "encrypted:" {
		return nil, errors.NewAppError(errors.CodeInternalError, "invalid encrypted data")
	}
	return encryptedData[10:], nil
}

func (m *mockEncrypter) DecryptWithAAD(encryptedData, additionalData []byte) ([]byte, error) {
	// Simple mock decryption with AAD - remove prefix
	if len(encryptedData) < 10 || string(encryptedData[:10]) != "encrypted:" {
		return nil, errors.NewAppError(errors.CodeInternalError, "invalid encrypted data")
	}
	return encryptedData[10:], nil
}

func (m *mockEncrypter) HashPassword(password []byte) ([]byte, error) {
	// Simple mock hashing - just return data with hash prefix
	return append([]byte("hash:"), password...), nil
}

func (m *mockEncrypter) VerifyPassword(hashedPassword, password []byte) (bool, error) {
	// Simple mock verification - check against stored password
	if string(hashedPassword) == "hash:password" && string(password) == "password" {
		return true, nil
	}
	return false, nil
}

func (m *mockEncrypter) HashLookupData(data []byte) []byte {
	// Simple mock hashing - just return data with hash prefix
	return append([]byte("hash:"), data...)
}

// Mock Logger Implementation
type mockLogger struct{}

func (m *mockLogger) Debug(msg string, fields ...logger.Field) {}
func (m *mockLogger) Info(msg string, fields ...logger.Field)  {}
func (m *mockLogger) Warn(msg string, fields ...logger.Field)  {}
func (m *mockLogger) Error(msg string, fields ...logger.Field) {}
func (m *mockLogger) Fatal(msg string, fields ...logger.Field) {}
func (m *mockLogger) With(fields ...logger.Field) logger.Logger {
	return m
}
func (m *mockLogger) WithContext(ctx context.Context) logger.Logger {
	return m
}

// Mock Cache Implementation
type mockCache struct {
	data map[string]interface{}
}

func newMockCache() *mockCache {
	return &mockCache{
		data: make(map[string]interface{}),
	}
}

func (m *mockCache) Get(ctx context.Context, key string) (any, bool, error) {
	if val, exists := m.data[key]; exists {
		return val, true, nil
	}
	return nil, false, errors.ErrCacheMiss
}

func (m *mockCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	m.data[key] = value
	return nil
}

func (m *mockCache) Delete(ctx context.Context, key string) error {
	delete(m.data, key)
	return nil
}

func (m *mockCache) Clear(ctx context.Context) error {
	m.data = make(map[string]interface{})
	return nil
}

func (m *mockCache) Has(ctx context.Context, key string) bool {
	_, exists := m.data[key]
	return exists
}

func (m *mockCache) GetKeys(ctx context.Context) []string {
	keys := make([]string, 0, len(m.data))
	for key := range m.data {
		keys = append(keys, key)
	}
	return keys
}

func (m *mockCache) Close() error {
	return nil
}

func (m *mockCache) GetMany(ctx context.Context, keys []string) (map[string]interface{}, error) {
	values := make(map[string]interface{}, len(keys))
	for _, key := range keys {
		if val, exists := m.data[key]; exists {
			values[key] = val
		}
	}
	return values, nil
}

func (m *mockCache) SetMany(ctx context.Context, items map[string]interface{}, ttl time.Duration) error {
	for key, value := range items {
		m.data[key] = value
	}
	return nil
}

func (m *mockCache) DeleteMany(ctx context.Context, keys []string) error {
	for _, key := range keys {
		delete(m.data, key)
	}
	return nil
}

func (m *mockCache) GetMetadata(ctx context.Context, key string) (*cache.CacheEntryMetadata, error) {
	return nil, nil
}

func (m *mockCache) GetManyMetadata(ctx context.Context, keys []string) (map[string]*cache.CacheEntryMetadata, error) {
	return nil, nil
}

func (m *mockCache) GetMetrics() *cache.CacheMetricsSnapshot {
	return nil
}

// Mock Config Implementation
type mockConfig struct {
	values map[string]interface{}
}

func newMockConfig() *mockConfig {
	return &mockConfig{
		values: map[string]interface{}{
			"user_service.max_login_attempts":      5,
			"user_service.lockout_duration":        "30m",
			"user_service.cache_user_ttl":          "15m",
			"user_service.cache_stats_ttl":         "5m",
			"user_service.enable_rate_limit":       true,
			"user_service.rate_limit_window":       "1h",
			"user_service.rate_limit_max_attempts": 10,
		},
	}
}

func (m *mockConfig) Get(key string) (any, bool) {
	if val, exists := m.values[key]; exists {
		return val, true
	}
	return nil, false
}

func (m *mockConfig) GetString(key string) (string, bool) {
	if val, exists := m.values[key]; exists {
		if str, ok := val.(string); ok {
			return str, true
		}
	}
	return "", false
}

func (m *mockConfig) GetInt(key string) (int, bool) {
	if val, exists := m.values[key]; exists {
		if i, ok := val.(int); ok {
			return i, true
		}
	}
	return 0, false
}

func (m *mockConfig) GetBool(key string) (bool, bool) {
	if val, exists := m.values[key]; exists {
		if b, ok := val.(bool); ok {
			return b, true
		}
	}
	return false, false
}

func (m *mockConfig) GetFloat(key string) (float64, bool) {
	if val, exists := m.values[key]; exists {
		if f, ok := val.(float64); ok {
			return f, true
		}
	}
	return 0, false
}

func (m *mockConfig) GetStringSlice(key string) ([]string, bool) {
	if val, exists := m.values[key]; exists {
		if ss, ok := val.([]string); ok {
			return ss, true
		}
	}
	return nil, false
}

func (m *mockConfig) Set(key string, value any) error {
	m.values[key] = value
	return nil
}

func (m *mockConfig) Load(source config.Source) error {
	return nil
}

func (m *mockConfig) Validate() error {
	return nil
}

// Mock Metrics Implementation
type mockMetrics struct{}
type mockTimer struct{}
type mockCounter struct{}
type mockGauge struct{}
type mockHistogram struct{}

func (m *mockMetrics) Tags() metrics.Tags                           { return metrics.Tags{} }
func (m *mockMetrics) Registry() metrics.Registry                   { return m }
func (m *mockMetrics) Counter(opts metrics.Options) metrics.Counter { return &mockCounter{} }
func (m *mockMetrics) Gauge(opts metrics.Options) metrics.Gauge     { return &mockGauge{} }
func (m *mockMetrics) Histogram(opts metrics.Options) metrics.Histogram {
	return &mockHistogram{}
}
func (m *mockMetrics) Timer(opts metrics.Options) metrics.Timer { return &mockTimer{} }
func (m *mockMetrics) Each(fn func(metrics.Metric))             {}
func (m *mockMetrics) Unregister(name string)                   {}

func (m *mockCounter) Name() string                           { return "mock counter" }
func (m *mockCounter) Description() string                    { return "mock counter" }
func (m *mockCounter) Type() metrics.Type                     { return metrics.TypeCounter }
func (m *mockCounter) Tags() metrics.Tags                     { return metrics.Tags{} }
func (m *mockCounter) Inc()                                   {}
func (m *mockCounter) Add(float64)                            {}
func (m *mockCounter) With(tags metrics.Tags) metrics.Counter { return m }

func (m *mockGauge) Name() string                         { return "mock gauge" }
func (m *mockGauge) Description() string                  { return "mock gauge" }
func (m *mockGauge) Type() metrics.Type                   { return metrics.TypeGauge }
func (m *mockGauge) Tags() metrics.Tags                   { return metrics.Tags{} }
func (m *mockGauge) Set(float64)                          {}
func (m *mockGauge) Add(float64)                          {}
func (m *mockGauge) Inc()                                 {}
func (m *mockGauge) Dec()                                 {}
func (m *mockGauge) With(tags metrics.Tags) metrics.Gauge { return m }

func (m *mockHistogram) Name() string                             { return "mock histogram" }
func (m *mockHistogram) Description() string                      { return "mock histogram" }
func (m *mockHistogram) Type() metrics.Type                       { return metrics.TypeHistogram }
func (m *mockHistogram) Tags() metrics.Tags                       { return metrics.Tags{} }
func (m *mockHistogram) Record(float64)                           {}
func (m *mockHistogram) RecordSince(start time.Time)              {}
func (m *mockHistogram) Time(fn func()) time.Duration             { return time.Duration(0) }
func (m *mockHistogram) Observe(float64)                          {}
func (m *mockHistogram) With(tags metrics.Tags) metrics.Histogram { return m }

func (m *mockTimer) Name() string                         { return "mock timer" }
func (m *mockTimer) Description() string                  { return "mock timer" }
func (m *mockTimer) Type() metrics.Type                   { return metrics.TypeTimer }
func (m *mockTimer) Tags() metrics.Tags                   { return metrics.Tags{} }
func (m *mockTimer) Record(start time.Duration)           {}
func (m *mockTimer) RecordSince(start time.Time)          {}
func (m *mockTimer) Time(fn func()) time.Duration         { return time.Duration(0) }
func (m *mockTimer) With(tags metrics.Tags) metrics.Timer { return m }

// Mock Auth Manager Implementation
type mockAuthManager struct{}

func (m *mockAuthManager) RegisterProvider(provider auth.AuthenticationProvider) error {
	return nil
}

func (m *mockAuthManager) GetProvider(providerType auth.ProviderType) (auth.AuthenticationProvider, error) {
	// Return appropriate mock provider based on type
	switch providerType {
	case auth.ProviderTypePassword:
		return &mockPasswordProvider{}, nil
	default:
		return nil, errors.NewUnsupportedProviderError(string(providerType))
	}
}

func (m *mockAuthManager) Authenticate(ctx context.Context, req *auth.AuthenticationRequest) (*auth.AuthenticationResult, error) {
	return nil, nil
}

func (m *mockAuthManager) ValidateCredentials(ctx context.Context, providerType auth.ProviderType, credentials interface{}, userInfo *auth.UserInfo) error {
	// Simple validation - just check that credentials exist
	if credentials == nil {
		return errors.NewValidationError("credentials", "credentials required")
	}
	return nil
}

func (m *mockAuthManager) UpdateCredentials(ctx context.Context, req *auth.CredentialUpdateRequest) (interface{}, error) {
	// Simple mock - verify old credentials match and return new ones
	if req.ProviderType == auth.ProviderTypePassword {
		// Mock password verification
		if oldCreds, ok := req.OldCredentials.(*password.PasswordCredentials); ok {
			if oldCreds.Password == "StrongPass123!" { // Expected old password
				return req.NewCredentials, nil
			}
		}
		return nil, errors.NewInvalidCredentialsError()
	}
	return req.NewCredentials, nil
}

func (m *mockAuthManager) PrepareCredentials(ctx context.Context, providerType auth.ProviderType, credentials interface{}) (interface{}, error) {
	// Simple preparation - just return as-is for maps
	return credentials, nil
}

func (m *mockAuthManager) ListProviders() []auth.ProviderType {
	return []auth.ProviderType{auth.ProviderTypePassword}
}

func (m *mockAuthManager) HasProvider(providerType auth.ProviderType) bool {
	return providerType == auth.ProviderTypePassword
}

// Mock Password Provider Implementation
type mockPasswordProvider struct{}

func (m *mockPasswordProvider) Authenticate(ctx context.Context, identifier string, credentials interface{}) (*auth.AuthenticationResult, error) {
	// Check if credentials contain the correct password
	if creds, ok := credentials.(*password.PasswordCredentials); ok {
		if creds.Password == "StrongPass123!" {
			return &auth.AuthenticationResult{
				UserID:         "test-user-id",
				ProviderType:   auth.ProviderTypePassword,
				ProviderUserID: identifier,
			}, nil
		}
	}
	return nil, errors.NewInvalidCredentialsError()
}

func (m *mockPasswordProvider) ValidateCredentials(ctx context.Context, credentials interface{}, userInfo *auth.UserInfo) error {
	// Simple validation - just check that credentials exist
	if credentials == nil {
		return errors.NewValidationError("credentials", "credentials required")
	}
	return nil
}

func (m *mockPasswordProvider) UpdateCredentials(ctx context.Context, userID string, oldCredentials, newCredentials interface{}) (interface{}, error) {
	// Simple mock - just return new credentials
	return newCredentials, nil
}

func (m *mockPasswordProvider) PrepareCredentials(ctx context.Context, credentials interface{}) (interface{}, error) {
	// Simple preparation - just return as-is for maps
	return credentials, nil
}

func (m *mockPasswordProvider) GetProviderType() auth.ProviderType {
	return auth.ProviderTypePassword
}

func (m *mockPasswordProvider) SupportsCredentialUpdate() bool {
	return true
}

func createTestUserService() UserService {
	mockRepo := newMockRepository()
	mockEnc := &mockEncrypter{}
	mockLog := &mockLogger{}
	mockCach := newMockCache()
	mockConf := newMockConfig()
	mockMet := &mockMetrics{}
	mockAuth := &mockAuthManager{}

	return NewUserService(
		mockRepo,
		mockEnc,
		mockLog,
		mockCach,
		mockConf,
		mockMet,
		mockAuth,
	)
}

// Helper function to create a test service with customizable repository
func createTestUserServiceWithRepo(repo UserRepository) UserService {
	mockEnc := &mockEncrypter{}
	mockLog := &mockLogger{}
	mockCach := newMockCache()
	mockConf := newMockConfig()
	mockMet := &mockMetrics{}
	mockAuth := &mockAuthManager{}

	return NewUserService(
		repo,
		mockEnc,
		mockLog,
		mockCach,
		mockConf,
		mockMet,
		mockAuth,
	)
}

// Helper function to get the mock repository from a test service
func getMockRepository(service UserService) *mockRepository {
	if userSvc, ok := service.(*userService); ok {
		if mockRepo, ok := userSvc.repository.(*mockRepository); ok {
			return mockRepo
		}
	}
	return nil
}
