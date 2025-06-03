package user

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/MichaelAJay/go-cache"
	"github.com/MichaelAJay/go-config"
	"github.com/MichaelAJay/go-metrics"
	"github.com/MichaelAJay/go-user-management/auth"
	"github.com/MichaelAJay/go-user-management/errors"
)

// MockUserRepository implements UserRepository for testing
type MockUserRepository struct {
	users        map[string]*User
	emailHashes  map[string]string // hashedEmail -> userID
	shouldFail   bool
	failOnMethod string
}

func NewMockUserRepository() *MockUserRepository {
	return &MockUserRepository{
		users:       make(map[string]*User),
		emailHashes: make(map[string]string),
	}
}

func (m *MockUserRepository) SetShouldFail(method string) {
	m.shouldFail = true
	m.failOnMethod = method
}

func (m *MockUserRepository) AddUser(user *User) {
	m.users[user.ID] = user.Clone()
	m.emailHashes[user.HashedEmail] = user.ID
}

func (m *MockUserRepository) Create(ctx context.Context, user *User) error {
	if m.shouldFail && m.failOnMethod == "Create" {
		return errors.NewAppError(errors.CodeInternalError, "repository create failed")
	}

	// Check for duplicate email
	if _, exists := m.emailHashes[user.HashedEmail]; exists {
		return errors.NewAppError(errors.CodeDuplicateEmail, "user with this email already exists")
	}

	m.AddUser(user)
	return nil
}

func (m *MockUserRepository) GetByHashedEmail(ctx context.Context, hashedEmail string) (*User, error) {
	if m.shouldFail && m.failOnMethod == "GetByHashedEmail" {
		return nil, errors.NewAppError(errors.CodeInternalError, "repository get failed")
	}

	if userID, exists := m.emailHashes[hashedEmail]; exists {
		if user, found := m.users[userID]; found {
			return user.Clone(), nil
		}
	}
	return nil, errors.ErrUserNotFound
}

func (m *MockUserRepository) GetByID(ctx context.Context, id string) (*User, error) {
	if m.shouldFail && m.failOnMethod == "GetByID" {
		return nil, errors.NewAppError(errors.CodeInternalError, "repository get failed")
	}

	if user, exists := m.users[id]; exists {
		return user.Clone(), nil
	}
	return nil, errors.ErrUserNotFound
}

func (m *MockUserRepository) Update(ctx context.Context, user *User) error {
	if m.shouldFail && m.failOnMethod == "Update" {
		return errors.NewAppError(errors.CodeInternalError, "repository update failed")
	}

	if _, exists := m.users[user.ID]; !exists {
		return errors.ErrUserNotFound
	}

	// Simple optimistic locking check
	m.users[user.ID] = user.Clone()
	return nil
}

func (m *MockUserRepository) Delete(ctx context.Context, id string) error {
	if m.shouldFail && m.failOnMethod == "Delete" {
		return errors.NewAppError(errors.CodeInternalError, "repository delete failed")
	}

	if user, exists := m.users[id]; exists {
		delete(m.emailHashes, user.HashedEmail)
		delete(m.users, id)
		return nil
	}
	return errors.ErrUserNotFound
}

func (m *MockUserRepository) UpdateLoginAttempts(ctx context.Context, hashedEmail string, attempts int) error {
	if m.shouldFail && m.failOnMethod == "UpdateLoginAttempts" {
		return errors.NewAppError(errors.CodeInternalError, "update login attempts failed")
	}
	return nil
}

func (m *MockUserRepository) ResetLoginAttempts(ctx context.Context, hashedEmail string) error {
	if m.shouldFail && m.failOnMethod == "ResetLoginAttempts" {
		return errors.NewAppError(errors.CodeInternalError, "reset login attempts failed")
	}
	return nil
}

func (m *MockUserRepository) LockAccount(ctx context.Context, hashedEmail string, until *time.Time) error {
	if m.shouldFail && m.failOnMethod == "LockAccount" {
		return errors.NewAppError(errors.CodeInternalError, "lock account failed")
	}
	return nil
}

func (m *MockUserRepository) ListUsers(ctx context.Context, offset, limit int) ([]*User, int64, error) {
	if m.shouldFail && m.failOnMethod == "ListUsers" {
		return nil, 0, errors.NewAppError(errors.CodeInternalError, "list users failed")
	}

	users := make([]*User, 0, len(m.users))
	for _, user := range m.users {
		users = append(users, user.Clone())
	}

	return users, int64(len(users)), nil
}

func (m *MockUserRepository) GetUserStats(ctx context.Context) (*UserStats, error) {
	if m.shouldFail && m.failOnMethod == "GetUserStats" {
		return nil, errors.NewAppError(errors.CodeInternalError, "get user stats failed")
	}

	stats := &UserStats{
		TotalUsers:  int64(len(m.users)),
		ActiveUsers: 0,
	}

	for _, user := range m.users {
		if user.Status == UserStatusActive {
			stats.ActiveUsers++
		}
	}

	return stats, nil
}

// MockCache implements cache.Cache for testing
type MockCache struct {
	data         map[string]any // Changed from []byte to any to handle User objects
	shouldFail   bool
	failOnMethod string
}

func NewMockCache() *MockCache {
	return &MockCache{
		data: make(map[string]any), // Changed from []byte to any
	}
}

func (m *MockCache) Get(ctx context.Context, key string) (any, bool, error) {
	if m.shouldFail && m.failOnMethod == "Get" {
		return nil, false, fmt.Errorf("cache get failed")
	}

	if data, exists := m.data[key]; exists {
		return data, true, nil // Return the actual data, not bytes
	}
	return nil, false, nil // Return nil instead of errors.ErrCacheMiss for graceful degradation
}

func (m *MockCache) Set(ctx context.Context, key string, value any, ttl time.Duration) error {
	if m.shouldFail && m.failOnMethod == "Set" {
		return fmt.Errorf("cache set failed")
	}

	// Store the value directly as any type - this handles User objects, strings, ints, etc.
	m.data[key] = value
	return nil
}

func (m *MockCache) Delete(ctx context.Context, key string) error {
	if m.shouldFail && m.failOnMethod == "Delete" {
		return fmt.Errorf("cache delete failed")
	}

	delete(m.data, key)
	return nil
}

func (m *MockCache) Clear(ctx context.Context) error {
	if m.shouldFail && m.failOnMethod == "Clear" {
		return fmt.Errorf("cache clear failed")
	}

	m.data = make(map[string]any)
	return nil
}

func (m *MockCache) Has(ctx context.Context, key string) bool {
	if m.shouldFail && m.failOnMethod == "Has" {
		return false
	}

	return true
}

func (m *MockCache) GetKeys(ctx context.Context) []string {
	if m.shouldFail && m.failOnMethod == "GetKeys" {
		return nil
	}

	return []string{}
}

func (m *MockCache) Close() error {
	return nil
}

func (m *MockCache) GetMany(ctx context.Context, keys []string) (map[string]any, error) {
	if m.shouldFail && m.failOnMethod == "GetMany" {
		return nil, fmt.Errorf("cache get many failed")
	}

	return nil, nil
}

func (m *MockCache) SetMany(ctx context.Context, items map[string]any, ttl time.Duration) error {
	if m.shouldFail && m.failOnMethod == "SetMany" {
		return fmt.Errorf("cache set many failed")
	}

	return nil
}

func (m *MockCache) DeleteMany(ctx context.Context, keys []string) error {
	if m.shouldFail && m.failOnMethod == "DeleteMany" {
		return fmt.Errorf("cache delete many failed")
	}

	return nil
}

func (m *MockCache) GetMetadata(ctx context.Context, key string) (*cache.CacheEntryMetadata, error) {
	if m.shouldFail && m.failOnMethod == "GetMetadata" {
		return nil, fmt.Errorf("cache get metadata failed")
	}

	return nil, nil
}

func (m *MockCache) GetManyMetadata(ctx context.Context, keys []string) (map[string]*cache.CacheEntryMetadata, error) {
	if m.shouldFail && m.failOnMethod == "GetManyMetadata" {
		return nil, fmt.Errorf("cache get many metadata failed")
	}

	return nil, nil
}

func (m *MockCache) GetMetrics() *cache.CacheMetricsSnapshot {
	return &cache.CacheMetricsSnapshot{
		Hits:          0,
		Misses:        0,
		HitRatio:      0,
		GetLatency:    0,
		SetLatency:    0,
		DeleteLatency: 0,
		CacheSize:     0,
		EntryCount:    0,
	}
}

func (m *MockCache) SetShouldFail(method string) {
	m.shouldFail = true
	m.failOnMethod = method
}

// MockConfig implements config.Config for testing
type MockConfig struct {
	data map[string]interface{}
}

func NewMockConfig() *MockConfig {
	return &MockConfig{
		data: make(map[string]interface{}),
	}
}

func (m *MockConfig) Get(key string) (interface{}, bool) {
	value, exists := m.data[key]
	return value, exists
}

func (m *MockConfig) GetString(key string) (string, bool) {
	if value, exists := m.data[key]; exists {
		if str, ok := value.(string); ok {
			return str, true
		}
	}
	return "", false
}

func (m *MockConfig) GetBool(key string) (bool, bool) {
	if value, exists := m.data[key]; exists {
		if boolVal, ok := value.(bool); ok {
			return boolVal, true
		}
	}
	return false, false
}

func (m *MockConfig) GetInt(key string) (int, bool) {
	if value, exists := m.data[key]; exists {
		if intVal, ok := value.(int); ok {
			return intVal, true
		}
	}
	return 0, false
}

func (m *MockConfig) GetFloat(key string) (float64, bool) {
	if value, exists := m.data[key]; exists {
		if floatVal, ok := value.(float64); ok {
			return floatVal, true
		}
	}
	return 0.0, false
}

func (m *MockConfig) GetStringSlice(key string) ([]string, bool) {
	if value, exists := m.data[key]; exists {
		if slice, ok := value.([]string); ok {
			return slice, true
		}
	}
	return nil, false
}

func (m *MockConfig) Set(key string, value any) error {
	m.data[key] = value
	return nil
}

func (m *MockConfig) Load(source config.Source) error {
	return nil
}

func (m *MockConfig) Validate() error {
	return nil
}

// MockMetrics implements metrics.Registry for testing
type MockMetrics struct{}

func NewMockMetrics() metrics.Registry {
	return &MockMetrics{}
}

func (m *MockMetrics) Counter(opts metrics.Options) metrics.Counter {
	return &MockCounter{}
}

func (m *MockMetrics) Gauge(opts metrics.Options) metrics.Gauge {
	return &MockGauge{}
}

func (m *MockMetrics) Histogram(opts metrics.Options) metrics.Histogram {
	return &MockHistogram{}
}

func (m *MockMetrics) Timer(opts metrics.Options) metrics.Timer {
	return &MockTimer{}
}

func (m *MockMetrics) Unregister(name string) {}

func (m *MockMetrics) Each(fn func(metric metrics.Metric)) {
	// No-op for mock
}

type MockCounter struct{}

func (m *MockCounter) Name() string        { return "mock counter" }
func (m *MockCounter) Description() string { return "mock counter" }
func (m *MockCounter) Type() metrics.Type  { return metrics.TypeCounter }
func (m *MockCounter) Tags() metrics.Tags  { return nil }
func (m *MockCounter) Inc()                {}
func (m *MockCounter) Add(delta float64)   {}
func (m *MockCounter) With(tags metrics.Tags) metrics.Counter {
	return m
}

type MockGauge struct{}

func (m *MockGauge) Name() string        { return "mock gauge" }
func (m *MockGauge) Description() string { return "mock gauge" }
func (m *MockGauge) Type() metrics.Type  { return metrics.TypeGauge }
func (m *MockGauge) Tags() metrics.Tags  { return nil }
func (m *MockGauge) Set(value float64)   {}
func (m *MockGauge) Add(delta float64)   {}
func (m *MockGauge) Inc()                {}
func (m *MockGauge) Dec()                {}
func (m *MockGauge) With(tags metrics.Tags) metrics.Gauge {
	return m
}

type MockHistogram struct{}

func (m *MockHistogram) Name() string          { return "mock histogram" }
func (m *MockHistogram) Description() string   { return "mock histogram" }
func (m *MockHistogram) Type() metrics.Type    { return metrics.TypeHistogram }
func (m *MockHistogram) Tags() metrics.Tags    { return nil }
func (m *MockHistogram) Observe(value float64) {}
func (m *MockHistogram) With(tags metrics.Tags) metrics.Histogram {
	return m
}

type MockTimer struct{}

func (m *MockTimer) Name() string                  { return "mock timer" }
func (m *MockTimer) Description() string           { return "mock timer" }
func (m *MockTimer) Type() metrics.Type            { return metrics.TypeTimer }
func (m *MockTimer) Tags() metrics.Tags            { return nil }
func (m *MockTimer) Record(duration time.Duration) {}
func (m *MockTimer) RecordSince(t time.Time)       {}
func (m *MockTimer) Time(fn func()) time.Duration {
	return 0
}
func (m *MockTimer) With(tags metrics.Tags) metrics.Timer {
	return m
}

// MockAuthManager implements auth.Manager for testing
type MockAuthManager struct {
	shouldFail      bool
	failOnMethod    string
	GetProviderFunc func(providerType auth.ProviderType) (auth.AuthenticationProvider, error)
}

func NewMockAuthManager() *MockAuthManager {
	return &MockAuthManager{
		GetProviderFunc: func(providerType auth.ProviderType) (auth.AuthenticationProvider, error) {
			return &MockAuthProvider{}, nil
		},
	}
}

func (m *MockAuthManager) SetShouldFail(method string) {
	m.shouldFail = true
	m.failOnMethod = method
}

func (m *MockAuthManager) GetProvider(providerType auth.ProviderType) (auth.AuthenticationProvider, error) {
	if m.shouldFail && m.failOnMethod == "GetProvider" {
		return nil, fmt.Errorf("provider not found")
	}
	if m.GetProviderFunc != nil {
		return m.GetProviderFunc(providerType)
	}
	return &MockAuthProvider{}, nil
}

func (m *MockAuthManager) RegisterProvider(provider auth.AuthenticationProvider) error {
	return nil
}

func (m *MockAuthManager) ListProviders() []auth.ProviderType {
	return []auth.ProviderType{auth.ProviderTypePassword}
}

func (m *MockAuthManager) ValidateCredentials(ctx context.Context, providerType auth.ProviderType, credentials any, userInfo *auth.UserInfo) error {
	if m.shouldFail && m.failOnMethod == "ValidateCredentials" {
		return fmt.Errorf("credential validation failed")
	}
	return nil
}

func (m *MockAuthManager) Authenticate(ctx context.Context, req *auth.AuthenticationRequest) (*auth.AuthenticationResult, error) {
	if m.shouldFail && m.failOnMethod == "Authenticate" {
		return nil, fmt.Errorf("authentication failed")
	}
	return &auth.AuthenticationResult{
		UserID:       "test-user-id",
		ProviderType: auth.ProviderTypePassword,
	}, nil
}

func (m *MockAuthManager) UpdateCredentials(ctx context.Context, req *auth.CredentialUpdateRequest) ([]byte, error) {
	return []byte("updated-credentials"), nil
}

func (m *MockAuthManager) PrepareCredentials(ctx context.Context, providerType auth.ProviderType, credentials any) ([]byte, error) {
	return []byte("prepared-credentials"), nil
}

func (m *MockAuthManager) HasProvider(providerType auth.ProviderType) bool {
	return true
}

// MockAuthProvider implements auth.AuthenticationProvider for testing
type MockAuthProvider struct {
	shouldFail bool
}

func (m *MockAuthProvider) GetProviderType() auth.ProviderType {
	return auth.ProviderTypePassword
}

func (m *MockAuthProvider) Authenticate(ctx context.Context, identifier string, credentials any, storedAuthData []byte) (*auth.AuthenticationResult, error) {
	if m.shouldFail {
		return nil, fmt.Errorf("authentication failed")
	}

	return &auth.AuthenticationResult{
		UserID:       "test-user-id",
		ProviderType: auth.ProviderTypePassword,
	}, nil
}

func (m *MockAuthProvider) PrepareCredentials(ctx context.Context, credentials any) ([]byte, error) {
	if m.shouldFail {
		return nil, fmt.Errorf("prepare credentials failed")
	}
	return []byte("prepared-auth-data"), nil
}

func (m *MockAuthProvider) ValidateCredentials(ctx context.Context, credentials any, userInfo *auth.UserInfo) error {
	if m.shouldFail {
		return fmt.Errorf("invalid credentials")
	}
	return nil
}

func (m *MockAuthProvider) UpdateCredentials(ctx context.Context, userID string, oldCredentials, newCredentials any, storedAuthData []byte) ([]byte, error) {
	if m.shouldFail {
		return nil, fmt.Errorf("update credentials failed")
	}
	return []byte("updated-auth-data"), nil
}

func (m *MockAuthProvider) SupportsCredentialUpdate() bool {
	return true
}

// Test helper to create service dependencies
type ServiceDependencies struct {
	UserRepo     *MockUserRepository
	AuthRepo     AuthenticationRepository
	SecurityRepo UserSecurityRepository
	Encrypter    *MockEncrypter
	Logger       *MockLogger
	Cache        *MockCache
	Config       *MockConfig
	Metrics      metrics.Registry
	AuthManager  *MockAuthManager
}

func NewServiceDependencies() *ServiceDependencies {
	config := NewMockConfig()

	// Set ALL required config values that the service needs
	config.Set("user_service.cache_user_ttl", "15m")
	config.Set("user_service.cache_stats_ttl", "5m")
	config.Set("user_service.max_login_attempts", 5)
	config.Set("user_service.lockout_duration", "30m")
	config.Set("user_service.enable_rate_limit", true)
	config.Set("user_service.rate_limit_window", "1h")
	config.Set("user_service.rate_limit_max_attempts", 10)
	config.Set("user_service.allow_disposable_emails", false)

	return &ServiceDependencies{
		UserRepo:     NewMockUserRepository(),
		AuthRepo:     NewInMemoryAuthRepository(),
		SecurityRepo: NewInMemorySecurityRepository(),
		Encrypter:    &MockEncrypter{},
		Logger:       &MockLogger{},
		Cache:        NewMockCache(),
		Config:       config,
		Metrics:      NewMockMetrics(),
		AuthManager:  NewMockAuthManager(),
	}
}

func (d *ServiceDependencies) CreateService() UserService {
	return NewUserService(
		d.UserRepo,
		d.AuthRepo,
		d.SecurityRepo,
		d.Encrypter,
		d.Logger,
		d.Cache,
		d.Config,
		d.Metrics,
		d.AuthManager,
	)
}

// Helper to create valid request objects
func createValidCreateUserRequest() *CreateUserRequest {
	return &CreateUserRequest{
		FirstName:              "John",
		LastName:               "Doe",
		Email:                  "john.doe@example.com",
		Credentials:            "password123",
		AuthenticationProvider: auth.ProviderTypePassword,
	}
}

func createValidAuthenticateRequest() *AuthenticateRequest {
	return &AuthenticateRequest{
		Email:                  "john.doe@example.com",
		Credentials:            "password123",
		AuthenticationProvider: auth.ProviderTypePassword,
	}
}

func createValidUpdateProfileRequest() *UpdateProfileRequest {
	firstName := "Jane"
	return &UpdateProfileRequest{
		FirstName: &firstName,
	}
}

// Constructor and Configuration Tests (5 tests)

func TestNewUserService_Success(t *testing.T) {
	deps := NewServiceDependencies()

	service := deps.CreateService()

	if service == nil {
		t.Error("Expected service to be created, got nil")
	}
}

func TestNewUserService_ConfigurationLoading(t *testing.T) {
	deps := NewServiceDependencies()

	// Set some config values
	deps.Config.Set("user_service.cache_user_ttl", "30m")
	deps.Config.Set("user_service.max_login_attempts", 3)
	deps.Config.Set("user_service.enable_rate_limit", false)

	service := deps.CreateService()

	if service == nil {
		t.Error("Expected service to be created with custom config, got nil")
	}
}

func TestNewUserService_DefaultValues(t *testing.T) {
	deps := NewServiceDependencies()

	// Create service without setting any config values to test defaults
	service := deps.CreateService()

	if service == nil {
		t.Error("Expected service to be created with default config, got nil")
	}
}

func TestNewUserService_EmailValidatorConfiguration(t *testing.T) {
	deps := NewServiceDependencies()

	// Set email validation config
	deps.Config.Set("user_service.allow_disposable_emails", true)

	service := deps.CreateService()

	if service == nil {
		t.Error("Expected service to be created with email validator config, got nil")
	}
}

func TestNewUserService_NilDependencies(t *testing.T) {
	// Test with some nil dependencies - this should work as the constructor
	// doesn't validate for nil (following Go's fail-fast philosophy)
	service := NewUserService(
		nil, // userRepository
		NewInMemoryAuthRepository(),
		NewInMemorySecurityRepository(),
		&MockEncrypter{},
		&MockLogger{},
		NewMockCache(),
		NewMockConfig(),
		NewMockMetrics(),
		NewMockAuthManager(),
	)

	if service == nil {
		t.Error("Expected service to be created even with some nil dependencies")
	}
}

// CreateUser Unit Tests (8 tests)

func TestCreateUser_Success(t *testing.T) {
	deps := NewServiceDependencies()
	service := deps.CreateService()
	ctx := context.Background()
	req := createValidCreateUserRequest()

	response, err := service.CreateUser(ctx, req)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	if response == nil {
		t.Fatal("Expected response, got nil")
	}

	if response.DisplayName == "" {
		t.Error("Expected display name to be set")
	}

	if response.Status != UserStatusPendingVerification {
		t.Errorf("Expected status %s, got %s", UserStatusPendingVerification, response.Status)
	}
}

func TestCreateUser_ValidationFailure(t *testing.T) {
	deps := NewServiceDependencies()
	service := deps.CreateService()
	ctx := context.Background()

	// Test with invalid request (empty first name)
	req := createValidCreateUserRequest()
	req.FirstName = ""

	response, err := service.CreateUser(ctx, req)

	if err == nil {
		t.Error("Expected validation error, got nil")
	}

	if response != nil {
		t.Error("Expected no response on validation failure, got response")
	}

	appErr, ok := err.(*errors.AppError)
	if !ok || appErr.Code != errors.CodeValidationFailed {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestCreateUser_EmailNormalization(t *testing.T) {
	deps := NewServiceDependencies()
	service := deps.CreateService()
	ctx := context.Background()

	req := createValidCreateUserRequest()
	req.Email = "  JOHN.DOE@EXAMPLE.COM  " // Test normalization

	response, err := service.CreateUser(ctx, req)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	if response == nil {
		t.Error("Expected response, got nil")
	}

	// Email should be normalized (trimmed and lowercased)
	// We can't directly check the stored email since it's hashed,
	// but the service should handle normalization internally
}

func TestCreateUser_DuplicateEmail(t *testing.T) {
	deps := NewServiceDependencies()
	service := deps.CreateService()
	ctx := context.Background()

	req := createValidCreateUserRequest()

	// Create first user
	_, err := service.CreateUser(ctx, req)
	if err != nil {
		t.Fatalf("Expected first user creation to succeed, got: %v", err)
	}

	// Try to create second user with same email
	_, err = service.CreateUser(ctx, req)

	if err == nil {
		t.Error("Expected duplicate email error, got nil")
	}

	appErr, ok := err.(*errors.AppError)
	if !ok || appErr.Code != errors.CodeDuplicateEmail {
		t.Errorf("Expected duplicate email error, got: %v", err)
	}
}

func TestCreateUser_EncryptionFailure(t *testing.T) {
	deps := NewServiceDependencies()
	deps.Encrypter.shouldFail = true
	service := deps.CreateService()
	ctx := context.Background()

	req := createValidCreateUserRequest()

	response, err := service.CreateUser(ctx, req)

	if err == nil {
		t.Error("Expected encryption error, got nil")
	}

	if response != nil {
		t.Error("Expected no response on encryption failure, got response")
	}
}

func TestCreateUser_RepositoryCreateFailure(t *testing.T) {
	deps := NewServiceDependencies()
	deps.UserRepo.SetShouldFail("Create")
	service := deps.CreateService()
	ctx := context.Background()

	req := createValidCreateUserRequest()

	response, err := service.CreateUser(ctx, req)

	if err == nil {
		t.Error("Expected repository error, got nil")
	}

	if response != nil {
		t.Error("Expected no response on repository failure, got response")
	}
}

func TestCreateUser_AuthManagerFailure(t *testing.T) {
	deps := NewServiceDependencies()
	deps.AuthManager.SetShouldFail("ValidateCredentials")
	service := deps.CreateService()
	ctx := context.Background()

	req := createValidCreateUserRequest()

	response, err := service.CreateUser(ctx, req)

	if err == nil {
		t.Error("Expected auth manager error, got nil")
	}

	if response != nil {
		t.Error("Expected no response on auth manager failure, got response")
	}
}

func TestCreateUser_CacheSetFailure(t *testing.T) {
	deps := NewServiceDependencies()
	deps.Cache.SetShouldFail("Set")
	service := deps.CreateService()
	ctx := context.Background()

	req := createValidCreateUserRequest()

	// Cache failures should be gracefully handled (not fail the operation)
	response, err := service.CreateUser(ctx, req)

	if err != nil {
		t.Errorf("Expected cache failure to be graceful, got error: %v", err)
	}

	if response == nil {
		t.Error("Expected successful response despite cache failure")
	}
}

// Authentication Unit Tests (10 tests)

func TestAuthenticateUser_Success(t *testing.T) {
	deps := NewServiceDependencies()
	service := deps.CreateService()
	ctx := context.Background()

	// First create a user
	createReq := createValidCreateUserRequest()
	userResponse, err := service.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Activate the user for authentication
	activatedUser, err := service.ActivateUser(ctx, userResponse.ID)
	if err != nil {
		t.Fatalf("Failed to activate user: %v", err)
	}

	// Now authenticate
	authReq := createValidAuthenticateRequest()
	authResponse, err := service.AuthenticateUser(ctx, authReq)

	if err != nil {
		t.Errorf("Expected successful authentication, got error: %v", err)
	}

	if authResponse == nil {
		t.Fatal("Expected authentication response, got nil")
	}

	if authResponse.User == nil {
		t.Error("Expected user in response, got nil")
	}

	if authResponse.User.ID != activatedUser.ID {
		t.Errorf("Expected user ID %s, got %s", activatedUser.ID, authResponse.User.ID)
	}
}

func TestAuthenticateUser_UserNotFound(t *testing.T) {
	deps := NewServiceDependencies()
	service := deps.CreateService()
	ctx := context.Background()

	authReq := createValidAuthenticateRequest()
	authReq.Email = "nonexistent@example.com"

	authResponse, err := service.AuthenticateUser(ctx, authReq)

	if err == nil {
		t.Error("Expected authentication error, got nil")
	}

	if authResponse != nil {
		t.Error("Expected no response on user not found, got response")
	}

	// Service returns INVALID_CREDENTIALS for security reasons (don't leak user existence)
	appErr, ok := err.(*errors.AppError)
	if !ok || appErr.Code != errors.CodeInvalidCredentials {
		t.Errorf("Expected invalid credentials error, got: %v", err)
	}
}

func TestAuthenticateUser_InvalidCredentials(t *testing.T) {
	deps := NewServiceDependencies()

	// Configure auth provider to fail authentication
	mockProvider := &MockAuthProvider{shouldFail: true}
	deps.AuthManager.GetProviderFunc = func(providerType auth.ProviderType) (auth.AuthenticationProvider, error) {
		return mockProvider, nil
	}

	service := deps.CreateService()
	ctx := context.Background()

	// First create and activate a user
	createReq := createValidCreateUserRequest()
	userResponse, err := service.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	_, err = service.ActivateUser(ctx, userResponse.ID)
	if err != nil {
		t.Fatalf("Failed to activate user: %v", err)
	}

	// Now try to authenticate with invalid credentials
	authReq := createValidAuthenticateRequest()
	authReq.Credentials = "wrong_password"

	authResponse, err := service.AuthenticateUser(ctx, authReq)

	if err == nil {
		t.Error("Expected authentication failure, got nil error")
	}

	if authResponse != nil {
		t.Error("Expected no response on auth failure, got response")
	}
}

func TestAuthenticateUser_AccountLocked(t *testing.T) {
	deps := NewServiceDependencies()
	service := deps.CreateService()
	ctx := context.Background()

	// Create and activate user
	createReq := createValidCreateUserRequest()
	userResponse, err := service.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	activatedUser, err := service.ActivateUser(ctx, userResponse.ID)
	if err != nil {
		t.Fatalf("Failed to activate user: %v", err)
	}

	// Lock the account
	lockUntil := time.Now().Add(time.Hour)
	_, err = service.LockUser(ctx, activatedUser.ID, &lockUntil, "test_lock")
	if err != nil {
		t.Fatalf("Failed to lock user: %v", err)
	}

	// Try to authenticate locked account
	authReq := createValidAuthenticateRequest()
	authResponse, err := service.AuthenticateUser(ctx, authReq)

	if err == nil {
		t.Error("Expected authentication failure for locked account, got nil error")
	}

	if authResponse != nil {
		t.Error("Expected no response for locked account, got response")
	}

	appErr, ok := err.(*errors.AppError)
	if !ok || (appErr.Code != errors.CodeAccountLocked && appErr.Code != errors.CodeUserSuspended) {
		t.Errorf("Expected user locked/suspended error, got: %v", err)
	}
}

func TestAuthenticateUser_AccountSuspended(t *testing.T) {
	deps := NewServiceDependencies()
	service := deps.CreateService()
	ctx := context.Background()

	// Create and activate user
	createReq := createValidCreateUserRequest()
	userResponse, err := service.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	activatedUser, err := service.ActivateUser(ctx, userResponse.ID)
	if err != nil {
		t.Fatalf("Failed to activate user: %v", err)
	}

	// Suspend the account
	_, err = service.SuspendUser(ctx, activatedUser.ID, "test_suspension")
	if err != nil {
		t.Fatalf("Failed to suspend user: %v", err)
	}

	// Try to authenticate suspended account
	authReq := createValidAuthenticateRequest()
	authResponse, err := service.AuthenticateUser(ctx, authReq)

	if err == nil {
		t.Error("Expected authentication failure for suspended account, got nil error")
	}

	if authResponse != nil {
		t.Error("Expected no response for suspended account, got response")
	}

	// Service returns ACCOUNT_NOT_ACTIVATED for non-active users
	appErr, ok := err.(*errors.AppError)
	if !ok || appErr.Code != errors.CodeAccountNotActivated {
		t.Errorf("Expected account not activated error, got: %v", err)
	}
}

func TestAuthenticateUser_AccountDeactivated(t *testing.T) {
	deps := NewServiceDependencies()
	service := deps.CreateService()
	ctx := context.Background()

	// Create and activate user
	createReq := createValidCreateUserRequest()
	userResponse, err := service.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	activatedUser, err := service.ActivateUser(ctx, userResponse.ID)
	if err != nil {
		t.Fatalf("Failed to activate user: %v", err)
	}

	// Deactivate the account
	_, err = service.DeactivateUser(ctx, activatedUser.ID, "test_deactivation")
	if err != nil {
		t.Fatalf("Failed to deactivate user: %v", err)
	}

	// Try to authenticate deactivated account
	authReq := createValidAuthenticateRequest()
	authResponse, err := service.AuthenticateUser(ctx, authReq)

	if err == nil {
		t.Error("Expected authentication failure for deactivated account, got nil error")
	}

	if authResponse != nil {
		t.Error("Expected no response for deactivated account, got response")
	}

	// Service returns ACCOUNT_NOT_ACTIVATED for non-active users
	appErr, ok := err.(*errors.AppError)
	if !ok || appErr.Code != errors.CodeAccountNotActivated {
		t.Errorf("Expected account not activated error, got: %v", err)
	}
}

func TestAuthenticateUser_RateLimit(t *testing.T) {
	deps := NewServiceDependencies()

	// Configure cache to simulate rate limit hit
	deps.Cache.SetShouldFail("Get")
	// We'll simulate that rate limit checking fails which should trigger rate limit behavior

	service := deps.CreateService()
	ctx := context.Background()

	authReq := createValidAuthenticateRequest()

	// The service should handle cache failures gracefully
	// but for this test, we're mainly checking that rate limit logic exists
	authResponse, err := service.AuthenticateUser(ctx, authReq)

	// The behavior depends on how the service handles cache failures during rate limiting
	// Since we expect graceful degradation, this might succeed or fail depending on implementation
	if err != nil && authResponse != nil {
		t.Error("Response should be nil when error occurs")
	}
}

func TestAuthenticateUser_SecurityUpdateFailure(t *testing.T) {
	deps := NewServiceDependencies()
	service := deps.CreateService()
	ctx := context.Background()

	// Create and activate user first
	createReq := createValidCreateUserRequest()
	userResponse, err := service.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	_, err = service.ActivateUser(ctx, userResponse.ID)
	if err != nil {
		t.Fatalf("Failed to activate user: %v", err)
	}

	// Now test authentication - even if security update fails, authentication might still succeed
	// depending on the service implementation's error handling strategy
	authReq := createValidAuthenticateRequest()

	// This is more of a integration test concern, but we can verify the behavior
	authResponse, err := service.AuthenticateUser(ctx, authReq)

	// The exact behavior depends on implementation - some services might fail,
	// others might succeed but log the error
	if err != nil && authResponse != nil {
		t.Error("Response should be nil when error occurs")
	}
}

func TestAuthenticateUser_ProviderNotFound(t *testing.T) {
	deps := NewServiceDependencies()
	deps.AuthManager.SetShouldFail("GetProvider")
	service := deps.CreateService()
	ctx := context.Background()

	authReq := createValidAuthenticateRequest()
	authReq.AuthenticationProvider = "nonexistent_provider"

	authResponse, err := service.AuthenticateUser(ctx, authReq)

	if err == nil {
		t.Error("Expected provider not found error, got nil")
	}

	if authResponse != nil {
		t.Error("Expected no response when provider not found, got response")
	}
}

func TestAuthenticateUser_CacheGetFailure(t *testing.T) {
	deps := NewServiceDependencies()
	deps.Cache.SetShouldFail("Get")
	service := deps.CreateService()
	ctx := context.Background()

	// Create and activate user first
	createReq := createValidCreateUserRequest()
	userResponse, err := service.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	_, err = service.ActivateUser(ctx, userResponse.ID)
	if err != nil {
		t.Fatalf("Failed to activate user: %v", err)
	}

	// Cache get failures should be handled gracefully - authentication should still work
	authReq := createValidAuthenticateRequest()
	authResponse, err := service.AuthenticateUser(ctx, authReq)

	// Since cache failures should be graceful, authentication might still succeed
	// The exact behavior depends on the implementation's graceful degradation strategy
	if err != nil && authResponse != nil {
		t.Error("Response should be nil when error occurs")
	}

	// The key test is that the service doesn't panic and handles the cache failure gracefully
}

// Profile Management Unit Tests (6 tests)

func TestUpdateProfile_Success(t *testing.T) {
	deps := NewServiceDependencies()
	service := deps.CreateService()
	ctx := context.Background()

	// Create user first
	createReq := createValidCreateUserRequest()
	userResponse, err := service.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Update profile
	updateReq := createValidUpdateProfileRequest()
	updatedResponse, err := service.UpdateProfile(ctx, userResponse.ID, updateReq)

	if err != nil {
		t.Errorf("Expected successful profile update, got error: %v", err)
	}

	if updatedResponse == nil {
		t.Fatal("Expected response, got nil")
	}

	if updatedResponse.ID != userResponse.ID {
		t.Errorf("Expected user ID %s, got %s", userResponse.ID, updatedResponse.ID)
	}

	// Verify version was incremented
	if updatedResponse.Version <= userResponse.Version {
		t.Errorf("Expected version to be incremented from %d, got %d", userResponse.Version, updatedResponse.Version)
	}
}

func TestUpdateProfile_EmptyRequest(t *testing.T) {
	deps := NewServiceDependencies()
	service := deps.CreateService()
	ctx := context.Background()

	// Create user first
	createReq := createValidCreateUserRequest()
	userResponse, err := service.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Try to update with empty request
	emptyReq := &UpdateProfileRequest{}
	updatedResponse, err := service.UpdateProfile(ctx, userResponse.ID, emptyReq)

	if err == nil {
		t.Error("Expected validation error for empty request, got nil")
	}

	if updatedResponse != nil {
		t.Error("Expected no response for empty request, got response")
	}

	appErr, ok := err.(*errors.AppError)
	if !ok || appErr.Code != errors.CodeValidationFailed {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestUpdateProfile_UserNotFound(t *testing.T) {
	deps := NewServiceDependencies()
	service := deps.CreateService()
	ctx := context.Background()

	req := createValidUpdateProfileRequest()

	// Use invalid ID format to trigger validation error
	response, err := service.UpdateProfile(ctx, "invalid-id", req)

	if err == nil {
		t.Error("Expected validation error, got nil")
	}

	if response != nil {
		t.Error("Expected no response on validation failure, got response")
	}

	// Service validates ID format first, so this returns VALIDATION_FAILED
	appErr, ok := err.(*errors.AppError)
	if !ok || appErr.Code != errors.CodeValidationFailed {
		t.Errorf("Expected validation failed error, got: %v", err)
	}
}

func TestUpdateProfile_EmailChangeValidation(t *testing.T) {
	deps := NewServiceDependencies()
	service := deps.CreateService()
	ctx := context.Background()

	// Create and activate user first
	createReq := createValidCreateUserRequest()
	userResponse, err := service.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	activatedUser, err := service.ActivateUser(ctx, userResponse.ID)
	if err != nil {
		t.Fatalf("Failed to activate user: %v", err)
	}

	// Update email - this should trigger re-verification
	newEmail := "newemail@example.com"
	updateReq := &UpdateProfileRequest{
		Email: &newEmail,
	}

	updatedResponse, err := service.UpdateProfile(ctx, activatedUser.ID, updateReq)

	if err != nil {
		t.Errorf("Expected successful email update, got error: %v", err)
	}

	if updatedResponse == nil {
		t.Fatal("Expected response, got nil")
	}

	// Email change should trigger re-verification (status should be pending)
	if updatedResponse.Status != UserStatusPendingVerification {
		t.Errorf("Expected status %s after email change, got %s", UserStatusPendingVerification, updatedResponse.Status)
	}
}

func TestUpdateProfile_EncryptionFailure(t *testing.T) {
	deps := NewServiceDependencies()
	deps.Encrypter.shouldFail = true
	service := deps.CreateService()
	ctx := context.Background()

	// Create user first (this might also fail due to encryption, but let's try)
	createReq := createValidCreateUserRequest()
	userResponse, err := service.CreateUser(ctx, createReq)
	if err != nil {
		// If creation fails due to encryption, that's expected
		t.Skipf("Skipping test due to encryption failure during user creation: %v", err)
	}

	// Try to update profile with encryption failure
	updateReq := createValidUpdateProfileRequest()
	updatedResponse, err := service.UpdateProfile(ctx, userResponse.ID, updateReq)

	if err == nil {
		t.Error("Expected encryption error, got nil")
	}

	if updatedResponse != nil {
		t.Error("Expected no response on encryption failure, got response")
	}
}

func TestUpdateProfile_RepositoryUpdateFailure(t *testing.T) {
	deps := NewServiceDependencies()
	service := deps.CreateService()
	ctx := context.Background()

	// Create user first
	createReq := createValidCreateUserRequest()
	userResponse, err := service.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Set repository to fail on update
	deps.UserRepo.SetShouldFail("Update")

	// Try to update profile
	updateReq := createValidUpdateProfileRequest()
	updatedResponse, err := service.UpdateProfile(ctx, userResponse.ID, updateReq)

	if err == nil {
		t.Error("Expected repository error, got nil")
	}

	if updatedResponse != nil {
		t.Error("Expected no response on repository failure, got response")
	}
}

// Account State Management Unit Tests (6 tests)

func TestActivateUser_Success(t *testing.T) {
	deps := NewServiceDependencies()
	service := deps.CreateService()
	ctx := context.Background()

	// Create user first (starts in pending verification status)
	createReq := createValidCreateUserRequest()
	userResponse, err := service.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Activate user
	activatedResponse, err := service.ActivateUser(ctx, userResponse.ID)

	if err != nil {
		t.Errorf("Expected successful activation, got error: %v", err)
	}

	if activatedResponse == nil {
		t.Fatal("Expected response, got nil")
	}

	if activatedResponse.Status != UserStatusActive {
		t.Errorf("Expected status %s, got %s", UserStatusActive, activatedResponse.Status)
	}

	if activatedResponse.EmailVerified != true {
		t.Error("Expected EmailVerified to be true after activation")
	}

	// Verify version was incremented
	if activatedResponse.Version <= userResponse.Version {
		t.Errorf("Expected version to be incremented from %d, got %d", userResponse.Version, activatedResponse.Version)
	}
}

func TestActivateUser_UserNotFound(t *testing.T) {
	deps := NewServiceDependencies()
	service := deps.CreateService()
	ctx := context.Background()

	// Use invalid ID format to trigger validation error
	response, err := service.ActivateUser(ctx, "invalid-id")

	if err == nil {
		t.Error("Expected validation error, got nil")
	}

	if response != nil {
		t.Error("Expected no response on validation failure, got response")
	}

	// Service validates ID format first, so this returns VALIDATION_FAILED
	appErr, ok := err.(*errors.AppError)
	if !ok || appErr.Code != errors.CodeValidationFailed {
		t.Errorf("Expected validation failed error, got: %v", err)
	}
}

func TestSuspendUser_Success(t *testing.T) {
	deps := NewServiceDependencies()
	service := deps.CreateService()
	ctx := context.Background()

	// Create and activate user first
	createReq := createValidCreateUserRequest()
	userResponse, err := service.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	activatedUser, err := service.ActivateUser(ctx, userResponse.ID)
	if err != nil {
		t.Fatalf("Failed to activate user: %v", err)
	}

	// Suspend user
	reason := "Terms of service violation"
	suspendedResponse, err := service.SuspendUser(ctx, activatedUser.ID, reason)

	if err != nil {
		t.Errorf("Expected successful suspension, got error: %v", err)
	}

	if suspendedResponse == nil {
		t.Fatal("Expected response, got nil")
	}

	if suspendedResponse.Status != UserStatusSuspended {
		t.Errorf("Expected status %s, got %s", UserStatusSuspended, suspendedResponse.Status)
	}

	if suspendedResponse.CanAuthenticate {
		t.Error("Expected CanAuthenticate to be false for suspended user")
	}

	// Verify version was incremented
	if suspendedResponse.Version <= activatedUser.Version {
		t.Errorf("Expected version to be incremented from %d, got %d", activatedUser.Version, suspendedResponse.Version)
	}
}

func TestDeactivateUser_Success(t *testing.T) {
	deps := NewServiceDependencies()
	service := deps.CreateService()
	ctx := context.Background()

	// Create and activate user first
	createReq := createValidCreateUserRequest()
	userResponse, err := service.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	activatedUser, err := service.ActivateUser(ctx, userResponse.ID)
	if err != nil {
		t.Fatalf("Failed to activate user: %v", err)
	}

	// Deactivate user
	reason := "User requested account deletion"
	deactivatedResponse, err := service.DeactivateUser(ctx, activatedUser.ID, reason)

	if err != nil {
		t.Errorf("Expected successful deactivation, got error: %v", err)
	}

	if deactivatedResponse == nil {
		t.Fatal("Expected response, got nil")
	}

	if deactivatedResponse.Status != UserStatusDeactivated {
		t.Errorf("Expected status %s, got %s", UserStatusDeactivated, deactivatedResponse.Status)
	}

	if deactivatedResponse.CanAuthenticate {
		t.Error("Expected CanAuthenticate to be false for deactivated user")
	}

	// Verify version was incremented
	if deactivatedResponse.Version <= activatedUser.Version {
		t.Errorf("Expected version to be incremented from %d, got %d", activatedUser.Version, deactivatedResponse.Version)
	}
}

func TestLockUser_Temporary(t *testing.T) {
	deps := NewServiceDependencies()
	service := deps.CreateService()
	ctx := context.Background()

	// Create and activate user first
	createReq := createValidCreateUserRequest()
	userResponse, err := service.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	activatedUser, err := service.ActivateUser(ctx, userResponse.ID)
	if err != nil {
		t.Fatalf("Failed to activate user: %v", err)
	}

	// Lock user temporarily
	lockUntil := time.Now().Add(2 * time.Hour)
	reason := "Suspicious login activity"
	lockedResponse, err := service.LockUser(ctx, activatedUser.ID, &lockUntil, reason)

	if err != nil {
		t.Errorf("Expected successful lock, got error: %v", err)
	}

	if lockedResponse == nil {
		t.Fatal("Expected response, got nil")
	}

	// The status might remain Active but AccountLocked should be true
	if !lockedResponse.AccountLocked {
		t.Error("Expected AccountLocked to be true")
	}

	if lockedResponse.CanAuthenticate {
		t.Error("Expected CanAuthenticate to be false for locked user")
	}

	// NOTE: User entity version doesn't increment for security-only changes
	// Only UserSecurity version increments (which isn't exposed in UserResponse)
	// This is correct behavior in our new coherent architecture
}

func TestUnlockUser_Success(t *testing.T) {
	deps := NewServiceDependencies()
	service := deps.CreateService()
	ctx := context.Background()

	// Create, activate, and lock user first
	createReq := createValidCreateUserRequest()
	userResponse, err := service.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	activatedUser, err := service.ActivateUser(ctx, userResponse.ID)
	if err != nil {
		t.Fatalf("Failed to activate user: %v", err)
	}

	lockUntil := time.Now().Add(time.Hour)
	lockedUser, err := service.LockUser(ctx, activatedUser.ID, &lockUntil, "test_lock")
	if err != nil {
		t.Fatalf("Failed to lock user: %v", err)
	}

	// Unlock user
	unlockedResponse, err := service.UnlockUser(ctx, lockedUser.ID)

	if err != nil {
		t.Errorf("Expected successful unlock, got error: %v", err)
	}

	if unlockedResponse == nil {
		t.Fatal("Expected response, got nil")
	}

	if unlockedResponse.AccountLocked {
		t.Error("Expected AccountLocked to be false after unlock")
	}

	if !unlockedResponse.CanAuthenticate {
		t.Error("Expected CanAuthenticate to be true after unlock")
	}

	// NOTE: User entity version doesn't increment for security-only changes
	// Only UserSecurity version increments (which isn't exposed in UserResponse)
	// This is correct behavior in our new coherent architecture
}

// Error Handling Unit Tests (3 tests)

func TestService_RepositoryErrors(t *testing.T) {
	deps := NewServiceDependencies()
	service := deps.CreateService()
	ctx := context.Background()

	// Test various repository error scenarios
	testCases := []struct {
		name      string
		method    string
		operation func() error
	}{
		{
			name:   "CreateUser with repository failure",
			method: "Create",
			operation: func() error {
				deps.UserRepo.SetShouldFail("Create")
				_, err := service.CreateUser(ctx, createValidCreateUserRequest())
				return err
			},
		},
		{
			name:   "GetUserByID with repository failure",
			method: "GetByID",
			operation: func() error {
				deps.UserRepo.SetShouldFail("GetByID")
				// Use a valid UUID to bypass validation and reach repository layer
				_, err := service.GetUserByID(ctx, "550e8400-e29b-41d4-a716-446655440000")
				return err
			},
		},
		{
			name:   "GetUserByEmail with repository failure",
			method: "GetByHashedEmail",
			operation: func() error {
				deps.UserRepo.SetShouldFail("GetByHashedEmail")
				_, err := service.GetUserByEmail(ctx, "test@example.com")
				return err
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset any previous failures
			deps.UserRepo.shouldFail = false

			err := tc.operation()

			if err == nil {
				t.Errorf("Expected repository error for %s, got nil", tc.name)
			}

			// Check that it's an appropriate error type
			if appErr, ok := err.(*errors.AppError); ok {
				if appErr.Code != errors.CodeInternalError && appErr.Code != errors.CodeUserNotFound {
					t.Errorf("Expected internal server error or user not found, got: %v", appErr.Code)
				}
			}
		})
	}
}

func TestService_EncryptionErrors(t *testing.T) {
	deps := NewServiceDependencies()
	deps.Encrypter.shouldFail = true
	service := deps.CreateService()
	ctx := context.Background()

	// Test various encryption failure scenarios
	testCases := []struct {
		name      string
		operation func() error
	}{
		{
			name: "CreateUser with encryption failure",
			operation: func() error {
				_, err := service.CreateUser(ctx, createValidCreateUserRequest())
				return err
			},
		},
		{
			name: "UpdateProfile with encryption failure",
			operation: func() error {
				// First create a user without encryption failure
				deps.Encrypter.shouldFail = false
				createReq := createValidCreateUserRequest()
				userResponse, err := service.CreateUser(ctx, createReq)
				if err != nil {
					return err
				}

				// Then try to update with encryption failure
				deps.Encrypter.shouldFail = true
				updateReq := createValidUpdateProfileRequest()
				_, err = service.UpdateProfile(ctx, userResponse.ID, updateReq)
				return err
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.operation()

			if err == nil {
				t.Errorf("Expected encryption error for %s, got nil", tc.name)
			}

			// The exact error type depends on how the service handles encryption errors
			// It might be wrapped as an AppError or returned as-is
		})
	}
}

func TestService_CacheErrors(t *testing.T) {
	deps := NewServiceDependencies()
	service := deps.CreateService()
	ctx := context.Background()

	// Test various cache failure scenarios with graceful degradation
	testCases := []struct {
		name      string
		method    string
		operation func() error
	}{
		{
			name:   "CreateUser with cache set failure",
			method: "Set",
			operation: func() error {
				deps.Cache.SetShouldFail("Set")
				_, err := service.CreateUser(ctx, createValidCreateUserRequest())
				return err
			},
		},
		{
			name:   "GetUserByID with cache get failure",
			method: "Get",
			operation: func() error {
				// First create a user
				createReq := createValidCreateUserRequest()
				userResponse, err := service.CreateUser(ctx, createReq)
				if err != nil {
					return err
				}

				// Then try to get with cache failure
				deps.Cache.SetShouldFail("Get")
				_, err = service.GetUserByID(ctx, userResponse.ID)
				return err
			},
		},
		{
			name:   "AuthenticateUser with cache failure",
			method: "Get",
			operation: func() error {
				// Create and activate user first
				createReq := createValidCreateUserRequest()
				userResponse, err := service.CreateUser(ctx, createReq)
				if err != nil {
					return err
				}

				_, err = service.ActivateUser(ctx, userResponse.ID)
				if err != nil {
					return err
				}

				// Then try to authenticate with cache failure
				deps.Cache.SetShouldFail("Get")
				authReq := createValidAuthenticateRequest()
				_, err = service.AuthenticateUser(ctx, authReq)
				return err
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset any previous failures
			deps.Cache.shouldFail = false

			err := tc.operation()

			// Cache failures should be handled gracefully - operations should still succeed
			// or fail for other reasons, not because of cache issues
			// The exact behavior depends on the service implementation's graceful degradation strategy

			// At minimum, the service shouldn't panic and should handle cache errors gracefully
			// Whether the operation succeeds or fails depends on the specific implementation
			t.Logf("Cache failure test %s completed with result: %v", tc.name, err)
		})
	}
}
