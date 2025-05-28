package user

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/MichaelAJay/go-cache"
	"github.com/MichaelAJay/go-config"
	"github.com/MichaelAJay/go-logger"
	"github.com/MichaelAJay/go-metrics"
	"github.com/MichaelAJay/go-user-management/auth"
	"github.com/MichaelAJay/go-user-management/errors"
)

// Mock implementations for testing
type mockRepository struct {
	users          map[string]*User
	usersByEmail   map[string]*User
	mu             sync.RWMutex
	createFunc     func(context.Context, *User) error
	getByIDFunc    func(context.Context, string) (*User, error)
	getByEmailFunc func(context.Context, string) (*User, error)
	updateFunc     func(context.Context, *User) error
	deleteFunc     func(context.Context, string) error
}

func newMockRepository() *mockRepository {
	return &mockRepository{
		users:        make(map[string]*User),
		usersByEmail: make(map[string]*User),
	}
}

func (m *mockRepository) Create(ctx context.Context, user *User) error {
	if m.createFunc != nil {
		return m.createFunc(ctx, user)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check for duplicate email
	if _, exists := m.usersByEmail[user.HashedEmail]; exists {
		return errors.NewDuplicateEmailError(user.HashedEmail)
	}

	m.users[user.ID] = user
	m.usersByEmail[user.HashedEmail] = user
	return nil
}

func (m *mockRepository) GetByHashedEmail(ctx context.Context, hashedEmail string) (*User, error) {
	if m.getByEmailFunc != nil {
		return m.getByEmailFunc(ctx, hashedEmail)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	user, exists := m.usersByEmail[hashedEmail]
	if !exists {
		return nil, errors.NewUserNotFoundError(hashedEmail)
	}
	return user, nil
}

func (m *mockRepository) GetByID(ctx context.Context, id string) (*User, error) {
	if m.getByIDFunc != nil {
		return m.getByIDFunc(ctx, id)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	user, exists := m.users[id]
	if !exists {
		return nil, errors.NewUserNotFoundError(id)
	}
	return user, nil
}

func (m *mockRepository) Update(ctx context.Context, user *User) error {
	if m.updateFunc != nil {
		return m.updateFunc(ctx, user)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.users[user.ID]; !exists {
		return errors.NewUserNotFoundError(user.ID)
	}

	user.Version++
	user.UpdatedAt = time.Now()
	m.users[user.ID] = user
	return nil
}

func (m *mockRepository) Delete(ctx context.Context, id string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, id)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	user, exists := m.users[id]
	if !exists {
		return errors.NewUserNotFoundError(id)
	}

	delete(m.users, id)
	delete(m.usersByEmail, user.HashedEmail)
	return nil
}

func (m *mockRepository) UpdateLoginAttempts(ctx context.Context, hashedEmail string, attempts int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, exists := m.usersByEmail[hashedEmail]
	if !exists {
		return errors.NewUserNotFoundError(hashedEmail)
	}

	user.LoginAttempts = attempts
	user.UpdatedAt = time.Now()
	return nil
}

func (m *mockRepository) ResetLoginAttempts(ctx context.Context, hashedEmail string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, exists := m.usersByEmail[hashedEmail]
	if !exists {
		return errors.NewUserNotFoundError(hashedEmail)
	}

	user.LoginAttempts = 0
	user.LockedUntil = nil
	user.UpdatedAt = time.Now()
	return nil
}

func (m *mockRepository) LockAccount(ctx context.Context, hashedEmail string, until *time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, exists := m.usersByEmail[hashedEmail]
	if !exists {
		return errors.NewUserNotFoundError(hashedEmail)
	}

	if until == nil {
		user.Status = UserStatusLocked
	} else {
		user.LockedUntil = until
	}
	user.UpdatedAt = time.Now()
	return nil
}

func (m *mockRepository) ListUsers(ctx context.Context, offset, limit int) ([]*User, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	users := make([]*User, 0, len(m.users))
	for _, user := range m.users {
		users = append(users, user)
	}

	total := int64(len(users))

	// Apply pagination
	start := offset
	end := offset + limit
	if start > len(users) {
		return []*User{}, total, nil
	}
	if end > len(users) {
		end = len(users)
	}

	return users[start:end], total, nil
}

func (m *mockRepository) GetUserStats(ctx context.Context) (*UserStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := &UserStats{
		TotalUsers: int64(len(m.users)),
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

// Mock implementations for other dependencies
type mockEncrypter struct{}

func (m *mockEncrypter) Encrypt(data []byte) ([]byte, error)             { return data, nil }
func (m *mockEncrypter) EncryptWithAAD(data, aad []byte) ([]byte, error) { return data, nil }
func (m *mockEncrypter) Decrypt(data []byte) ([]byte, error)             { return data, nil }
func (m *mockEncrypter) DecryptWithAAD(data, aad []byte) ([]byte, error) { return data, nil }
func (m *mockEncrypter) HashLookupData(data []byte) []byte               { return []byte("hashed_" + string(data)) }
func (m *mockEncrypter) HashPassword(password []byte) ([]byte, error) {
	return []byte("hashed_" + string(password)), nil
}
func (m *mockEncrypter) VerifyPassword(hashedPassword, password []byte) (bool, error) {
	return string(hashedPassword) == "hashed_"+string(password), nil
}

type mockLogger struct{}

func (m *mockLogger) Debug(msg string, fields ...logger.Field)      {}
func (m *mockLogger) Info(msg string, fields ...logger.Field)       {}
func (m *mockLogger) Warn(msg string, fields ...logger.Field)       {}
func (m *mockLogger) Error(msg string, fields ...logger.Field)      {}
func (m *mockLogger) Fatal(msg string, fields ...logger.Field)      {}
func (m *mockLogger) With(fields ...logger.Field) logger.Logger     { return m }
func (m *mockLogger) WithContext(ctx context.Context) logger.Logger { return m }

type mockCache struct {
	data map[string]interface{}
	mu   sync.RWMutex
}

func newMockCache() *mockCache {
	return &mockCache{
		data: make(map[string]interface{}),
	}
}

func (m *mockCache) Get(ctx context.Context, key string) (interface{}, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	val, exists := m.data[key]
	return val, exists, nil
}

func (m *mockCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = value
	return nil
}

func (m *mockCache) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func (m *mockCache) Clear(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = make(map[string]interface{})
	return nil
}

func (m *mockCache) Has(ctx context.Context, key string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.data[key]
	return exists
}

func (m *mockCache) GetKeys(ctx context.Context) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	keys := make([]string, 0, len(m.data))
	for k := range m.data {
		keys = append(keys, k)
	}
	return keys
}

func (m *mockCache) Close() error { return nil }

func (m *mockCache) GetMany(ctx context.Context, keys []string) (map[string]interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]interface{})
	for _, key := range keys {
		if val, exists := m.data[key]; exists {
			result[key] = val
		}
	}
	return result, nil
}

func (m *mockCache) SetMany(ctx context.Context, items map[string]interface{}, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range items {
		m.data[k] = v
	}
	return nil
}

func (m *mockCache) DeleteMany(ctx context.Context, keys []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
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
func (m *mockCache) GetMetrics() *cache.CacheMetricsSnapshot { return nil }

type mockConfig struct {
	values map[string]interface{}
}

func newMockConfig() *mockConfig {
	return &mockConfig{
		values: make(map[string]interface{}),
	}
}

func (c *mockConfig) Get(key string) (interface{}, bool) {
	val, ok := c.values[key]
	return val, ok
}

func (c *mockConfig) GetString(key string) (string, bool) {
	if val, ok := c.values[key]; ok {
		if str, ok := val.(string); ok {
			return str, true
		}
	}
	return "", false
}

func (c *mockConfig) GetInt(key string) (int, bool) {
	if val, ok := c.values[key]; ok {
		if i, ok := val.(int); ok {
			return i, true
		}
	}
	return 0, false
}

func (c *mockConfig) GetBool(key string) (bool, bool) {
	if val, ok := c.values[key]; ok {
		if b, ok := val.(bool); ok {
			return b, true
		}
	}
	return false, false
}

func (c *mockConfig) GetFloat(key string) (float64, bool) {
	if val, ok := c.values[key]; ok {
		if f, ok := val.(float64); ok {
			return f, true
		}
	}
	return 0.0, false
}

func (c *mockConfig) GetStringSlice(key string) ([]string, bool) {
	if val, ok := c.values[key]; ok {
		if slice, ok := val.([]string); ok {
			return slice, true
		}
	}
	return nil, false
}

func (c *mockConfig) Set(key string, value interface{}) error {
	c.values[key] = value
	return nil
}

func (c *mockConfig) Load(source config.Source) error { return nil }
func (c *mockConfig) Validate() error                 { return nil }

type mockMetrics struct{}

func (m *mockMetrics) Counter(opts metrics.Options) metrics.Counter     { return &mockCounter{} }
func (m *mockMetrics) Gauge(opts metrics.Options) metrics.Gauge         { return &mockGauge{} }
func (m *mockMetrics) Histogram(opts metrics.Options) metrics.Histogram { return &mockHistogram{} }
func (m *mockMetrics) Timer(opts metrics.Options) metrics.Timer         { return &mockTimer{} }
func (m *mockMetrics) Unregister(name string)                           {}
func (m *mockMetrics) Each(fn func(metrics.Metric))                     {}

type mockCounter struct{}

func (c *mockCounter) Inc()                                   {}
func (c *mockCounter) Add(value float64)                      {}
func (c *mockCounter) With(tags metrics.Tags) metrics.Counter { return c }
func (c *mockCounter) Name() string                           { return "test_counter" }
func (c *mockCounter) Description() string                    { return "" }
func (c *mockCounter) Type() metrics.Type                     { return metrics.TypeCounter }
func (c *mockCounter) Tags() metrics.Tags                     { return nil }

type mockGauge struct{}

func (g *mockGauge) Set(value float64)                    {}
func (g *mockGauge) Add(value float64)                    {}
func (g *mockGauge) Inc()                                 {}
func (g *mockGauge) Dec()                                 {}
func (g *mockGauge) With(tags metrics.Tags) metrics.Gauge { return g }
func (g *mockGauge) Name() string                         { return "test_gauge" }
func (g *mockGauge) Description() string                  { return "" }
func (g *mockGauge) Type() metrics.Type                   { return metrics.TypeGauge }
func (g *mockGauge) Tags() metrics.Tags                   { return nil }

type mockHistogram struct{}

func (h *mockHistogram) Observe(value float64)                    {}
func (h *mockHistogram) With(tags metrics.Tags) metrics.Histogram { return h }
func (h *mockHistogram) Name() string                             { return "test_histogram" }
func (h *mockHistogram) Description() string                      { return "" }
func (h *mockHistogram) Type() metrics.Type                       { return metrics.TypeHistogram }
func (h *mockHistogram) Tags() metrics.Tags                       { return nil }

type mockTimer struct{}

func (t *mockTimer) Record(d time.Duration)               {}
func (t *mockTimer) RecordSince(start time.Time)          {}
func (t *mockTimer) Time(fn func()) time.Duration         { fn(); return time.Millisecond }
func (t *mockTimer) With(tags metrics.Tags) metrics.Timer { return t }
func (t *mockTimer) Name() string                         { return "test_timer" }
func (t *mockTimer) Description() string                  { return "" }
func (t *mockTimer) Type() metrics.Type                   { return metrics.TypeTimer }
func (t *mockTimer) Tags() metrics.Tags                   { return nil }

func createTestUserService() UserService {
	authManager := auth.NewManager(&mockLogger{}, &mockMetrics{})

	return NewUserService(
		newMockRepository(),
		&mockEncrypter{},
		&mockLogger{},
		newMockCache(),
		newMockConfig(),
		&mockMetrics{},
		authManager,
	)
}

func TestNewUserService(t *testing.T) {
	service := createTestUserService()

	if service == nil {
		t.Fatal("NewUserService returned nil")
	}
}

func TestCreateUser_Success(t *testing.T) {
	service := createTestUserService()
	ctx := context.Background()

	req := &CreateUserRequest{
		FirstName:              "John",
		LastName:               "Doe",
		Email:                  "john.doe@example.com",
		AuthenticationProvider: auth.ProviderTypePassword,
		Credentials: map[string]interface{}{
			"password": "StrongPassword123!",
		},
	}

	response, err := service.CreateUser(ctx, req)

	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	if response == nil {
		t.Fatal("CreateUser response is nil")
	}

	if response.FirstName != req.FirstName {
		t.Errorf("Expected FirstName %s, got %s", req.FirstName, response.FirstName)
	}

	if response.Email != req.Email {
		t.Errorf("Expected Email %s, got %s", req.Email, response.Email)
	}

	if response.Status != UserStatusPendingVerification {
		t.Errorf("Expected Status %v, got %v", UserStatusPendingVerification, response.Status)
	}
}

func TestCreateUser_DuplicateEmail(t *testing.T) {
	service := createTestUserService()
	ctx := context.Background()

	req := &CreateUserRequest{
		FirstName:              "John",
		LastName:               "Doe",
		Email:                  "john.doe@example.com",
		AuthenticationProvider: auth.ProviderTypePassword,
		Credentials: map[string]interface{}{
			"password": "StrongPassword123!",
		},
	}

	// Create first user
	_, err := service.CreateUser(ctx, req)
	if err != nil {
		t.Fatalf("First CreateUser failed: %v", err)
	}

	// Try to create second user with same email
	_, err = service.CreateUser(ctx, req)
	if err == nil {
		t.Fatal("Expected error for duplicate email")
	}

	var duplicateErr *errors.AppError
	if !errors.As(err, &duplicateErr) || duplicateErr.Code != errors.CodeDuplicateEmail {
		t.Errorf("Expected duplicate email error, got %v", err)
	}
}

func TestCreateUser_Concurrency(t *testing.T) {
	service := createTestUserService()
	ctx := context.Background()

	const numGoroutines = 50

	var wg sync.WaitGroup
	errorsChan := make(chan error, numGoroutines)
	successes := make(chan *UserResponse, numGoroutines)

	// Test concurrent user creation with unique emails
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			req := &CreateUserRequest{
				FirstName:              fmt.Sprintf("User%d", id),
				LastName:               "Test",
				Email:                  fmt.Sprintf("user%d@example.com", id),
				AuthenticationProvider: auth.ProviderTypePassword,
				Credentials: map[string]interface{}{
					"password": "StrongPassword123!",
				},
			}

			response, err := service.CreateUser(ctx, req)
			if err != nil {
				errorsChan <- err
				return
			}

			successes <- response
		}(i)
	}

	wg.Wait()
	close(errorsChan)
	close(successes)

	// Check for any errors
	for err := range errorsChan {
		t.Errorf("Concurrent CreateUser error: %v", err)
	}

	// Verify all users were created successfully
	successCount := 0
	for range successes {
		successCount++
	}

	if successCount != numGoroutines {
		t.Errorf("Expected %d successful creations, got %d", numGoroutines, successCount)
	}
}

func TestGetUserByID_Success(t *testing.T) {
	service := createTestUserService()
	ctx := context.Background()

	// First create a user
	createReq := &CreateUserRequest{
		FirstName:              "John",
		LastName:               "Doe",
		Email:                  "john.doe@example.com",
		AuthenticationProvider: auth.ProviderTypePassword,
		Credentials: map[string]interface{}{
			"password": "StrongPassword123!",
		},
	}

	createResp, err := service.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Now get the user by ID
	getResp, err := service.GetUserByID(ctx, createResp.ID)
	if err != nil {
		t.Fatalf("GetUserByID failed: %v", err)
	}

	if getResp.ID != createResp.ID {
		t.Errorf("Expected ID %s, got %s", createResp.ID, getResp.ID)
	}

	if getResp.Email != createResp.Email {
		t.Errorf("Expected Email %s, got %s", createResp.Email, getResp.Email)
	}
}

func TestGetUserByID_NotFound(t *testing.T) {
	service := createTestUserService()
	ctx := context.Background()

	_, err := service.GetUserByID(ctx, "nonexistent-id")

	if err == nil {
		t.Fatal("Expected error for nonexistent user")
	}

	var notFoundErr *errors.AppError
	if !errors.As(err, &notFoundErr) || notFoundErr.Code != errors.CodeUserNotFound {
		t.Errorf("Expected user not found error, got %v", err)
	}
}

func TestGetUserByEmail_Success(t *testing.T) {
	service := createTestUserService()
	ctx := context.Background()

	// First create a user
	createReq := &CreateUserRequest{
		FirstName:              "John",
		LastName:               "Doe",
		Email:                  "john.doe@example.com",
		AuthenticationProvider: auth.ProviderTypePassword,
		Credentials: map[string]interface{}{
			"password": "StrongPassword123!",
		},
	}

	createResp, err := service.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Now get the user by email
	getResp, err := service.GetUserByEmail(ctx, createReq.Email)
	if err != nil {
		t.Fatalf("GetUserByEmail failed: %v", err)
	}

	if getResp.ID != createResp.ID {
		t.Errorf("Expected ID %s, got %s", createResp.ID, getResp.ID)
	}

	if getResp.Email != createResp.Email {
		t.Errorf("Expected Email %s, got %s", createResp.Email, getResp.Email)
	}
}

func TestUpdateProfile_Success(t *testing.T) {
	service := createTestUserService()
	ctx := context.Background()

	// First create a user
	createReq := &CreateUserRequest{
		FirstName:              "John",
		LastName:               "Doe",
		Email:                  "john.doe@example.com",
		AuthenticationProvider: auth.ProviderTypePassword,
		Credentials: map[string]interface{}{
			"password": "StrongPassword123!",
		},
	}

	createResp, err := service.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Update the profile
	updateReq := &UpdateProfileRequest{
		FirstName: stringPtr("Jane"),
		LastName:  stringPtr("Smith"),
	}

	updateResp, err := service.UpdateProfile(ctx, createResp.ID, updateReq)
	if err != nil {
		t.Fatalf("UpdateProfile failed: %v", err)
	}

	if updateResp.FirstName != "Jane" {
		t.Errorf("Expected FirstName 'Jane', got '%s'", updateResp.FirstName)
	}

	if updateResp.LastName != "Smith" {
		t.Errorf("Expected LastName 'Smith', got '%s'", updateResp.LastName)
	}
}

func TestListUsers_Success(t *testing.T) {
	service := createTestUserService()
	ctx := context.Background()

	// Create multiple users
	for i := 0; i < 5; i++ {
		req := &CreateUserRequest{
			FirstName:              fmt.Sprintf("User%d", i),
			LastName:               "Test",
			Email:                  fmt.Sprintf("user%d@example.com", i),
			AuthenticationProvider: auth.ProviderTypePassword,
			Credentials: map[string]interface{}{
				"password": "StrongPassword123!",
			},
		}

		_, err := service.CreateUser(ctx, req)
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}
	}

	// List users
	listReq := &ListUsersRequest{
		Offset: 0,
		Limit:  10,
	}

	listResp, err := service.ListUsers(ctx, listReq)
	if err != nil {
		t.Fatalf("ListUsers failed: %v", err)
	}

	if len(listResp.Users) != 5 {
		t.Errorf("Expected 5 users, got %d", len(listResp.Users))
	}

	if listResp.Total != 5 {
		t.Errorf("Expected total 5, got %d", listResp.Total)
	}
}

func TestGetUserStats_Success(t *testing.T) {
	service := createTestUserService()
	ctx := context.Background()

	// Create a user
	req := &CreateUserRequest{
		FirstName:              "John",
		LastName:               "Doe",
		Email:                  "john.doe@example.com",
		AuthenticationProvider: auth.ProviderTypePassword,
		Credentials: map[string]interface{}{
			"password": "StrongPassword123!",
		},
	}

	_, err := service.CreateUser(ctx, req)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Get stats
	stats, err := service.GetUserStats(ctx)
	if err != nil {
		t.Fatalf("GetUserStats failed: %v", err)
	}

	if stats.TotalUsers != 1 {
		t.Errorf("Expected TotalUsers 1, got %d", stats.TotalUsers)
	}

	if stats.PendingVerificationUsers != 1 {
		t.Errorf("Expected PendingVerificationUsers 1, got %d", stats.PendingVerificationUsers)
	}
}

func TestDeleteUser_Success(t *testing.T) {
	service := createTestUserService()
	ctx := context.Background()

	// First create a user
	createReq := &CreateUserRequest{
		FirstName:              "John",
		LastName:               "Doe",
		Email:                  "john.doe@example.com",
		AuthenticationProvider: auth.ProviderTypePassword,
		Credentials: map[string]interface{}{
			"password": "StrongPassword123!",
		},
	}

	createResp, err := service.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Delete the user
	err = service.DeleteUser(ctx, createResp.ID)
	if err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}

	// Verify user is deleted
	_, err = service.GetUserByID(ctx, createResp.ID)
	if err == nil {
		t.Fatal("Expected error when getting deleted user")
	}
}

// Benchmark tests for performance under load
func BenchmarkCreateUser(b *testing.B) {
	service := createTestUserService()
	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			req := &CreateUserRequest{
				FirstName:              fmt.Sprintf("User%d", i),
				LastName:               "Test",
				Email:                  fmt.Sprintf("user%d@example.com", i),
				AuthenticationProvider: auth.ProviderTypePassword,
				Credentials: map[string]interface{}{
					"password": "StrongPassword123!",
				},
			}

			_, err := service.CreateUser(ctx, req)
			if err != nil {
				b.Fatalf("CreateUser failed: %v", err)
			}
			i++
		}
	})
}

func BenchmarkGetUserByID(b *testing.B) {
	service := createTestUserService()
	ctx := context.Background()

	// Create a user first
	req := &CreateUserRequest{
		FirstName:              "John",
		LastName:               "Doe",
		Email:                  "john.doe@example.com",
		AuthenticationProvider: auth.ProviderTypePassword,
		Credentials: map[string]interface{}{
			"password": "StrongPassword123!",
		},
	}

	resp, err := service.CreateUser(ctx, req)
	if err != nil {
		b.Fatalf("CreateUser failed: %v", err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := service.GetUserByID(ctx, resp.ID)
			if err != nil {
				b.Fatalf("GetUserByID failed: %v", err)
			}
		}
	})
}

// Helper functions
func stringPtr(s string) *string {
	return &s
}
