package password

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/MichaelAJay/go-config"
	"github.com/MichaelAJay/go-logger"
	"github.com/MichaelAJay/go-metrics"
	"github.com/MichaelAJay/go-user-management/auth"
	apperrors "github.com/MichaelAJay/go-user-management/errors"
)

// Mock implementations for testing
type mockEncrypter struct {
	hashPasswordFunc   func([]byte) ([]byte, error)
	verifyPasswordFunc func([]byte, []byte) (bool, error)
}

func (m *mockEncrypter) Encrypt(data []byte) ([]byte, error)             { return data, nil }
func (m *mockEncrypter) EncryptWithAAD(data, aad []byte) ([]byte, error) { return data, nil }
func (m *mockEncrypter) Decrypt(data []byte) ([]byte, error)             { return data, nil }
func (m *mockEncrypter) DecryptWithAAD(data, aad []byte) ([]byte, error) { return data, nil }
func (m *mockEncrypter) HashLookupData(data []byte) []byte               { return data }
func (m *mockEncrypter) HashPassword(password []byte) ([]byte, error) {
	if m.hashPasswordFunc != nil {
		return m.hashPasswordFunc(password)
	}
	return []byte("hashed_" + string(password)), nil
}
func (m *mockEncrypter) VerifyPassword(hashedPassword, password []byte) (bool, error) {
	if m.verifyPasswordFunc != nil {
		return m.verifyPasswordFunc(hashedPassword, password)
	}
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

type mockMetrics struct {
	counters map[string]int64
	timers   map[string][]time.Duration
	mu       sync.RWMutex
}

func newMockMetrics() *mockMetrics {
	return &mockMetrics{
		counters: make(map[string]int64),
		timers:   make(map[string][]time.Duration),
	}
}

func (m *mockMetrics) Counter(opts metrics.Options) metrics.Counter {
	return &mockCounter{metrics: m, name: "test_counter"}
}

func (m *mockMetrics) Gauge(opts metrics.Options) metrics.Gauge         { return &mockGauge{} }
func (m *mockMetrics) Histogram(opts metrics.Options) metrics.Histogram { return &mockHistogram{} }
func (m *mockMetrics) Timer(opts metrics.Options) metrics.Timer {
	return &mockTimer{metrics: m, name: "test_timer"}
}
func (m *mockMetrics) Unregister(name string)       {}
func (m *mockMetrics) Each(fn func(metrics.Metric)) {}

type mockCounter struct {
	metrics *mockMetrics
	name    string
}

func (c *mockCounter) Inc() {
	c.metrics.mu.Lock()
	defer c.metrics.mu.Unlock()
	c.metrics.counters[c.name]++
}

func (c *mockCounter) Add(value float64) {
	c.metrics.mu.Lock()
	defer c.metrics.mu.Unlock()
	c.metrics.counters[c.name] += int64(value)
}

func (c *mockCounter) With(tags metrics.Tags) metrics.Counter { return c }
func (c *mockCounter) Name() string                           { return c.name }
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

type mockTimer struct {
	metrics *mockMetrics
	name    string
}

func (t *mockTimer) Record(d time.Duration) {
	t.metrics.mu.Lock()
	defer t.metrics.mu.Unlock()
	t.metrics.timers[t.name] = append(t.metrics.timers[t.name], d)
}

func (t *mockTimer) RecordSince(start time.Time) {
	t.Record(time.Since(start))
}

func (t *mockTimer) Time(fn func()) time.Duration {
	start := time.Now()
	fn()
	duration := time.Since(start)
	t.Record(duration)
	return duration
}

func (t *mockTimer) With(tags metrics.Tags) metrics.Timer { return t }
func (t *mockTimer) Name() string                         { return t.name }
func (t *mockTimer) Description() string                  { return "" }
func (t *mockTimer) Type() metrics.Type                   { return metrics.TypeTimer }
func (t *mockTimer) Tags() metrics.Tags                   { return nil }

type mockConfig struct {
	values map[string]any
}

func newMockConfig() *mockConfig {
	return &mockConfig{
		values: make(map[string]any),
	}
}

func (c *mockConfig) Get(key string) (any, bool) {
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

func (c *mockConfig) Set(key string, value any) error {
	c.values[key] = value
	return nil
}

func (c *mockConfig) Load(source config.Source) error { return nil }
func (c *mockConfig) Validate() error                 { return nil }

func createTestProvider() *Provider {
	return NewProvider(
		&mockEncrypter{},
		&mockLogger{},
		newMockMetrics(),
		newMockConfig(),
	)
}

func TestNewProvider(t *testing.T) {
	provider := createTestProvider()

	if provider == nil {
		t.Fatal("NewProvider returned nil")
	}

	if provider.encrypter == nil {
		t.Error("Provider encrypter is nil")
	}

	if provider.logger == nil {
		t.Error("Provider logger is nil")
	}

	if provider.metrics == nil {
		t.Error("Provider metrics is nil")
	}

	if provider.config == nil {
		t.Error("Provider config is nil")
	}

	if provider.passwordValidator == nil {
		t.Error("Provider passwordValidator is nil")
	}
}

func TestNewProvider_WithCustomConfig(t *testing.T) {
	config := newMockConfig()
	config.Set("password.min_length", 12)
	config.Set("password.require_upper", false)

	provider := NewProvider(
		&mockEncrypter{},
		&mockLogger{},
		newMockMetrics(),
		config,
	)

	if provider == nil {
		t.Fatal("NewProvider returned nil")
	}

	// Verify configuration was applied
	if provider.passwordValidator.MinLength != 12 {
		t.Errorf("Expected MinLength 12, got %d", provider.passwordValidator.MinLength)
	}

	if provider.passwordValidator.RequireUppercase != false {
		t.Error("Expected RequireUppercase to be false")
	}
}

func TestAuthenticate_Success(t *testing.T) {
	provider := createTestProvider()
	ctx := context.Background()

	credentials := &PasswordCredentials{
		Password: "testpassword123",
	}

	result, err := provider.Authenticate(ctx, "test@example.com", credentials)

	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	if result == nil {
		t.Fatal("Authentication result is nil")
	}

	if result.ProviderType != auth.ProviderTypePassword {
		t.Errorf("Expected provider type %v, got %v", auth.ProviderTypePassword, result.ProviderType)
	}

	if result.ProviderUserID != "test@example.com" {
		t.Errorf("Expected provider user ID 'test@example.com', got '%s'", result.ProviderUserID)
	}

	if result.SessionData == nil {
		t.Error("Session data is nil")
	}

	if authMethod, ok := result.SessionData["auth_method"]; !ok || authMethod != "password" {
		t.Error("Expected auth_method 'password' in session data")
	}
}

func TestAuthenticate_InvalidCredentialType(t *testing.T) {
	provider := createTestProvider()
	ctx := context.Background()

	// Pass invalid credential type
	invalidCredentials := "not_a_password_credential"

	result, err := provider.Authenticate(ctx, "test@example.com", invalidCredentials)

	if err == nil {
		t.Fatal("Expected error for invalid credential type")
	}

	if result != nil {
		t.Error("Expected nil result for invalid credentials")
	}

	// Verify it's a validation error
	var validationErr *apperrors.AppError
	if !errors.As(err, &validationErr) || validationErr.Code != apperrors.CodeValidationFailed {
		t.Errorf("Expected validation error, got %v", err)
	}
}

func TestAuthenticate_Concurrency(t *testing.T) {
	provider := createTestProvider()
	ctx := context.Background()

	const numGoroutines = 100
	const numIterations = 10

	var wg sync.WaitGroup
	errorsChan := make(chan error, numGoroutines*numIterations)

	// Test concurrent authentication requests
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < numIterations; j++ {
				credentials := &PasswordCredentials{
					Password: "testpassword123",
				}

				result, err := provider.Authenticate(ctx, "test@example.com", credentials)
				if err != nil {
					errorsChan <- err
					return
				}

				if result == nil {
					errorsChan <- apperrors.NewAppError(apperrors.CodeInternalError, "nil result")
					return
				}

				if result.ProviderType != auth.ProviderTypePassword {
					errorsChan <- apperrors.NewAppError(apperrors.CodeInternalError, "wrong provider type")
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errorsChan)

	// Check for any errors
	for err := range errorsChan {
		t.Errorf("Concurrent authentication error: %v", err)
	}
}

func TestValidateCredentials_Success(t *testing.T) {
	provider := createTestProvider()
	ctx := context.Background()

	credentials := &PasswordCredentials{
		Password: "StrongPassword123!",
	}

	userInfo := &auth.UserInfo{
		FirstName: "John",
		LastName:  "Doe",
		Email:     "john.doe@example.com",
	}

	err := provider.ValidateCredentials(ctx, credentials, userInfo)

	if err != nil {
		t.Fatalf("ValidateCredentials failed: %v", err)
	}
}

func TestValidateCredentials_WeakPassword(t *testing.T) {
	provider := createTestProvider()
	ctx := context.Background()

	testCases := []struct {
		name     string
		password string
	}{
		{"too_short", "123"},
		{"no_uppercase", "weakpassword123!"},
		{"no_lowercase", "WEAKPASSWORD123!"},
		{"no_numbers", "WeakPassword!"},
		{"no_special", "WeakPassword123"},
		{"common_password", "password123"},
	}

	userInfo := &auth.UserInfo{
		FirstName: "John",
		LastName:  "Doe",
		Email:     "john.doe@example.com",
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			credentials := &PasswordCredentials{
				Password: tc.password,
			}

			err := provider.ValidateCredentials(ctx, credentials, userInfo)

			if err == nil {
				t.Errorf("Expected validation error for weak password: %s", tc.password)
			}
		})
	}
}

func TestValidateCredentials_InvalidCredentialType(t *testing.T) {
	provider := createTestProvider()
	ctx := context.Background()

	invalidCredentials := "not_a_password_credential"
	userInfo := &auth.UserInfo{
		FirstName: "John",
		LastName:  "Doe",
		Email:     "john.doe@example.com",
	}

	err := provider.ValidateCredentials(ctx, invalidCredentials, userInfo)

	if err == nil {
		t.Fatal("Expected error for invalid credential type")
	}

	var validationErr *apperrors.AppError
	if !errors.As(err, &validationErr) || validationErr.Code != apperrors.CodeValidationFailed {
		t.Errorf("Expected validation error, got %v", err)
	}
}

func TestValidateCredentials_Concurrency(t *testing.T) {
	provider := createTestProvider()
	ctx := context.Background()

	const numGoroutines = 50

	var wg sync.WaitGroup
	errorsChan := make(chan error, numGoroutines)

	userInfo := &auth.UserInfo{
		FirstName: "John",
		LastName:  "Doe",
		Email:     "john.doe@example.com",
	}

	// Test concurrent validation requests
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			credentials := &PasswordCredentials{
				Password: "StrongPassword123!",
			}

			err := provider.ValidateCredentials(ctx, credentials, userInfo)
			if err != nil {
				errorsChan <- err
			}
		}(i)
	}

	wg.Wait()
	close(errorsChan)

	// Check for any errors
	for err := range errorsChan {
		t.Errorf("Concurrent validation error: %v", err)
	}
}

func TestUpdateCredentials_Success(t *testing.T) {
	provider := createTestProvider()
	ctx := context.Background()

	oldCredentials := &PasswordCredentials{
		Password: "OldPassword123!",
	}

	newCredentials := &PasswordCredentials{
		Password: "NewPassword123!",
	}

	result, err := provider.UpdateCredentials(ctx, "user123", oldCredentials, newCredentials)

	if err != nil {
		t.Fatalf("UpdateCredentials failed: %v", err)
	}

	if result == nil {
		t.Fatal("Update result is nil")
	}

	// Verify the result is StoredPasswordData
	storedData, ok := result.(*StoredPasswordData)
	if !ok {
		t.Errorf("Expected StoredPasswordData, got %T", result)
	}

	if storedData != nil && len(storedData.HashedPassword) == 0 {
		t.Error("Hashed password is empty")
	}
}

func TestUpdateCredentials_SamePassword(t *testing.T) {
	provider := createTestProvider()
	ctx := context.Background()

	credentials := &PasswordCredentials{
		Password: "SamePassword123!",
	}

	result, err := provider.UpdateCredentials(ctx, "user123", credentials, credentials)

	if err == nil {
		t.Fatal("Expected error for same password")
	}

	if result != nil {
		t.Error("Expected nil result for same password")
	}

	var validationErr *apperrors.AppError
	if !errors.As(err, &validationErr) || validationErr.Code != apperrors.CodeValidationFailed {
		t.Errorf("Expected validation error, got %v", err)
	}
}

func TestUpdateCredentials_InvalidCredentialTypes(t *testing.T) {
	provider := createTestProvider()
	ctx := context.Background()

	validCredentials := &PasswordCredentials{
		Password: "ValidPassword123!",
	}

	testCases := []struct {
		name           string
		oldCredentials any
		newCredentials any
	}{
		{"invalid_old", "invalid", validCredentials},
		{"invalid_new", validCredentials, "invalid"},
		{"both_invalid", "invalid1", "invalid2"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := provider.UpdateCredentials(ctx, "user123", tc.oldCredentials, tc.newCredentials)

			if err == nil {
				t.Fatal("Expected error for invalid credential types")
			}

			if result != nil {
				t.Error("Expected nil result for invalid credentials")
			}
		})
	}
}

func TestPrepareCredentials_Success(t *testing.T) {
	provider := createTestProvider()
	ctx := context.Background()

	credentials := &PasswordCredentials{
		Password: "TestPassword123!",
	}

	result, err := provider.PrepareCredentials(ctx, credentials)

	if err != nil {
		t.Fatalf("PrepareCredentials failed: %v", err)
	}

	storedData, ok := result.(*StoredPasswordData)
	if !ok {
		t.Fatalf("Expected StoredPasswordData, got %T", result)
	}

	if len(storedData.HashedPassword) == 0 {
		t.Error("Hashed password is empty")
	}

	if storedData.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero")
	}

	if storedData.UpdatedAt.IsZero() {
		t.Error("UpdatedAt is zero")
	}

	// Verify the password was hashed correctly
	expectedHash := "hashed_TestPassword123!"
	if string(storedData.HashedPassword) != expectedHash {
		t.Errorf("Expected hash '%s', got '%s'", expectedHash, string(storedData.HashedPassword))
	}
}

func TestPrepareCredentials_InvalidCredentialType(t *testing.T) {
	provider := createTestProvider()
	ctx := context.Background()

	invalidCredentials := "not_a_password_credential"

	result, err := provider.PrepareCredentials(ctx, invalidCredentials)

	if err == nil {
		t.Fatal("Expected error for invalid credential type")
	}

	if result != nil {
		t.Error("Expected nil result for invalid credentials")
	}
}

func TestPrepareCredentials_EncrypterError(t *testing.T) {
	encrypter := &mockEncrypter{
		hashPasswordFunc: func([]byte) ([]byte, error) {
			return nil, apperrors.NewAppError(apperrors.CodeInternalError, "encryption failed")
		},
	}

	provider := NewProvider(
		encrypter,
		&mockLogger{},
		newMockMetrics(),
		newMockConfig(),
	)

	ctx := context.Background()
	credentials := &PasswordCredentials{
		Password: "TestPassword123!",
	}

	result, err := provider.PrepareCredentials(ctx, credentials)

	if err == nil {
		t.Fatal("Expected error from encrypter")
	}

	if result != nil {
		t.Error("Expected nil result on encrypter error")
	}
}

func TestVerifyPassword_Success(t *testing.T) {
	provider := createTestProvider()
	ctx := context.Background()

	storedData := &StoredPasswordData{
		HashedPassword: []byte("hashed_TestPassword123!"),
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	isValid, err := provider.VerifyPassword(ctx, storedData, "TestPassword123!")

	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}

	if !isValid {
		t.Error("Expected password to be valid")
	}
}

func TestVerifyPassword_InvalidPassword(t *testing.T) {
	provider := createTestProvider()
	ctx := context.Background()

	storedData := &StoredPasswordData{
		HashedPassword: []byte("hashed_TestPassword123!"),
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	isValid, err := provider.VerifyPassword(ctx, storedData, "WrongPassword")

	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}

	if isValid {
		t.Error("Expected password to be invalid")
	}
}

func TestVerifyPassword_InvalidStoredDataType(t *testing.T) {
	provider := createTestProvider()
	ctx := context.Background()

	invalidStoredData := "not_stored_password_data"

	isValid, err := provider.VerifyPassword(ctx, invalidStoredData, "TestPassword123!")

	if err == nil {
		t.Fatal("Expected error for invalid stored data type")
	}

	if isValid {
		t.Error("Expected password to be invalid")
	}
}

func TestVerifyPassword_EncrypterError(t *testing.T) {
	encrypter := &mockEncrypter{
		verifyPasswordFunc: func([]byte, []byte) (bool, error) {
			return false, apperrors.NewAppError(apperrors.CodeInternalError, "verification failed")
		},
	}

	provider := NewProvider(
		encrypter,
		&mockLogger{},
		newMockMetrics(),
		newMockConfig(),
	)

	ctx := context.Background()
	storedData := &StoredPasswordData{
		HashedPassword: []byte("hashed_TestPassword123!"),
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	isValid, err := provider.VerifyPassword(ctx, storedData, "TestPassword123!")

	if err == nil {
		t.Fatal("Expected error from encrypter")
	}

	if isValid {
		t.Error("Expected password to be invalid on error")
	}
}

func TestGetProviderType(t *testing.T) {
	provider := createTestProvider()

	providerType := provider.GetProviderType()

	if providerType != auth.ProviderTypePassword {
		t.Errorf("Expected provider type %v, got %v", auth.ProviderTypePassword, providerType)
	}
}

func TestSupportsCredentialUpdate(t *testing.T) {
	provider := createTestProvider()

	supports := provider.SupportsCredentialUpdate()

	if !supports {
		t.Error("Expected password provider to support credential updates")
	}
}

func TestProvider_ConcurrentOperations(t *testing.T) {
	provider := createTestProvider()
	ctx := context.Background()

	const numGoroutines = 20
	const numOperations = 5

	var wg sync.WaitGroup
	errorsChan := make(chan error, numGoroutines*numOperations*4) // 4 operations per iteration

	userInfo := &auth.UserInfo{
		FirstName: "John",
		LastName:  "Doe",
		Email:     "john.doe@example.com",
	}

	// Test all operations concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < numOperations; j++ {
				credentials := &PasswordCredentials{
					Password: "StrongPassword123!",
				}

				// Test Authenticate
				if _, err := provider.Authenticate(ctx, "test@example.com", credentials); err != nil {
					errorsChan <- err
				}

				// Test ValidateCredentials
				if err := provider.ValidateCredentials(ctx, credentials, userInfo); err != nil {
					errorsChan <- err
				}

				// Test PrepareCredentials
				if _, err := provider.PrepareCredentials(ctx, credentials); err != nil {
					errorsChan <- err
				}

				// Test VerifyPassword
				storedData := &StoredPasswordData{
					HashedPassword: []byte("hashed_StrongPassword123!"),
					CreatedAt:      time.Now(),
					UpdatedAt:      time.Now(),
				}
				if _, err := provider.VerifyPassword(ctx, storedData, "StrongPassword123!"); err != nil {
					errorsChan <- err
				}
			}
		}(i)
	}

	wg.Wait()
	close(errorsChan)

	// Check for any errors
	for err := range errorsChan {
		t.Errorf("Concurrent operation error: %v", err)
	}
}

// Benchmark tests for performance under load
func BenchmarkAuthenticate(b *testing.B) {
	provider := createTestProvider()
	ctx := context.Background()
	credentials := &PasswordCredentials{
		Password: "TestPassword123!",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := provider.Authenticate(ctx, "test@example.com", credentials)
			if err != nil {
				b.Fatalf("Authenticate failed: %v", err)
			}
		}
	})
}

func BenchmarkValidateCredentials(b *testing.B) {
	provider := createTestProvider()
	ctx := context.Background()
	credentials := &PasswordCredentials{
		Password: "StrongPassword123!",
	}
	userInfo := &auth.UserInfo{
		FirstName: "John",
		LastName:  "Doe",
		Email:     "john.doe@example.com",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			err := provider.ValidateCredentials(ctx, credentials, userInfo)
			if err != nil {
				b.Fatalf("ValidateCredentials failed: %v", err)
			}
		}
	})
}

func BenchmarkPrepareCredentials(b *testing.B) {
	provider := createTestProvider()
	ctx := context.Background()
	credentials := &PasswordCredentials{
		Password: "TestPassword123!",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := provider.PrepareCredentials(ctx, credentials)
			if err != nil {
				b.Fatalf("PrepareCredentials failed: %v", err)
			}
		}
	})
}

func BenchmarkVerifyPassword(b *testing.B) {
	provider := createTestProvider()
	ctx := context.Background()
	storedData := &StoredPasswordData{
		HashedPassword: []byte("hashed_TestPassword123!"),
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := provider.VerifyPassword(ctx, storedData, "TestPassword123!")
			if err != nil {
				b.Fatalf("VerifyPassword failed: %v", err)
			}
		}
	})
}
