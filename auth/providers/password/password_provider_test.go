package password

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/MichaelAJay/go-config"
	"github.com/MichaelAJay/go-logger"
	"github.com/MichaelAJay/go-metrics"
	"github.com/MichaelAJay/go-user-management/auth"
	userErrors "github.com/MichaelAJay/go-user-management/errors"
)

// MockEncrypter tracks calls and returns configured responses
type MockEncrypter struct {
	hashPasswordCalls    [][]byte
	hashPasswordReturn   []byte
	hashPasswordError    error
	verifyPasswordCalls  []VerifyPasswordCall
	verifyPasswordReturn bool
	verifyPasswordError  error
}

type VerifyPasswordCall struct {
	HashedPassword []byte
	Password       []byte
}

func (m *MockEncrypter) Encrypt(data []byte) ([]byte, error) {
	return nil, nil
}

func (m *MockEncrypter) EncryptWithAAD(data, additionalData []byte) ([]byte, error) {
	return nil, nil
}

func (m *MockEncrypter) Decrypt(data []byte) ([]byte, error) {
	return nil, nil
}

func (m *MockEncrypter) DecryptWithAAD(data, additionalData []byte) ([]byte, error) {
	return nil, nil
}

func (m *MockEncrypter) HashPassword(password []byte) ([]byte, error) {
	m.hashPasswordCalls = append(m.hashPasswordCalls, password)
	return m.hashPasswordReturn, m.hashPasswordError
}

func (m *MockEncrypter) VerifyPassword(hashedPassword, password []byte) (bool, error) {
	m.verifyPasswordCalls = append(m.verifyPasswordCalls, VerifyPasswordCall{
		HashedPassword: hashedPassword,
		Password:       password,
	})
	return m.verifyPasswordReturn, m.verifyPasswordError
}

func (m *MockEncrypter) HashLookupData(data []byte) []byte {
	return nil
}

func (m *MockEncrypter) GetKeyVersion() string {
	return ""
}

// MockLogger tracks log calls
type MockLogger struct {
	infoCalls  []LogCall
	errorCalls []LogCall
	debugCalls []LogCall
	warnCalls  []LogCall
	fatalCalls []LogCall
}

type LogCall struct {
	Message string
	Fields  []logger.Field
}

func (m *MockLogger) Info(msg string, fields ...logger.Field) {
	m.infoCalls = append(m.infoCalls, LogCall{Message: msg, Fields: fields})
}

func (m *MockLogger) Error(msg string, fields ...logger.Field) {
	m.errorCalls = append(m.errorCalls, LogCall{Message: msg, Fields: fields})
}

func (m *MockLogger) Debug(msg string, fields ...logger.Field) {
	m.debugCalls = append(m.debugCalls, LogCall{Message: msg, Fields: fields})
}

func (m *MockLogger) Warn(msg string, fields ...logger.Field) {
	m.warnCalls = append(m.warnCalls, LogCall{Message: msg, Fields: fields})
}

func (m *MockLogger) Fatal(msg string, fields ...logger.Field) {
	m.fatalCalls = append(m.fatalCalls, LogCall{Message: msg, Fields: fields})
}

func (m *MockLogger) With(fields ...logger.Field) logger.Logger {
	return m
}

func (m *MockLogger) WithContext(ctx context.Context) logger.Logger {
	return m
}

// MockMetrics tracks metric calls
type MockMetrics struct {
	counterCalls   []CounterCall
	timerCalls     []TimerCall
	gaugeCalls     []GaugeCall
	histogramCalls []HistogramCall
}

type CounterCall struct {
	Options metrics.Options
}

type TimerCall struct {
	Options metrics.Options
}

type GaugeCall struct {
	Options metrics.Options
}

type HistogramCall struct {
	Options metrics.Options
}

func (m *MockMetrics) Counter(opts metrics.Options) metrics.Counter {
	m.counterCalls = append(m.counterCalls, CounterCall{Options: opts})
	return &MockCounter{}
}

func (m *MockMetrics) Timer(opts metrics.Options) metrics.Timer {
	m.timerCalls = append(m.timerCalls, TimerCall{Options: opts})
	return &MockTimer{}
}

func (m *MockMetrics) Gauge(opts metrics.Options) metrics.Gauge {
	m.gaugeCalls = append(m.gaugeCalls, GaugeCall{Options: opts})
	return &MockGauge{}
}

func (m *MockMetrics) Histogram(opts metrics.Options) metrics.Histogram {
	m.histogramCalls = append(m.histogramCalls, HistogramCall{Options: opts})
	return &MockHistogram{}
}

func (m *MockMetrics) Unregister(name string) {}

func (m *MockMetrics) Each(fn func(metrics.Metric)) {}

// MockCounter tracks counter operations
type MockCounter struct {
	incCalls  []struct{}
	addCalls  []float64
	withCalls []metrics.Tags
}

func (m *MockCounter) Inc() {
	m.incCalls = append(m.incCalls, struct{}{})
}

func (m *MockCounter) Add(value float64) {
	m.addCalls = append(m.addCalls, value)
}

func (m *MockCounter) With(tags metrics.Tags) metrics.Counter {
	m.withCalls = append(m.withCalls, tags)
	return &MockCounter{}
}

func (m *MockCounter) Name() string        { return "mock_counter" }
func (m *MockCounter) Description() string { return "Mock counter for testing" }
func (m *MockCounter) Type() metrics.Type  { return metrics.TypeCounter }
func (m *MockCounter) Tags() metrics.Tags  { return metrics.Tags{} }

// MockTimer is a mock timer for testing
type MockTimer struct {
	recordCalls      []time.Duration
	recordSinceCalls []time.Time
	timeCalls        []func()
	withCalls        []metrics.Tags
}

func (m *MockTimer) Record(d time.Duration) {
	m.recordCalls = append(m.recordCalls, d)
}

func (m *MockTimer) RecordSince(start time.Time) {
	m.recordSinceCalls = append(m.recordSinceCalls, start)
}

func (m *MockTimer) Time(fn func()) time.Duration {
	m.timeCalls = append(m.timeCalls, fn)
	start := time.Now()
	fn()
	return time.Since(start)
}

func (m *MockTimer) With(tags metrics.Tags) metrics.Timer {
	m.withCalls = append(m.withCalls, tags)
	return &MockTimer{}
}

func (m *MockTimer) Name() string        { return "mock_timer" }
func (m *MockTimer) Description() string { return "Mock timer for testing" }
func (m *MockTimer) Type() metrics.Type  { return metrics.TypeTimer }
func (m *MockTimer) Tags() metrics.Tags  { return metrics.Tags{} }

// MockGauge is a mock gauge for testing
type MockGauge struct {
	setCalls  []float64
	addCalls  []float64
	incCalls  []struct{}
	decCalls  []struct{}
	withCalls []metrics.Tags
}

func (m *MockGauge) Set(value float64) {
	m.setCalls = append(m.setCalls, value)
}

func (m *MockGauge) Add(value float64) {
	m.addCalls = append(m.addCalls, value)
}

func (m *MockGauge) Inc() {
	m.incCalls = append(m.incCalls, struct{}{})
}

func (m *MockGauge) Dec() {
	m.decCalls = append(m.decCalls, struct{}{})
}

func (m *MockGauge) With(tags metrics.Tags) metrics.Gauge {
	m.withCalls = append(m.withCalls, tags)
	return &MockGauge{}
}

func (m *MockGauge) Name() string        { return "mock_gauge" }
func (m *MockGauge) Description() string { return "Mock gauge for testing" }
func (m *MockGauge) Type() metrics.Type  { return metrics.TypeGauge }
func (m *MockGauge) Tags() metrics.Tags  { return metrics.Tags{} }

// MockHistogram is a mock histogram for testing
type MockHistogram struct {
	observeCalls []float64
	withCalls    []metrics.Tags
}

func (m *MockHistogram) Observe(value float64) {
	m.observeCalls = append(m.observeCalls, value)
}

func (m *MockHistogram) With(tags metrics.Tags) metrics.Histogram {
	m.withCalls = append(m.withCalls, tags)
	return &MockHistogram{}
}

func (m *MockHistogram) Name() string        { return "mock_histogram" }
func (m *MockHistogram) Description() string { return "Mock histogram for testing" }
func (m *MockHistogram) Type() metrics.Type  { return metrics.TypeHistogram }
func (m *MockHistogram) Tags() metrics.Tags  { return metrics.Tags{} }

// MockConfig provides configurable config for testing
type MockConfig struct {
	data map[string]interface{}
}

func NewMockConfig() *MockConfig {
	return &MockConfig{
		data: make(map[string]interface{}),
	}
}

func (m *MockConfig) Get(key string) (interface{}, bool) {
	if val, exists := m.data[key]; exists {
		return val, true
	}
	return nil, false
}

func (m *MockConfig) GetString(key string) (string, bool) {
	if val, exists := m.data[key]; exists {
		if str, ok := val.(string); ok {
			return str, true
		}
	}
	return "", false
}

func (m *MockConfig) GetInt(key string) (int, bool) {
	if val, exists := m.data[key]; exists {
		if i, ok := val.(int); ok {
			return i, true
		}
	}
	return 0, false
}

func (m *MockConfig) GetBool(key string) (bool, bool) {
	if val, exists := m.data[key]; exists {
		if b, ok := val.(bool); ok {
			return b, true
		}
	}
	return false, false
}

func (m *MockConfig) GetFloat(key string) (float64, bool) {
	if val, exists := m.data[key]; exists {
		if f, ok := val.(float64); ok {
			return f, true
		}
	}
	return 0, false
}

func (m *MockConfig) GetStringSlice(key string) ([]string, bool) {
	if val, exists := m.data[key]; exists {
		if ss, ok := val.([]string); ok {
			return ss, true
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

// Test Provider Creation and Basic Properties

func TestNewProvider(t *testing.T) {
	mockEncrypter := &MockEncrypter{}
	mockLogger := &MockLogger{}
	mockMetrics := &MockMetrics{}
	mockConfig := NewMockConfig()

	provider := NewProvider(mockEncrypter, mockLogger, mockMetrics, mockConfig)

	if provider == nil {
		t.Fatal("Expected provider to be created, got nil")
	}
}

func TestProvider_GetProviderType(t *testing.T) {
	provider := createTestProvider()

	providerType := provider.GetProviderType()
	if providerType != auth.ProviderTypePassword {
		t.Errorf("Expected provider type %s, got %s", auth.ProviderTypePassword, providerType)
	}
}

func TestProvider_SupportsCredentialUpdate(t *testing.T) {
	provider := createTestProvider()

	if !provider.SupportsCredentialUpdate() {
		t.Error("Expected provider to support credential updates")
	}
}

// Test PrepareCredentials

func TestProvider_PrepareCredentials(t *testing.T) {
	tests := []struct {
		name                  string
		credentials           interface{}
		hashPasswordReturn    []byte
		hashPasswordError     error
		expectError           bool
		expectValidationError bool
		expectAppError        bool
	}{
		{
			name: "successful password preparation",
			credentials: &PasswordCredentials{
				Password: "SecurePassword123!",
			},
			hashPasswordReturn: []byte("hashed_password_data"),
			hashPasswordError:  nil,
			expectError:        false,
		},
		{
			name:                  "invalid credential type",
			credentials:           "invalid_string",
			expectError:           true,
			expectValidationError: true,
		},
		{
			name: "encrypter hash error",
			credentials: &PasswordCredentials{
				Password: "SecurePassword123!",
			},
			hashPasswordError: errors.New("hashing failed"),
			expectError:       true,
			expectAppError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockEncrypter := &MockEncrypter{
				hashPasswordReturn: tt.hashPasswordReturn,
				hashPasswordError:  tt.hashPasswordError,
			}
			mockLogger := &MockLogger{}
			mockMetrics := &MockMetrics{}
			mockConfig := NewMockConfig()

			provider := NewProvider(mockEncrypter, mockLogger, mockMetrics, mockConfig)

			result, err := provider.PrepareCredentials(context.Background(), tt.credentials)

			if tt.expectError {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}

				if tt.expectValidationError {
					errorCode := userErrors.GetErrorCode(err)
					if errorCode != userErrors.CodeValidationFailed {
						t.Errorf("Expected ValidationError code, got %s", errorCode)
					}
				}

				if tt.expectAppError {
					errorCode := userErrors.GetErrorCode(err)
					if errorCode == userErrors.CodeInternalError {
						// This is expected for AppErrors that aren't validation errors
					} else {
						t.Errorf("Expected AppError with internal error code, got %s", errorCode)
					}
				}

				if result != nil {
					t.Error("Expected nil result when error occurs")
				}
			} else {
				if err != nil {
					t.Fatalf("Expected no error, got %v", err)
				}
				if result == nil {
					t.Fatal("Expected non-nil result")
				}

				// Verify stored data structure
				var storedData StoredPasswordData
				if err := json.Unmarshal(result, &storedData); err != nil {
					t.Fatalf("Failed to unmarshal stored data: %v", err)
				}

				if string(storedData.HashedPassword) != string(tt.hashPasswordReturn) {
					t.Errorf("Expected hashed password %s, got %s",
						string(tt.hashPasswordReturn), string(storedData.HashedPassword))
				}

				if storedData.CreatedAt.IsZero() || storedData.UpdatedAt.IsZero() {
					t.Error("Expected CreatedAt and UpdatedAt to be set")
				}
			}

			// Verify encrypter calls
			if passwordCreds, ok := tt.credentials.(*PasswordCredentials); ok {
				if len(mockEncrypter.hashPasswordCalls) != 1 {
					t.Errorf("Expected 1 hash call, got %d", len(mockEncrypter.hashPasswordCalls))
				} else {
					expectedPassword := []byte(passwordCreds.Password)
					actualPassword := mockEncrypter.hashPasswordCalls[0]
					if string(actualPassword) != string(expectedPassword) {
						t.Errorf("Expected password %s, got %s",
							string(expectedPassword), string(actualPassword))
					}
				}
			}
		})
	}
}

// Test Authenticate

func TestProvider_Authenticate(t *testing.T) {
	tests := []struct {
		name                    string
		identifier              string
		credentials             interface{}
		storedAuthData          []byte
		verifyPasswordReturn    bool
		verifyPasswordError     error
		expectError             bool
		expectValidationError   bool
		expectInvalidCredsError bool
	}{
		{
			name:       "successful authentication",
			identifier: "user123",
			credentials: &PasswordCredentials{
				Password: "correct_password",
			},
			storedAuthData:       createValidStoredAuthData(t),
			verifyPasswordReturn: true,
			verifyPasswordError:  nil,
			expectError:          false,
		},
		{
			name:                  "invalid credential type",
			identifier:            "user123",
			credentials:           "invalid_string",
			storedAuthData:        createValidStoredAuthData(t),
			expectError:           true,
			expectValidationError: true,
		},
		{
			name:       "wrong password",
			identifier: "user123",
			credentials: &PasswordCredentials{
				Password: "wrong_password",
			},
			storedAuthData:          createValidStoredAuthData(t),
			verifyPasswordReturn:    false,
			verifyPasswordError:     nil,
			expectError:             true,
			expectInvalidCredsError: true,
		},
		{
			name:       "password verification error",
			identifier: "user123",
			credentials: &PasswordCredentials{
				Password: "some_password",
			},
			storedAuthData:          createValidStoredAuthData(t),
			verifyPasswordReturn:    false,
			verifyPasswordError:     errors.New("verification failed"),
			expectError:             true,
			expectInvalidCredsError: true,
		},
		{
			name:       "invalid stored auth data",
			identifier: "user123",
			credentials: &PasswordCredentials{
				Password: "password",
			},
			storedAuthData: []byte("invalid_json"),
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockEncrypter := &MockEncrypter{
				verifyPasswordReturn: tt.verifyPasswordReturn,
				verifyPasswordError:  tt.verifyPasswordError,
			}
			mockLogger := &MockLogger{}
			mockMetrics := &MockMetrics{}
			mockConfig := NewMockConfig()

			provider := NewProvider(mockEncrypter, mockLogger, mockMetrics, mockConfig)

			result, err := provider.Authenticate(context.Background(), tt.identifier, tt.credentials, tt.storedAuthData)

			if tt.expectError {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}

				if tt.expectValidationError {
					errorCode := userErrors.GetErrorCode(err)
					if errorCode != userErrors.CodeValidationFailed {
						t.Errorf("Expected ValidationError code, got %s", errorCode)
					}
				}

				if tt.expectInvalidCredsError {
					errorCode := userErrors.GetErrorCode(err)
					if errorCode != userErrors.CodeInvalidCredentials {
						t.Errorf("Expected InvalidCredentials code, got %s", errorCode)
					}
				}

				if result != nil {
					t.Error("Expected nil result when error occurs")
				}
			} else {
				if err != nil {
					t.Fatalf("Expected no error, got %v", err)
				}
				if result == nil {
					t.Fatal("Expected non-nil result")
				}

				// Verify result properties
				if result.UserID != tt.identifier {
					t.Errorf("Expected UserID %s, got %s", tt.identifier, result.UserID)
				}
				if result.ProviderType != auth.ProviderTypePassword {
					t.Errorf("Expected ProviderType %s, got %s", auth.ProviderTypePassword, result.ProviderType)
				}
				if result.ProviderUserID != tt.identifier {
					t.Errorf("Expected ProviderUserID %s, got %s", tt.identifier, result.ProviderUserID)
				}
				if len(result.SessionData) == 0 {
					t.Error("Expected non-empty SessionData")
				}
				if authMethod, ok := result.SessionData["auth_method"]; !ok || authMethod != "password" {
					t.Error("Expected auth_method to be 'password'")
				}
			}

			// Verify encrypter calls for valid credentials
			if passwordCreds, ok := tt.credentials.(*PasswordCredentials); ok && len(tt.storedAuthData) > 0 {
				if len(mockEncrypter.verifyPasswordCalls) != 1 {
					t.Errorf("Expected 1 verify call, got %d", len(mockEncrypter.verifyPasswordCalls))
				} else {
					call := mockEncrypter.verifyPasswordCalls[0]
					expectedPassword := []byte(passwordCreds.Password)
					if string(call.Password) != string(expectedPassword) {
						t.Errorf("Expected password %s, got %s",
							string(expectedPassword), string(call.Password))
					}
				}
			}
		})
	}
}

// Test ValidateCredentials

func TestProvider_ValidateCredentials(t *testing.T) {
	tests := []struct {
		name                  string
		credentials           interface{}
		userInfo              *auth.UserInfo
		expectError           bool
		expectValidationError bool
		expectedField         string
	}{
		{
			name: "valid strong password",
			credentials: &PasswordCredentials{
				Password: "StrongPassword123!",
			},
			userInfo: &auth.UserInfo{
				UserID:    "user123",
				FirstName: "John",
				LastName:  "Doe",
				Email:     "john@example.com",
			},
			expectError: false,
		},
		{
			name:        "invalid credential type",
			credentials: "invalid_string",
			userInfo: &auth.UserInfo{
				UserID: "user123",
			},
			expectError:           true,
			expectValidationError: true,
			expectedField:         "credentials",
		},
		{
			name: "weak password - too short",
			credentials: &PasswordCredentials{
				Password: "weak",
			},
			userInfo: &auth.UserInfo{
				UserID:    "user123",
				FirstName: "John",
				LastName:  "Doe",
				Email:     "john@example.com",
			},
			expectError:           true,
			expectValidationError: true,
		},
		{
			name: "weak password - no uppercase",
			credentials: &PasswordCredentials{
				Password: "nouppercase123!",
			},
			userInfo: &auth.UserInfo{
				UserID:    "user123",
				FirstName: "John",
				LastName:  "Doe",
				Email:     "john@example.com",
			},
			expectError:           true,
			expectValidationError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockEncrypter := &MockEncrypter{}
			mockLogger := &MockLogger{}
			mockMetrics := &MockMetrics{}
			mockConfig := NewMockConfig()

			provider := NewProvider(mockEncrypter, mockLogger, mockMetrics, mockConfig)

			err := provider.ValidateCredentials(context.Background(), tt.credentials, tt.userInfo)

			if tt.expectError {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}

				if tt.expectValidationError {
					errorCode := userErrors.GetErrorCode(err)
					if errorCode != userErrors.CodeValidationFailed {
						t.Errorf("Expected ValidationError code, got %s", errorCode)
					}
				}
			} else {
				if err != nil {
					t.Fatalf("Expected no error, got %v", err)
				}
			}
		})
	}
}

// Test UpdateCredentials

func TestProvider_UpdateCredentials(t *testing.T) {
	tests := []struct {
		name                    string
		userID                  string
		oldCredentials          interface{}
		newCredentials          interface{}
		storedAuthData          []byte
		verifyPasswordReturn    bool
		verifyPasswordError     error
		hashPasswordReturn      []byte
		hashPasswordError       error
		expectError             bool
		expectValidationError   bool
		expectInvalidCredsError bool
	}{
		{
			name:   "successful update",
			userID: "user123",
			oldCredentials: &PasswordCredentials{
				Password: "old_password",
			},
			newCredentials: &PasswordCredentials{
				Password: "NewStrongPassword123!",
			},
			storedAuthData:       createValidStoredAuthData(t),
			verifyPasswordReturn: true,
			verifyPasswordError:  nil,
			hashPasswordReturn:   []byte("new_hashed_password"),
			hashPasswordError:    nil,
			expectError:          false,
		},
		{
			name:           "invalid old credential type",
			userID:         "user123",
			oldCredentials: "invalid_string",
			newCredentials: &PasswordCredentials{
				Password: "NewStrongPassword123!",
			},
			storedAuthData:        createValidStoredAuthData(t),
			expectError:           true,
			expectValidationError: true,
		},
		{
			name:   "invalid new credential type",
			userID: "user123",
			oldCredentials: &PasswordCredentials{
				Password: "old_password",
			},
			newCredentials:        "invalid_string",
			storedAuthData:        createValidStoredAuthData(t),
			expectError:           true,
			expectValidationError: true,
		},
		{
			name:   "wrong old password",
			userID: "user123",
			oldCredentials: &PasswordCredentials{
				Password: "wrong_old_password",
			},
			newCredentials: &PasswordCredentials{
				Password: "NewStrongPassword123!",
			},
			storedAuthData:          createValidStoredAuthData(t),
			verifyPasswordReturn:    false,
			verifyPasswordError:     nil,
			expectError:             true,
			expectInvalidCredsError: true,
		},
		{
			name:   "same old and new password",
			userID: "user123",
			oldCredentials: &PasswordCredentials{
				Password: "same_password",
			},
			newCredentials: &PasswordCredentials{
				Password: "same_password",
			},
			storedAuthData:        createValidStoredAuthData(t),
			verifyPasswordReturn:  true,
			verifyPasswordError:   nil,
			expectError:           true,
			expectValidationError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockEncrypter := &MockEncrypter{
				verifyPasswordReturn: tt.verifyPasswordReturn,
				verifyPasswordError:  tt.verifyPasswordError,
				hashPasswordReturn:   tt.hashPasswordReturn,
				hashPasswordError:    tt.hashPasswordError,
			}
			mockLogger := &MockLogger{}
			mockMetrics := &MockMetrics{}
			mockConfig := NewMockConfig()

			provider := NewProvider(mockEncrypter, mockLogger, mockMetrics, mockConfig)

			result, err := provider.UpdateCredentials(context.Background(), tt.userID, tt.oldCredentials, tt.newCredentials, tt.storedAuthData)

			if tt.expectError {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}

				if tt.expectValidationError {
					errorCode := userErrors.GetErrorCode(err)
					if errorCode != userErrors.CodeValidationFailed {
						t.Errorf("Expected ValidationError code, got %s", errorCode)
					}
				}

				if tt.expectInvalidCredsError {
					errorCode := userErrors.GetErrorCode(err)
					if errorCode != userErrors.CodeInvalidCredentials {
						t.Errorf("Expected InvalidCredentials code, got %s", errorCode)
					}
				}

				if result != nil {
					t.Error("Expected nil result when error occurs")
				}
			} else {
				if err != nil {
					t.Fatalf("Expected no error, got %v", err)
				}
				if result == nil {
					t.Fatal("Expected non-nil result")
				}

				// Verify new stored data
				var storedData StoredPasswordData
				if err := json.Unmarshal(result, &storedData); err != nil {
					t.Fatalf("Failed to unmarshal result: %v", err)
				}

				if string(storedData.HashedPassword) != string(tt.hashPasswordReturn) {
					t.Errorf("Expected hashed password %s, got %s",
						string(tt.hashPasswordReturn), string(storedData.HashedPassword))
				}
			}
		})
	}
}

// Test LoadConfig

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name           string
		configData     map[string]interface{}
		expectedConfig *Config
	}{
		{
			name:       "default configuration",
			configData: map[string]interface{}{},
			expectedConfig: &Config{
				MinLength:      8,
				MaxLength:      128,
				MinEntropy:     30.0,
				RequireUpper:   true,
				RequireLower:   true,
				RequireNumber:  true,
				RequireSpecial: true,
			},
		},
		{
			name: "custom configuration",
			configData: map[string]interface{}{
				"password_provider.min_length":      12,
				"password_provider.max_length":      256,
				"password_provider.require_upper":   false,
				"password_provider.require_lower":   false,
				"password_provider.require_number":  false,
				"password_provider.require_special": false,
			},
			expectedConfig: &Config{
				MinLength:      12,
				MaxLength:      256,
				MinEntropy:     30.0,
				RequireUpper:   false,
				RequireLower:   false,
				RequireNumber:  false,
				RequireSpecial: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockConfig := NewMockConfig()
			for key, value := range tt.configData {
				mockConfig.Set(key, value)
			}

			config := loadConfig(mockConfig)

			if config.MinLength != tt.expectedConfig.MinLength {
				t.Errorf("Expected MinLength %d, got %d", tt.expectedConfig.MinLength, config.MinLength)
			}
			if config.MaxLength != tt.expectedConfig.MaxLength {
				t.Errorf("Expected MaxLength %d, got %d", tt.expectedConfig.MaxLength, config.MaxLength)
			}
			if config.MinEntropy != tt.expectedConfig.MinEntropy {
				t.Errorf("Expected MinEntropy %f, got %f", tt.expectedConfig.MinEntropy, config.MinEntropy)
			}
			if config.RequireUpper != tt.expectedConfig.RequireUpper {
				t.Errorf("Expected RequireUpper %t, got %t", tt.expectedConfig.RequireUpper, config.RequireUpper)
			}
			if config.RequireLower != tt.expectedConfig.RequireLower {
				t.Errorf("Expected RequireLower %t, got %t", tt.expectedConfig.RequireLower, config.RequireLower)
			}
			if config.RequireNumber != tt.expectedConfig.RequireNumber {
				t.Errorf("Expected RequireNumber %t, got %t", tt.expectedConfig.RequireNumber, config.RequireNumber)
			}
			if config.RequireSpecial != tt.expectedConfig.RequireSpecial {
				t.Errorf("Expected RequireSpecial %t, got %t", tt.expectedConfig.RequireSpecial, config.RequireSpecial)
			}
		})
	}
}

// Helper Functions

func createTestProvider() *Provider {
	mockEncrypter := &MockEncrypter{}
	mockLogger := &MockLogger{}
	mockMetrics := &MockMetrics{}
	mockConfig := NewMockConfig()

	return NewProvider(mockEncrypter, mockLogger, mockMetrics, mockConfig)
}

func createValidStoredAuthData(t *testing.T) []byte {
	storedData := &StoredPasswordData{
		HashedPassword: []byte("test_hashed_password"),
		CreatedAt:      time.Now().Add(-24 * time.Hour),
		UpdatedAt:      time.Now().Add(-24 * time.Hour),
	}

	data, err := json.Marshal(storedData)
	if err != nil {
		t.Fatalf("Failed to create test stored auth data: %v", err)
	}
	return data
}
