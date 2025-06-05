package auth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/MichaelAJay/go-logger"
	"github.com/MichaelAJay/go-metrics"
	"github.com/MichaelAJay/go-user-management/errors"
)

// MockAuthenticationProvider is a mock implementation of AuthenticationProvider for testing
type MockAuthenticationProvider struct {
	authenticateCalls        []AuthenticateCall
	authenticateReturn       *AuthenticationResult
	authenticateError        error
	validateCredentialsCalls []ValidateCredentialsCall
	validateCredentialsError error
	updateCredentialsCalls   []UpdateCredentialsCall
	updateCredentialsReturn  []byte
	updateCredentialsError   error
	prepareCredentialsCalls  []PrepareCredentialsCall
	prepareCredentialsReturn []byte
	prepareCredentialsError  error
	providerType             ProviderType
	supportsUpdate           bool
}

type AuthenticateCall struct {
	Ctx            context.Context
	Identifier     string
	Credentials    any
	StoredAuthData []byte
}

type ValidateCredentialsCall struct {
	Ctx         context.Context
	Credentials any
	UserInfo    *UserInfo
}

type UpdateCredentialsCall struct {
	Ctx            context.Context
	UserID         string
	OldCredentials any
	NewCredentials any
	StoredAuthData []byte
}

type PrepareCredentialsCall struct {
	Ctx         context.Context
	Credentials any
}

func (m *MockAuthenticationProvider) Authenticate(ctx context.Context, identifier string, credentials any, storedAuthData []byte) (*AuthenticationResult, error) {
	m.authenticateCalls = append(m.authenticateCalls, AuthenticateCall{
		Ctx:            ctx,
		Identifier:     identifier,
		Credentials:    credentials,
		StoredAuthData: storedAuthData,
	})
	return m.authenticateReturn, m.authenticateError
}

func (m *MockAuthenticationProvider) ValidateCredentials(ctx context.Context, credentials any, userInfo *UserInfo) error {
	m.validateCredentialsCalls = append(m.validateCredentialsCalls, ValidateCredentialsCall{
		Ctx:         ctx,
		Credentials: credentials,
		UserInfo:    userInfo,
	})
	return m.validateCredentialsError
}

func (m *MockAuthenticationProvider) UpdateCredentials(ctx context.Context, userID string, oldCredentials, newCredentials any, storedAuthData []byte) ([]byte, error) {
	m.updateCredentialsCalls = append(m.updateCredentialsCalls, UpdateCredentialsCall{
		Ctx:            ctx,
		UserID:         userID,
		OldCredentials: oldCredentials,
		NewCredentials: newCredentials,
		StoredAuthData: storedAuthData,
	})
	return m.updateCredentialsReturn, m.updateCredentialsError
}

func (m *MockAuthenticationProvider) PrepareCredentials(ctx context.Context, credentials any) ([]byte, error) {
	m.prepareCredentialsCalls = append(m.prepareCredentialsCalls, PrepareCredentialsCall{
		Ctx:         ctx,
		Credentials: credentials,
	})
	return m.prepareCredentialsReturn, m.prepareCredentialsError
}

func (m *MockAuthenticationProvider) GetProviderType() ProviderType {
	return m.providerType
}

func (m *MockAuthenticationProvider) SupportsCredentialUpdate() bool {
	return m.supportsUpdate
}

// MockLogger is a simple mock for testing
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

// MockMetrics is a simple mock for testing
type MockMetrics struct {
	counterCalls []CounterCall
	timerCalls   []TimerCall
}

func (m *MockMetrics) Unregister(name string) {}

func (m *MockMetrics) Each(fn func(metrics.Metric)) {}

type CounterCall struct {
	Options metrics.Options
}

type TimerCall struct {
	Options metrics.Options
}

func (m *MockMetrics) Histogram(opts metrics.Options) metrics.Histogram {
	return &MockHistogram{}
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
	return &MockGauge{}
}

// MockCounter for metrics testing
type MockCounter struct {
	incCalls []struct{}
	addCalls []float64
}

func (m *MockCounter) Name() string {
	return "mock_counter"
}

func (m *MockCounter) Description() string {
	return "mock_counter"
}

func (m *MockCounter) Type() metrics.Type {
	return metrics.TypeCounter
}

func (m *MockCounter) Tags() metrics.Tags {
	return metrics.Tags{}
}

func (m *MockCounter) Inc() {
	m.incCalls = append(m.incCalls, struct{}{})
}

func (m *MockCounter) Add(value float64) {
	m.addCalls = append(m.addCalls, value)
}

func (m *MockCounter) With(tags metrics.Tags) metrics.Counter {
	return m
}

// MockTimer for metrics testing
type MockTimer struct{}

func (m *MockTimer) Name() string {
	return "mock_timer"
}

func (m *MockTimer) Description() string {
	return "mock_timer"
}

func (m *MockTimer) Type() metrics.Type {
	return metrics.TypeTimer
}

func (m *MockTimer) Tags() metrics.Tags {
	return metrics.Tags{}
}

func (m *MockTimer) Record(duration time.Duration) {}
func (m *MockTimer) RecordSince(start time.Time)   {}
func (m *MockTimer) Time(fn func()) time.Duration {
	return time.Duration(0)
}
func (m *MockTimer) With(tags metrics.Tags) metrics.Timer {
	return m
}

// MockGauge for metrics testing
type MockGauge struct{}

func (m *MockGauge) Name() string {
	return "mock_gauge"
}

func (m *MockGauge) Description() string {
	return "mock_gauge"
}

func (m *MockGauge) Type() metrics.Type {
	return metrics.TypeGauge
}

func (m *MockGauge) Tags() metrics.Tags {
	return metrics.Tags{}
}

func (m *MockGauge) Set(value float64) {}
func (m *MockGauge) Add(value float64) {}
func (m *MockGauge) Inc()              {}
func (m *MockGauge) Dec()              {}
func (m *MockGauge) With(tags metrics.Tags) metrics.Gauge {
	return m
}

type MockHistogram struct{}

func (m *MockHistogram) Name() string {
	return "mock_histogram"
}

func (m *MockHistogram) Description() string {
	return "mock_histogram"
}

func (m *MockHistogram) Type() metrics.Type {
	return metrics.TypeHistogram
}

func (m *MockHistogram) Tags() metrics.Tags {
	return metrics.Tags{}
}

func (m *MockHistogram) Observe(value float64) {}
func (m *MockHistogram) With(tags metrics.Tags) metrics.Histogram {
	return m
}

func TestNewManager(t *testing.T) {
	mockLogger := &MockLogger{}
	mockMetrics := &MockMetrics{}

	manager := NewManager(mockLogger, mockMetrics)

	if manager == nil {
		t.Fatal("Expected manager to be created, got nil")
	}

	// Type assertion to verify we got a concrete implementation
	// Since NewManager returns an interface, we just verify it's not nil
	// and implements the expected interface methods
	if manager == nil {
		t.Fatal("Expected non-nil manager")
	}
}

func TestManager_RegisterProvider(t *testing.T) {
	tests := []struct {
		name          string
		setupManager  func() Manager
		provider      AuthenticationProvider
		expectedError string
		expectLogging bool
	}{
		{
			name: "successful registration",
			setupManager: func() Manager {
				mockLogger := &MockLogger{}
				mockMetrics := &MockMetrics{}
				return NewManager(mockLogger, mockMetrics)
			},
			provider: &MockAuthenticationProvider{
				providerType: ProviderTypePassword,
			},
			expectedError: "",
			expectLogging: true,
		},
		{
			name: "duplicate provider registration",
			setupManager: func() Manager {
				mockLogger := &MockLogger{}
				mockMetrics := &MockMetrics{}

				mgr := NewManager(mockLogger, mockMetrics)

				// Register the provider first time
				mockProvider := &MockAuthenticationProvider{
					providerType: ProviderTypePassword,
				}
				mgr.RegisterProvider(mockProvider)

				return mgr
			},
			provider: &MockAuthenticationProvider{
				providerType: ProviderTypePassword,
			},
			expectedError: "provider of type password is already registered",
			expectLogging: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := tt.setupManager()
			err := manager.RegisterProvider(tt.provider)

			if tt.expectedError != "" {
				if err == nil {
					t.Fatalf("Expected error containing '%s', got nil", tt.expectedError)
				}
				if !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.expectedError, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("Expected no error, got %v", err)
				}
			}

			// Verify the provider was registered (or not)
			hasProvider := manager.HasProvider(tt.provider.GetProviderType())
			if tt.expectedError == "" {
				if !hasProvider {
					t.Error("Expected provider to be registered")
				}
			}
		})
	}
}

func TestManager_GetProvider(t *testing.T) {
	tests := []struct {
		name         string
		setupManager func() Manager
		providerType ProviderType
		expectError  bool
	}{
		{
			name: "get existing provider",
			setupManager: func() Manager {
				mockLogger := &MockLogger{}
				mockMetrics := &MockMetrics{}

				mgr := NewManager(mockLogger, mockMetrics)

				mockProvider := &MockAuthenticationProvider{
					providerType: ProviderTypePassword,
				}
				mgr.RegisterProvider(mockProvider)

				return mgr
			},
			providerType: ProviderTypePassword,
			expectError:  false,
		},
		{
			name: "get non-existent provider",
			setupManager: func() Manager {
				mockLogger := &MockLogger{}
				mockMetrics := &MockMetrics{}
				return NewManager(mockLogger, mockMetrics)
			},
			providerType: ProviderTypeOAuth,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := tt.setupManager()
			provider, err := manager.GetProvider(tt.providerType)

			if tt.expectError {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				if provider != nil {
					t.Error("Expected nil provider when error occurs")
				}
				if !strings.Contains(err.Error(), "no provider registered") {
					t.Errorf("Expected error to contain 'no provider registered', got '%s'", err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("Expected no error, got %v", err)
				}
				if provider == nil {
					t.Fatal("Expected provider, got nil")
				}
				if provider.GetProviderType() != tt.providerType {
					t.Errorf("Expected provider type %s, got %s", tt.providerType, provider.GetProviderType())
				}
			}
		})
	}
}

func TestManager_Authenticate(t *testing.T) {
	tests := []struct {
		name         string
		setupManager func() (Manager, *MockAuthenticationProvider, *MockMetrics)
		request      *AuthenticationRequest
		expectError  bool
		errorType    string
	}{
		{
			name: "successful authentication",
			setupManager: func() (Manager, *MockAuthenticationProvider, *MockMetrics) {
				mockLogger := &MockLogger{}
				mockMetrics := &MockMetrics{}

				mgr := NewManager(mockLogger, mockMetrics)

				mockProvider := &MockAuthenticationProvider{
					providerType: ProviderTypePassword,
					authenticateReturn: &AuthenticationResult{
						UserID:       "user123",
						ProviderType: ProviderTypePassword,
					},
					authenticateError: nil,
				}

				mgr.RegisterProvider(mockProvider)

				return mgr, mockProvider, mockMetrics
			},
			request: &AuthenticationRequest{
				Identifier:   "test@example.com",
				Credentials:  "testpassword",
				ProviderType: ProviderTypePassword,
			},
			expectError: false,
		},
		{
			name: "provider not found",
			setupManager: func() (Manager, *MockAuthenticationProvider, *MockMetrics) {
				mockLogger := &MockLogger{}
				mockMetrics := &MockMetrics{}

				mgr := NewManager(mockLogger, mockMetrics)

				return mgr, nil, mockMetrics
			},
			request: &AuthenticationRequest{
				Identifier:   "test@example.com",
				Credentials:  "testpassword",
				ProviderType: ProviderTypeOAuth,
			},
			expectError: true,
			errorType:   "ValidationError",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, mockProvider, _ := tt.setupManager()

			result, err := manager.Authenticate(context.Background(), tt.request)

			if tt.expectError {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				if result != nil {
					t.Error("Expected nil result when error occurs")
				}
				if tt.errorType == "ValidationError" {
					errorCode := errors.GetErrorCode(err)
					if errorCode != errors.CodeValidationFailed {
						t.Errorf("Expected ValidationError code, got %s", errorCode)
					}
				}
			} else {
				if err != nil {
					t.Fatalf("Expected no error, got %v", err)
				}
				if result == nil {
					t.Fatal("Expected result, got nil")
				}
				if result.ProviderType != tt.request.ProviderType {
					t.Errorf("Expected provider type %s, got %s", tt.request.ProviderType, result.ProviderType)
				}

				// Verify mock was called
				if mockProvider != nil {
					if len(mockProvider.authenticateCalls) != 1 {
						t.Errorf("Expected 1 authenticate call, got %d", len(mockProvider.authenticateCalls))
					}
				}
			}
		})
	}
}

func TestManager_ValidateCredentials(t *testing.T) {
	mockLogger := &MockLogger{}
	mockMetrics := &MockMetrics{}

	mgr := NewManager(mockLogger, mockMetrics)

	mockProvider := &MockAuthenticationProvider{
		providerType:             ProviderTypePassword,
		validateCredentialsError: nil,
	}

	err := mgr.RegisterProvider(mockProvider)
	if err != nil {
		t.Fatalf("Failed to register provider: %v", err)
	}

	userInfo := &UserInfo{
		UserID:    "user123",
		Email:     "test@example.com",
		FirstName: "Test",
		LastName:  "User",
	}

	err = mgr.ValidateCredentials(context.Background(), ProviderTypePassword, "testpassword", userInfo)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify mock was called
	if len(mockProvider.validateCredentialsCalls) != 1 {
		t.Errorf("Expected 1 validate credentials call, got %d", len(mockProvider.validateCredentialsCalls))
	}
}

func TestManager_ListProviders(t *testing.T) {
	mockLogger := &MockLogger{}
	mockMetrics := &MockMetrics{}

	mgr := NewManager(mockLogger, mockMetrics)

	// Initially empty
	providers := mgr.ListProviders()
	if len(providers) != 0 {
		t.Errorf("Expected empty provider list, got %d providers", len(providers))
	}

	// Add a provider
	mockProvider := &MockAuthenticationProvider{
		providerType: ProviderTypePassword,
	}

	err := mgr.RegisterProvider(mockProvider)
	if err != nil {
		t.Fatalf("Failed to register provider: %v", err)
	}

	providers = mgr.ListProviders()
	if len(providers) != 1 {
		t.Errorf("Expected 1 provider, got %d", len(providers))
	}

	found := false
	for _, p := range providers {
		if p == ProviderTypePassword {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to find ProviderTypePassword in provider list")
	}
}

func TestManager_HasProvider(t *testing.T) {
	mockLogger := &MockLogger{}
	mockMetrics := &MockMetrics{}

	mgr := NewManager(mockLogger, mockMetrics)

	// Provider doesn't exist
	if mgr.HasProvider(ProviderTypePassword) {
		t.Error("Expected HasProvider to return false for non-existent provider")
	}

	// Add provider
	mockProvider := &MockAuthenticationProvider{
		providerType: ProviderTypePassword,
	}

	err := mgr.RegisterProvider(mockProvider)
	if err != nil {
		t.Fatalf("Failed to register provider: %v", err)
	}

	// Provider exists
	if !mgr.HasProvider(ProviderTypePassword) {
		t.Error("Expected HasProvider to return true for existing provider")
	}
	if mgr.HasProvider(ProviderTypeOAuth) {
		t.Error("Expected HasProvider to return false for non-existent OAuth provider")
	}
}
