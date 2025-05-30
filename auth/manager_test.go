package auth

import (
	"context"
	"testing"
	"time"

	"github.com/MichaelAJay/go-logger"
	"github.com/MichaelAJay/go-metrics"
	"github.com/MichaelAJay/go-user-management/errors"
)

// MockAuthenticationProvider implements AuthenticationProvider for testing
type MockAuthenticationProvider struct {
	providerType             ProviderType
	authenticateFunc         func(ctx context.Context, identifier string, credentials interface{}) (*AuthenticationResult, error)
	validateCredentialsFunc  func(ctx context.Context, credentials interface{}, userInfo *UserInfo) error
	updateCredentialsFunc    func(ctx context.Context, userID string, oldCredentials, newCredentials interface{}) (interface{}, error)
	prepareCredentialsFunc   func(ctx context.Context, credentials interface{}) (interface{}, error)
	supportsCredentialUpdate bool
}

func (m *MockAuthenticationProvider) Authenticate(ctx context.Context, identifier string, credentials interface{}) (*AuthenticationResult, error) {
	if m.authenticateFunc != nil {
		return m.authenticateFunc(ctx, identifier, credentials)
	}
	return &AuthenticationResult{
		UserID:       "test-user-id",
		ProviderType: m.providerType,
	}, nil
}

func (m *MockAuthenticationProvider) ValidateCredentials(ctx context.Context, credentials interface{}, userInfo *UserInfo) error {
	if m.validateCredentialsFunc != nil {
		return m.validateCredentialsFunc(ctx, credentials, userInfo)
	}
	return nil
}

func (m *MockAuthenticationProvider) UpdateCredentials(ctx context.Context, userID string, oldCredentials, newCredentials interface{}) (interface{}, error) {
	if m.updateCredentialsFunc != nil {
		return m.updateCredentialsFunc(ctx, userID, oldCredentials, newCredentials)
	}
	return newCredentials, nil
}

func (m *MockAuthenticationProvider) PrepareCredentials(ctx context.Context, credentials interface{}) (interface{}, error) {
	if m.prepareCredentialsFunc != nil {
		return m.prepareCredentialsFunc(ctx, credentials)
	}
	return credentials, nil
}

func (m *MockAuthenticationProvider) GetProviderType() ProviderType {
	return m.providerType
}

func (m *MockAuthenticationProvider) SupportsCredentialUpdate() bool {
	return m.supportsCredentialUpdate
}

// MockLogger implements logger.Logger for testing
type MockLogger struct {
	logs []LogEntry
}

type LogEntry struct {
	Level   string
	Message string
	Fields  []logger.Field
}

func (m *MockLogger) Debug(msg string, fields ...logger.Field) {
	m.logs = append(m.logs, LogEntry{Level: "DEBUG", Message: msg, Fields: fields})
}

func (m *MockLogger) Info(msg string, fields ...logger.Field) {
	m.logs = append(m.logs, LogEntry{Level: "INFO", Message: msg, Fields: fields})
}

func (m *MockLogger) Warn(msg string, fields ...logger.Field) {
	m.logs = append(m.logs, LogEntry{Level: "WARN", Message: msg, Fields: fields})
}

func (m *MockLogger) Error(msg string, fields ...logger.Field) {
	m.logs = append(m.logs, LogEntry{Level: "ERROR", Message: msg, Fields: fields})
}

func (m *MockLogger) Fatal(msg string, fields ...logger.Field) {
	m.logs = append(m.logs, LogEntry{Level: "FATAL", Message: msg, Fields: fields})
}

func (m *MockLogger) With(fields ...logger.Field) logger.Logger {
	return m
}

func (m *MockLogger) WithContext(ctx context.Context) logger.Logger {
	return m
}

// MockMetrics implements metrics.Registry for testing
type MockMetrics struct {
	counters   map[string]*MockCounter
	timers     map[string]*MockTimer
	gauges     map[string]*MockGauge
	histograms map[string]*MockHistogram
}

func NewMockMetrics() *MockMetrics {
	return &MockMetrics{
		counters:   make(map[string]*MockCounter),
		timers:     make(map[string]*MockTimer),
		gauges:     make(map[string]*MockGauge),
		histograms: make(map[string]*MockHistogram),
	}
}

func (m *MockMetrics) Counter(opts metrics.Options) metrics.Counter {
	if counter, exists := m.counters[opts.Name]; exists {
		return counter
	}
	counter := &MockCounter{name: opts.Name}
	m.counters[opts.Name] = counter
	return counter
}

func (m *MockMetrics) Timer(opts metrics.Options) metrics.Timer {
	if timer, exists := m.timers[opts.Name]; exists {
		return timer
	}
	timer := &MockTimer{name: opts.Name}
	m.timers[opts.Name] = timer
	return timer
}

func (m *MockMetrics) Gauge(opts metrics.Options) metrics.Gauge {
	if gauge, exists := m.gauges[opts.Name]; exists {
		return gauge
	}
	gauge := &MockGauge{name: opts.Name}
	m.gauges[opts.Name] = gauge
	return gauge
}

func (m *MockMetrics) Histogram(opts metrics.Options) metrics.Histogram {
	if histogram, exists := m.histograms[opts.Name]; exists {
		return histogram
	}
	histogram := &MockHistogram{name: opts.Name}
	m.histograms[opts.Name] = histogram
	return histogram
}

func (m *MockMetrics) Unregister(name string) {
	delete(m.counters, name)
	delete(m.timers, name)
	delete(m.gauges, name)
	delete(m.histograms, name)
}

func (m *MockMetrics) Each(fn func(metrics.Metric)) {
	for _, counter := range m.counters {
		fn(counter)
	}
	for _, timer := range m.timers {
		fn(timer)
	}
	for _, gauge := range m.gauges {
		fn(gauge)
	}
	for _, histogram := range m.histograms {
		fn(histogram)
	}
}

// Mock metric implementations
type MockCounter struct {
	name  string
	value float64
}

func (c *MockCounter) Inc()                                   { c.value++ }
func (c *MockCounter) Add(value float64)                      { c.value += value }
func (c *MockCounter) With(tags metrics.Tags) metrics.Counter { return c }
func (c *MockCounter) Name() string                           { return c.name }
func (c *MockCounter) Description() string                    { return "" }
func (c *MockCounter) Type() metrics.Type                     { return "counter" }
func (c *MockCounter) Tags() metrics.Tags                     { return nil }

type MockTimer struct {
	name      string
	durations []time.Duration
}

func (t *MockTimer) Record(d time.Duration)      { t.durations = append(t.durations, d) }
func (t *MockTimer) RecordSince(start time.Time) { t.Record(time.Since(start)) }
func (t *MockTimer) Time(fn func()) time.Duration {
	start := time.Now()
	fn()
	duration := time.Since(start)
	t.Record(duration)
	return duration
}
func (t *MockTimer) With(tags metrics.Tags) metrics.Timer { return t }
func (t *MockTimer) Name() string                         { return t.name }
func (t *MockTimer) Description() string                  { return "" }
func (t *MockTimer) Type() metrics.Type                   { return "timer" }
func (t *MockTimer) Tags() metrics.Tags                   { return nil }

type MockGauge struct {
	name  string
	value float64
}

func (g *MockGauge) Set(value float64)                    { g.value = value }
func (g *MockGauge) Add(value float64)                    { g.value += value }
func (g *MockGauge) Inc()                                 { g.value++ }
func (g *MockGauge) Dec()                                 { g.value-- }
func (g *MockGauge) With(tags metrics.Tags) metrics.Gauge { return g }
func (g *MockGauge) Name() string                         { return g.name }
func (g *MockGauge) Description() string                  { return "" }
func (g *MockGauge) Type() metrics.Type                   { return "gauge" }
func (g *MockGauge) Tags() metrics.Tags                   { return nil }

type MockHistogram struct {
	name   string
	values []float64
}

func (h *MockHistogram) Observe(value float64)                    { h.values = append(h.values, value) }
func (h *MockHistogram) With(tags metrics.Tags) metrics.Histogram { return h }
func (h *MockHistogram) Name() string                             { return h.name }
func (h *MockHistogram) Description() string                      { return "" }
func (h *MockHistogram) Type() metrics.Type                       { return "histogram" }
func (h *MockHistogram) Tags() metrics.Tags                       { return nil }

func TestNewManager(t *testing.T) {
	logger := &MockLogger{}
	metrics := NewMockMetrics()

	manager := NewManager(logger, metrics)

	if manager == nil {
		t.Error("Expected manager to be created")
	}
	if manager == nil {
		t.Fatal("Expected providers map to be initialized")
	}
	providers := manager.ListProviders()
	if len(providers) != 0 {
		t.Error("Expected providers map to be empty initially")
	}
}

func TestManager_RegisterProvider(t *testing.T) {
	logger := &MockLogger{}
	metrics := NewMockMetrics()
	manager := NewManager(logger, metrics)

	provider := &MockAuthenticationProvider{
		providerType: ProviderTypePassword,
	}

	err := manager.RegisterProvider(provider)
	if err != nil {
		t.Errorf("Expected no error registering provider, got %v", err)
	}

	// Test through interface methods
	providers := manager.ListProviders()
	if len(providers) != 1 {
		t.Errorf("Expected 1 provider, got %d", len(providers))
	}

	// Verify the provider is registered using HasProvider
	if !manager.HasProvider(ProviderTypePassword) {
		t.Error("Expected password provider to be registered")
	}

	// Verify we can get the provider
	retrievedProvider, err := manager.GetProvider(ProviderTypePassword)
	if err != nil {
		t.Errorf("Expected to retrieve registered provider, got error: %v", err)
	}
	if retrievedProvider != provider {
		t.Error("Expected to get the same provider instance")
	}

	// Verify logging
	if len(logger.logs) == 0 {
		t.Error("Expected log entry for provider registration")
	}
}

func TestManager_RegisterProvider_Duplicate(t *testing.T) {
	logger := &MockLogger{}
	metrics := NewMockMetrics()
	manager := NewManager(logger, metrics)

	provider1 := &MockAuthenticationProvider{
		providerType: ProviderTypePassword,
	}
	provider2 := &MockAuthenticationProvider{
		providerType: ProviderTypePassword,
	}

	// Register first provider
	err := manager.RegisterProvider(provider1)
	if err != nil {
		t.Errorf("Expected no error registering first provider, got %v", err)
	}

	// Try to register duplicate
	err = manager.RegisterProvider(provider2)
	if err == nil {
		t.Error("Expected error when registering duplicate provider")
	}

	// Test through interface methods
	providers := manager.ListProviders()
	if len(providers) != 1 {
		t.Errorf("Expected 1 provider after duplicate registration, got %d", len(providers))
	}
}

func TestManager_GetProvider(t *testing.T) {
	logger := &MockLogger{}
	metrics := NewMockMetrics()
	manager := NewManager(logger, metrics)

	provider := &MockAuthenticationProvider{
		providerType: ProviderTypePassword,
	}

	// Register provider
	manager.RegisterProvider(provider)

	// Get existing provider
	retrievedProvider, err := manager.GetProvider(ProviderTypePassword)
	if err != nil {
		t.Errorf("Expected no error getting provider, got %v", err)
	}
	if retrievedProvider != provider {
		t.Error("Expected to get the same provider instance")
	}

	// Try to get non-existent provider
	_, err = manager.GetProvider(ProviderTypeOAuth)
	if err == nil {
		t.Error("Expected error when getting non-existent provider")
	}
}

func TestManager_Authenticate(t *testing.T) {
	logger := &MockLogger{}
	metrics := NewMockMetrics()
	manager := NewManager(logger, metrics)

	expectedResult := &AuthenticationResult{
		UserID:       "test-user-id",
		ProviderType: ProviderTypePassword,
	}

	provider := &MockAuthenticationProvider{
		providerType: ProviderTypePassword,
		authenticateFunc: func(ctx context.Context, identifier string, credentials interface{}) (*AuthenticationResult, error) {
			return expectedResult, nil
		},
	}

	manager.RegisterProvider(provider)

	req := &AuthenticationRequest{
		Identifier:   "test@example.com",
		Credentials:  map[string]interface{}{"password": "test123"},
		ProviderType: ProviderTypePassword,
	}

	result, err := manager.Authenticate(context.Background(), req)
	if err != nil {
		t.Errorf("Expected no error during authentication, got %v", err)
	}
	if result == nil {
		t.Fatal("Expected authentication result")
	}
	if result.UserID != expectedResult.UserID {
		t.Errorf("Expected UserID %s, got %s", expectedResult.UserID, result.UserID)
	}
	if result.ProviderType != ProviderTypePassword {
		t.Errorf("Expected ProviderType %s, got %s", ProviderTypePassword, result.ProviderType)
	}

	// Verify metrics
	if counter, exists := metrics.counters["auth_manager.authenticate.success"]; !exists || counter.value != 1 {
		t.Error("Expected success counter to be incremented")
	}
}

func TestManager_Authenticate_ProviderNotFound(t *testing.T) {
	logger := &MockLogger{}
	metrics := NewMockMetrics()
	manager := NewManager(logger, metrics)

	req := &AuthenticationRequest{
		Identifier:   "test@example.com",
		Credentials:  map[string]interface{}{"password": "test123"},
		ProviderType: ProviderTypePassword,
	}

	_, err := manager.Authenticate(context.Background(), req)
	if err == nil {
		t.Error("Expected error when provider not found")
	}

	// Verify metrics
	if counter, exists := metrics.counters["auth_manager.authenticate.provider_not_found"]; !exists || counter.value != 1 {
		t.Error("Expected provider_not_found counter to be incremented")
	}
}

func TestManager_Authenticate_ProviderError(t *testing.T) {
	logger := &MockLogger{}
	metrics := NewMockMetrics()
	manager := NewManager(logger, metrics)

	provider := &MockAuthenticationProvider{
		providerType: ProviderTypePassword,
		authenticateFunc: func(ctx context.Context, identifier string, credentials interface{}) (*AuthenticationResult, error) {
			return nil, errors.NewInvalidCredentialsError()
		},
	}

	manager.RegisterProvider(provider)

	req := &AuthenticationRequest{
		Identifier:   "test@example.com",
		Credentials:  map[string]interface{}{"password": "wrong"},
		ProviderType: ProviderTypePassword,
	}

	_, err := manager.Authenticate(context.Background(), req)
	if err == nil {
		t.Error("Expected error when provider authentication fails")
	}

	// Verify metrics
	if counter, exists := metrics.counters["auth_manager.authenticate.failed"]; !exists || counter.value != 1 {
		t.Error("Expected failed counter to be incremented")
	}
}

func TestManager_ValidateCredentials(t *testing.T) {
	logger := &MockLogger{}
	metrics := NewMockMetrics()
	manager := NewManager(logger, metrics)

	provider := &MockAuthenticationProvider{
		providerType: ProviderTypePassword,
		validateCredentialsFunc: func(ctx context.Context, credentials interface{}, userInfo *UserInfo) error {
			return nil
		},
	}

	manager.RegisterProvider(provider)

	userInfo := &UserInfo{
		UserID:    "test-user-id",
		FirstName: "John",
		LastName:  "Doe",
		Email:     "john.doe@example.com",
	}

	err := manager.ValidateCredentials(context.Background(), ProviderTypePassword, map[string]interface{}{"password": "test123"}, userInfo)
	if err != nil {
		t.Errorf("Expected no error during credential validation, got %v", err)
	}
}

func TestManager_ValidateCredentials_ProviderNotFound(t *testing.T) {
	logger := &MockLogger{}
	metrics := NewMockMetrics()
	manager := NewManager(logger, metrics)

	userInfo := &UserInfo{
		UserID: "test-user-id",
		Email:  "john.doe@example.com",
	}

	err := manager.ValidateCredentials(context.Background(), ProviderTypePassword, map[string]interface{}{"password": "test123"}, userInfo)
	if err == nil {
		t.Error("Expected error when provider not found")
	}
}

func TestManager_UpdateCredentials(t *testing.T) {
	logger := &MockLogger{}
	metrics := NewMockMetrics()
	manager := NewManager(logger, metrics)

	provider := &MockAuthenticationProvider{
		providerType:             ProviderTypePassword,
		supportsCredentialUpdate: true,
		updateCredentialsFunc: func(ctx context.Context, userID string, oldCredentials, newCredentials interface{}) (interface{}, error) {
			return newCredentials, nil
		},
	}

	manager.RegisterProvider(provider)

	req := &CredentialUpdateRequest{
		UserID:         "test-user-id",
		OldCredentials: map[string]interface{}{"password": "old123"},
		NewCredentials: map[string]interface{}{"password": "new123"},
		ProviderType:   ProviderTypePassword,
	}

	result, err := manager.UpdateCredentials(context.Background(), req)
	if err != nil {
		t.Errorf("Expected no error during credential update, got %v", err)
	}
	if result == nil {
		t.Error("Expected credential update result")
	}
}

func TestManager_UpdateCredentials_NotSupported(t *testing.T) {
	logger := &MockLogger{}
	metrics := NewMockMetrics()
	manager := NewManager(logger, metrics)

	provider := &MockAuthenticationProvider{
		providerType:             ProviderTypeOAuth,
		supportsCredentialUpdate: false,
	}

	manager.RegisterProvider(provider)

	req := &CredentialUpdateRequest{
		UserID:         "test-user-id",
		OldCredentials: map[string]interface{}{"token": "old_token"},
		NewCredentials: map[string]interface{}{"token": "new_token"},
		ProviderType:   ProviderTypeOAuth,
	}

	_, err := manager.UpdateCredentials(context.Background(), req)
	if err == nil {
		t.Error("Expected error when provider doesn't support credential updates")
	}
}

func TestManager_PrepareCredentials(t *testing.T) {
	logger := &MockLogger{}
	metrics := NewMockMetrics()
	manager := NewManager(logger, metrics)

	provider := &MockAuthenticationProvider{
		providerType: ProviderTypePassword,
		prepareCredentialsFunc: func(ctx context.Context, credentials interface{}) (interface{}, error) {
			return "prepared_credentials", nil
		},
	}

	manager.RegisterProvider(provider)

	result, err := manager.PrepareCredentials(context.Background(), ProviderTypePassword, map[string]interface{}{"password": "test123"})
	if err != nil {
		t.Errorf("Expected no error during credential preparation, got %v", err)
	}
	if result != "prepared_credentials" {
		t.Errorf("Expected prepared credentials, got %v", result)
	}
}

func TestManager_ListProviders(t *testing.T) {
	logger := &MockLogger{}
	metrics := NewMockMetrics()
	manager := NewManager(logger, metrics)

	provider1 := &MockAuthenticationProvider{providerType: ProviderTypePassword}
	provider2 := &MockAuthenticationProvider{providerType: ProviderTypeOAuth}

	manager.RegisterProvider(provider1)
	manager.RegisterProvider(provider2)

	providers := manager.ListProviders()
	if len(providers) != 2 {
		t.Errorf("Expected 2 providers, got %d", len(providers))
	}

	// Check that both providers are in the list
	hasPassword := false
	hasOAuth := false
	for _, providerType := range providers {
		if providerType == ProviderTypePassword {
			hasPassword = true
		}
		if providerType == ProviderTypeOAuth {
			hasOAuth = true
		}
	}
	if !hasPassword {
		t.Error("Expected password provider in list")
	}
	if !hasOAuth {
		t.Error("Expected OAuth provider in list")
	}
}

func TestManager_HasProvider(t *testing.T) {
	logger := &MockLogger{}
	metrics := NewMockMetrics()
	manager := NewManager(logger, metrics)

	provider := &MockAuthenticationProvider{providerType: ProviderTypePassword}
	manager.RegisterProvider(provider)

	if !manager.HasProvider(ProviderTypePassword) {
		t.Error("Expected manager to have password provider")
	}
	if manager.HasProvider(ProviderTypeOAuth) {
		t.Error("Expected manager to not have OAuth provider")
	}
}

func TestProviderType_String(t *testing.T) {
	tests := []struct {
		providerType ProviderType
		expected     string
	}{
		{ProviderTypePassword, "password"},
		{ProviderTypeOAuth, "oauth"},
		{ProviderTypeGoogle, "google"},
		{ProviderTypeAuth0, "auth0"},
		{ProviderTypeSAML, "saml"},
	}

	for _, tt := range tests {
		t.Run(string(tt.providerType), func(t *testing.T) {
			if got := tt.providerType.String(); got != tt.expected {
				t.Errorf("ProviderType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}
