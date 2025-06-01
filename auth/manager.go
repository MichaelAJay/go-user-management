package auth

import (
	"context"
	"fmt"

	"github.com/MichaelAJay/go-logger"
	"github.com/MichaelAJay/go-metrics"
	"github.com/MichaelAJay/go-user-management/errors"
)

// manager coordinates authentication across multiple providers.
// This follows the Strategy pattern, allowing different authentication
// methods to be used interchangeably.
//
// Best Practice: Open/Closed Principle - new authentication providers
// can be added without modifying existing code.
type manager struct {
	providers map[ProviderType]AuthenticationProvider
	logger    logger.Logger
	metrics   metrics.Registry
}

// NewManager creates a new authentication manager that implements the Manager interface.
//
// Best Practice: Return interfaces, not concrete types - this makes the code
// more testable and flexible.
func NewManager(logger logger.Logger, metrics metrics.Registry) Manager {
	return &manager{
		providers: make(map[ProviderType]AuthenticationProvider),
		logger:    logger,
		metrics:   metrics,
	}
}

// RegisterProvider registers an authentication provider with the manager.
func (m *manager) RegisterProvider(provider AuthenticationProvider) error {
	providerType := provider.GetProviderType()

	if _, exists := m.providers[providerType]; exists {
		return fmt.Errorf("provider of type %s is already registered", providerType)
	}

	m.providers[providerType] = provider
	m.logger.Info("Authentication provider registered",
		logger.Field{Key: "provider_type", Value: string(providerType)})

	return nil
}

// GetProvider returns the authentication provider for the specified type.
func (m *manager) GetProvider(providerType ProviderType) (AuthenticationProvider, error) {
	provider, exists := m.providers[providerType]
	if !exists {
		return nil, fmt.Errorf("no provider registered for type %s", providerType)
	}

	return provider, nil
}

// Authenticate authenticates a user using the specified provider.
func (m *manager) Authenticate(ctx context.Context, req *AuthenticationRequest) (*AuthenticationResult, error) {
	provider, err := m.GetProvider(req.ProviderType)
	if err != nil {
		counter := m.metrics.Counter(metrics.Options{
			Name: "auth_manager.authenticate.provider_not_found",
		})
		counter.Inc()
		return nil, errors.NewValidationError("provider_type", err.Error())
	}

	// Note: This method is used when we don't have stored auth data (for external auth flows)
	// For user authentication with stored data, use the provider directly
	result, err := provider.Authenticate(ctx, req.Identifier, req.Credentials, nil)
	if err != nil {
		counter := m.metrics.Counter(metrics.Options{
			Name: "auth_manager.authenticate.failed",
			Tags: map[string]string{
				"provider_type": string(req.ProviderType),
			},
		})
		counter.Inc()
		return nil, err
	}

	// Ensure the result has the correct provider type
	result.ProviderType = req.ProviderType

	counter := m.metrics.Counter(metrics.Options{
		Name: "auth_manager.authenticate.success",
		Tags: map[string]string{
			"provider_type": string(req.ProviderType),
		},
	})
	counter.Inc()

	return result, nil
}

// ValidateCredentials validates credentials using the specified provider.
func (m *manager) ValidateCredentials(ctx context.Context, providerType ProviderType, credentials any, userInfo *UserInfo) error {
	provider, err := m.GetProvider(providerType)
	if err != nil {
		return errors.NewValidationError("provider_type", err.Error())
	}

	return provider.ValidateCredentials(ctx, credentials, userInfo)
}

// UpdateCredentials updates credentials using the specified provider.
func (m *manager) UpdateCredentials(ctx context.Context, req *CredentialUpdateRequest) (any, error) {
	provider, err := m.GetProvider(req.ProviderType)
	if err != nil {
		return nil, errors.NewValidationError("provider_type", err.Error())
	}

	if !provider.SupportsCredentialUpdate() {
		return nil, errors.NewValidationError("provider_type",
			fmt.Sprintf("provider %s does not support credential updates", req.ProviderType))
	}

	// Note: For credential updates, we need to pass the stored auth data
	// This should be provided in the request or retrieved from storage
	return provider.UpdateCredentials(ctx, req.UserID, req.OldCredentials, req.NewCredentials, nil) // TODO: Add StoredAuthData to request
}

// PrepareCredentials prepares credentials for storage using the specified provider.
func (m *manager) PrepareCredentials(ctx context.Context, providerType ProviderType, credentials any) (any, error) {
	provider, err := m.GetProvider(providerType)
	if err != nil {
		return nil, errors.NewValidationError("provider_type", err.Error())
	}

	return provider.PrepareCredentials(ctx, credentials)
}

// ListProviders returns a list of registered provider types.
func (m *manager) ListProviders() []ProviderType {
	types := make([]ProviderType, 0, len(m.providers))
	for providerType := range m.providers {
		types = append(types, providerType)
	}
	return types
}

// HasProvider checks if a provider of the specified type is registered.
func (m *manager) HasProvider(providerType ProviderType) bool {
	_, exists := m.providers[providerType]
	return exists
}

// Ensure manager implements Manager interface
var _ Manager = (*manager)(nil)
