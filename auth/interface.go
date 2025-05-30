// File: auth/interfaces.go
package auth

import "context"

// Manager defines the interface for authentication management.
// This interface allows for easier testing by enabling mock implementations.
//
// Best Practice: Depend on interfaces, not concretions - this allows for
// easy testing and makes the code more flexible and maintainable.
type Manager interface {
	// RegisterProvider registers an authentication provider with the manager
	RegisterProvider(provider AuthenticationProvider) error

	// GetProvider returns the authentication provider for the specified type
	GetProvider(providerType ProviderType) (AuthenticationProvider, error)

	// Authenticate authenticates a user using the specified provider
	Authenticate(ctx context.Context, req *AuthenticationRequest) (*AuthenticationResult, error)

	// ValidateCredentials validates credentials using the specified provider
	ValidateCredentials(ctx context.Context, providerType ProviderType, credentials interface{}, userInfo *UserInfo) error

	// UpdateCredentials updates credentials using the specified provider
	UpdateCredentials(ctx context.Context, req *CredentialUpdateRequest) (interface{}, error)

	// PrepareCredentials prepares credentials for storage using the specified provider
	PrepareCredentials(ctx context.Context, providerType ProviderType, credentials interface{}) (interface{}, error)

	// ListProviders returns a list of registered provider types
	ListProviders() []ProviderType

	// HasProvider checks if a provider of the specified type is registered
	HasProvider(providerType ProviderType) bool
}
