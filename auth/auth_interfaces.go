// File: auth/interfaces.go
package auth

import (
	"context"
	"time"
)

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
	ValidateCredentials(ctx context.Context, providerType ProviderType, credentials any, userInfo *UserInfo) error

	// UpdateCredentials updates credentials using the specified provider
	UpdateCredentials(ctx context.Context, req *CredentialUpdateRequest) ([]byte, error)

	// PrepareCredentials prepares credentials for storage using the specified provider
	PrepareCredentials(ctx context.Context, providerType ProviderType, credentials any) ([]byte, error)

	// ListProviders returns a list of registered provider types
	ListProviders() []ProviderType

	// HasProvider checks if a provider of the specified type is registered
	HasProvider(providerType ProviderType) bool
}

// AuthenticationProvider defines the interface for different authentication methods.
// This abstraction allows the user management system to support multiple authentication
// providers (password, OAuth, SAML, etc.) without coupling to specific implementations.
//
// Best Practice: Interface Segregation Principle - this interface focuses solely on
// authentication concerns, keeping it minimal and focused.
type AuthenticationProvider interface {
	// Authenticate verifies user credentials and returns authentication result.
	// The credentials parameter is provider-specific (e.g., password, OAuth token, etc.).
	// The storedAuthData parameter contains the raw serialized auth data for this provider.
	// Returns AuthenticationResult with user information and session data on success.
	Authenticate(ctx context.Context, identifier string, credentials any, storedAuthData []byte) (*AuthenticationResult, error)

	// ValidateCredentials checks if the provided credentials meet the provider's requirements.
	// This is used during user registration or credential updates.
	// The userInfo parameter provides context for validation (e.g., preventing password reuse).
	ValidateCredentials(ctx context.Context, credentials any, userInfo *UserInfo) error

	// UpdateCredentials updates the user's credentials for this provider.
	// The oldCredentials parameter is used for verification before updating.
	// The storedAuthData parameter contains the current serialized auth data.
	// Returns the new serialized credential data to be stored with the user.
	UpdateCredentials(ctx context.Context, userID string, oldCredentials, newCredentials any, storedAuthData []byte) ([]byte, error)

	// PrepareCredentials prepares credentials for storage (e.g., hashing passwords).
	// This method is called during user creation to transform raw credentials
	// into a format suitable for storage.
	// Returns serialized credential data ready for encryption and storage.
	PrepareCredentials(ctx context.Context, credentials any) ([]byte, error)

	// GetProviderType returns the type identifier for this authentication provider.
	// This is used for routing authentication requests to the correct provider.
	GetProviderType() ProviderType

	// SupportsCredentialUpdate returns true if this provider supports credential updates.
	// Some providers (like OAuth) may not support direct credential updates.
	SupportsCredentialUpdate() bool
}

// ProviderType represents the type of authentication provider.
type ProviderType string

const (
	// ProviderTypePassword represents password-based authentication
	ProviderTypePassword ProviderType = "password"
	// ProviderTypeOAuth represents OAuth-based authentication
	ProviderTypeOAuth ProviderType = "oauth"
	// ProviderTypeGoogle represents Google OAuth authentication
	ProviderTypeGoogle ProviderType = "google"
	// ProviderTypeAuth0 represents Auth0 authentication
	ProviderTypeAuth0 ProviderType = "auth0"
	// ProviderTypeSAML represents SAML-based authentication
	ProviderTypeSAML ProviderType = "saml"
)

// String returns the string representation of the provider type.
func (pt ProviderType) String() string {
	return string(pt)
}

// AuthenticationResult represents the result of a successful authentication.
type AuthenticationResult struct {
	// UserID is the unique identifier of the authenticated user
	UserID string `json:"user_id"`

	// ProviderType indicates which provider was used for authentication
	ProviderType ProviderType `json:"provider_type"`

	// ProviderUserID is the user identifier from the external provider (for OAuth, etc.)
	// For password authentication, this will be the same as UserID
	ProviderUserID string `json:"provider_user_id,omitempty"`

	// SessionData contains provider-specific session information
	SessionData map[string]any `json:"session_data,omitempty"`

	// ExpiresAt indicates when this authentication result expires (if applicable)
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// Metadata contains additional provider-specific information
	Metadata map[string]any `json:"metadata,omitempty"`
}

// UserInfo provides user context for credential validation.
// This follows the principle of providing minimal necessary information
// to authentication providers for validation purposes.
type UserInfo struct {
	// UserID is the unique identifier of the user
	UserID string `json:"user_id"`

	// FirstName is the user's first name (decrypted)
	FirstName string `json:"first_name"`

	// LastName is the user's last name (decrypted)
	LastName string `json:"last_name"`

	// Email is the user's email address (decrypted)
	Email string `json:"email"`

	// CreatedAt is when the user account was created
	CreatedAt time.Time `json:"created_at"`
}

// AuthenticationRequest represents a request to authenticate a user.
type AuthenticationRequest struct {
	// Identifier is the user identifier (email, username, etc.)
	Identifier string `json:"identifier"`

	// Credentials contains the authentication credentials (provider-specific)
	Credentials any `json:"credentials"`

	// ProviderType specifies which provider to use for authentication
	ProviderType ProviderType `json:"provider_type"`

	// Metadata contains additional request context
	Metadata map[string]any `json:"metadata,omitempty"`
}

// CredentialUpdateRequest represents a request to update user credentials.
type CredentialUpdateRequest struct {
	// UserID is the unique identifier of the user
	UserID string `json:"user_id"`

	// OldCredentials contains the current credentials for verification
	OldCredentials any `json:"old_credentials"`

	// NewCredentials contains the new credentials to set
	NewCredentials any `json:"new_credentials"`

	// ProviderType specifies which provider to use
	ProviderType ProviderType `json:"provider_type"`
}
