# Go User Management - Refactored Authentication Architecture

This document describes the refactored user management system that separates authentication logic from user management through a pluggable authentication provider architecture.

## Architecture Overview

The refactored system follows these key principles:

- **Separation of Concerns**: Authentication logic is completely separated from user management
- **Strategy Pattern**: Different authentication methods can be used interchangeably
- **Open/Closed Principle**: New authentication providers can be added without modifying existing code
- **Dependency Injection**: All dependencies are injected, making the system testable and flexible

## Core Components

### 1. Authentication Provider Interface (`auth/provider.go`)

The `AuthenticationProvider` interface defines the contract for all authentication methods:

```go
type AuthenticationProvider interface {
    Authenticate(ctx context.Context, identifier string, credentials interface{}) (*AuthenticationResult, error)
    ValidateCredentials(ctx context.Context, credentials interface{}, userInfo *UserInfo) error
    UpdateCredentials(ctx context.Context, userID string, oldCredentials, newCredentials interface{}) (interface{}, error)
    PrepareCredentials(ctx context.Context, credentials interface{}) (interface{}, error)
    GetProviderType() ProviderType
    SupportsCredentialUpdate() bool
}
```

### 2. Authentication Manager (`auth/manager.go`)

The `Manager` coordinates between different authentication providers using the Registry pattern:

```go
type Manager struct {
    providers map[ProviderType]AuthenticationProvider
    logger    logger.Logger
    metrics   metrics.Registry
}
```

### 3. Password Provider (`auth/providers/password/provider.go`)

A concrete implementation for password-based authentication that handles:
- Password hashing and verification
- Password strength validation
- Credential updates
- Security best practices

### 4. Updated User Entity (`user/user.go`)

The User entity now supports multiple authentication providers:

```go
type User struct {
    // ... other fields ...
    
    // AuthenticationData stores provider-specific authentication data
    AuthenticationData map[auth.ProviderType]interface{} `json:"-"`
    
    // PrimaryAuthProvider indicates the primary authentication provider
    PrimaryAuthProvider auth.ProviderType `json:"primary_auth_provider"`
}
```

## Usage Examples

### Setting Up the System

```go
// Create authentication manager
authManager := auth.NewManager(logger, metrics)

// Create and register password provider
passwordProvider := password.NewProvider(encrypter, logger, metrics, config)
authManager.RegisterProvider(passwordProvider)

// Create user service with authentication manager
userService := user.NewUserService(
    repository,
    encrypter,
    logger,
    cache,
    config,
    metrics,
    authManager,
)
```

### Creating a User with Password Authentication

```go
passwordCreds := &password.PasswordCredentials{
    Password: "SecurePassword123!",
}

createReq := &user.CreateUserRequest{
    FirstName:              "John",
    LastName:               "Doe",
    Email:                  "john.doe@example.com",
    Credentials:            passwordCreds,
    AuthenticationProvider: auth.ProviderTypePassword,
}

userResp, err := userService.CreateUser(ctx, createReq)
```

### Authenticating a User

```go
authReq := &user.AuthenticateRequest{
    Email:                  "john.doe@example.com",
    Credentials:            "SecurePassword123!",
    AuthenticationProvider: auth.ProviderTypePassword,
}

authResp, err := userService.AuthenticateUser(ctx, authReq)
```

### Updating Credentials

```go
updateCredsReq := &user.UpdateCredentialsRequest{
    CurrentCredentials:     &password.PasswordCredentials{Password: "OldPassword"},
    NewCredentials:         &password.PasswordCredentials{Password: "NewPassword"},
    AuthenticationProvider: auth.ProviderTypePassword,
}

err := userService.UpdateCredentials(ctx, userID, updateCredsReq)
```

## Adding New Authentication Providers

To add a new authentication provider (e.g., OAuth, SAML):

1. **Create the Provider**: Implement the `AuthenticationProvider` interface
2. **Define Credentials**: Create provider-specific credential types
3. **Register Provider**: Add the provider to the authentication manager
4. **Use Provider**: Specify the provider type in requests

Example OAuth provider structure:

```go
type OAuthProvider struct {
    clientID     string
    clientSecret string
    redirectURL  string
    // ... other OAuth-specific fields
}

func (p *OAuthProvider) Authenticate(ctx context.Context, identifier string, credentials interface{}) (*auth.AuthenticationResult, error) {
    // OAuth-specific authentication logic
}

func (p *OAuthProvider) GetProviderType() auth.ProviderType {
    return auth.ProviderTypeOAuth
}

// ... implement other interface methods
```

## Benefits of the Refactored Architecture

### 1. **Extensibility**
- Easy to add new authentication methods
- No changes required to existing user management code
- Support for multiple authentication providers per user

### 2. **Maintainability**
- Clear separation of concerns
- Authentication logic is isolated and testable
- Reduced coupling between components

### 3. **Flexibility**
- Users can have multiple authentication methods
- Different authentication providers for different use cases
- Easy to switch or upgrade authentication methods

### 4. **Security**
- Provider-specific security implementations
- Centralized authentication management
- Consistent security practices across providers

## Migration from Old System

The refactored system maintains backward compatibility while providing new capabilities:

1. **Existing Password Users**: Automatically migrated to use the password provider
2. **API Compatibility**: Request/response structures updated but maintain core functionality
3. **Database Schema**: User entity updated to support multiple authentication providers

## Configuration

Authentication providers can be configured through the config system:

```yaml
# Password provider configuration
password_provider:
  min_length: 8
  max_length: 128
  require_upper: true
  require_lower: true
  require_number: true
  require_special: true

# OAuth provider configuration (example)
oauth_provider:
  client_id: "your-client-id"
  client_secret: "your-client-secret"
  redirect_url: "https://your-app.com/auth/callback"
```

## Testing

The refactored architecture improves testability:

```go
// Mock authentication provider for testing
type MockAuthProvider struct{}

func (m *MockAuthProvider) Authenticate(ctx context.Context, identifier string, credentials interface{}) (*auth.AuthenticationResult, error) {
    // Mock implementation
}

// Use in tests
authManager := auth.NewManager(logger, metrics)
authManager.RegisterProvider(&MockAuthProvider{})
```

## Best Practices

1. **Provider Registration**: Register all providers during application startup
2. **Error Handling**: Implement comprehensive error handling in providers
3. **Security**: Follow security best practices in each provider implementation
4. **Logging**: Use structured logging for authentication events
5. **Metrics**: Track authentication metrics for monitoring and alerting

## Future Enhancements

The architecture supports future enhancements such as:

- Multi-factor authentication (MFA)
- Social login providers (Google, Facebook, etc.)
- Enterprise SSO (SAML, LDAP)
- Passwordless authentication
- Biometric authentication

## Conclusion

The refactored authentication architecture provides a solid foundation for scalable, maintainable, and secure user management. The separation of concerns and pluggable design make it easy to adapt to changing authentication requirements while maintaining system reliability and security. 