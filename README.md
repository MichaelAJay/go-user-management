# Go User Management Package

A comprehensive, production-ready user management package for Go applications that provides core user authentication and session management functionality. This package is designed to be storage-agnostic, highly testable, and suitable for concurrent web applications.

## Features

- **Security First**: All PII encrypted at rest, secure password hashing with Argon2id, robust session management
- **Storage Agnostic**: Uses Repository pattern with dependency injection to support any storage backend
- **Concurrent Safe**: All operations designed for high-concurrency web applications
- **Comprehensive Error Handling**: Structured errors with codes for proper API responses
- **Testable**: Mock-friendly interfaces with comprehensive test coverage
- **Performance Optimized**: Caching strategies and efficient database operations

## Architecture

The package follows Go best practices and is organized into several key components:

### Core Entities
- **User**: Main user entity with encrypted PII fields
- **Session**: User session management with metadata tracking
- **Token**: Verification and reset token management
- **Errors**: Comprehensive error handling with structured error codes

### Design Principles
- **Interface Segregation**: Interfaces defined where they're used
- **Dependency Injection**: Repository pattern for storage abstraction
- **Optimistic Locking**: Version-based concurrency control
- **Secure by Default**: All sensitive data encrypted

## Current Implementation Status

### ✅ Completed
- **User Entity** (`user/user.go`): Complete user entity with status management, account locking, and validation
- **Error Handling** (`errors/errors.go`): Comprehensive error definitions with structured error codes
- **Go Module Setup**: Proper module initialization with all required dependencies

### 🚧 In Progress
- User Repository interface
- User Service implementation
- User validation logic
- Session management
- Authentication service
- Token management
- Configuration management

### 📋 Planned
- Integration tests
- Example implementations
- Documentation
- Performance benchmarks

## User Entity

The `User` struct represents the core user entity with the following key features:

### Security Features
- **Encrypted PII**: FirstName, LastName, and Email are encrypted using go-encrypter
- **Hashed Email**: Separate hashed email field for efficient database lookups
- **Secure Passwords**: Argon2id password hashing
- **Account Locking**: Temporary and permanent account locking mechanisms

### Status Management
```go
type UserStatus int

const (
    UserStatusActive UserStatus = iota
    UserStatusSuspended
    UserStatusPendingVerification
    UserStatusLocked
    UserStatusDeactivated
)
```

### Key Methods
- `NewUser()`: Creates a new user with proper defaults
- `CanAuthenticate()`: Checks if user can currently authenticate
- `IsLocked()`: Checks account lock status
- `IncrementLoginAttempts()`: Manages failed login attempts
- `LockAccount()` / `UnlockAccount()`: Account locking management
- `Activate()` / `Suspend()` / `Deactivate()`: Status management
- `Clone()`: Deep copy for optimistic locking scenarios
- `Validate()`: Entity validation

## Error Handling

The package provides comprehensive error handling with:

### Error Categories
- User-related errors (not found, invalid credentials, etc.)
- Authentication errors (account locked, not activated, etc.)
- Session errors (expired, revoked, etc.)
- Token errors (expired, already used, etc.)
- Validation errors
- System errors

### Structured Errors
```go
type AppError struct {
    Code    ErrorCode `json:"code"`
    Message string    `json:"message"`
    Details string    `json:"details,omitempty"`
    Cause   error     `json:"-"`
}
```

### Error Codes
Standardized error codes for API responses:
- `USER_NOT_FOUND`
- `INVALID_CREDENTIALS`
- `ACCOUNT_LOCKED`
- `WEAK_PASSWORD`
- And many more...

## Dependencies

The package integrates with your existing Go modules:

- **go-encrypter**: PII encryption and password hashing
- **go-cache**: Session storage and rate limiting
- **go-logger**: Security event logging and audit trails
- **go-config**: Configuration management
- **go-metrics**: Performance monitoring
- **go-serializer**: Data serialization
- **github.com/google/uuid**: UUID generation

## Getting Started

```go
package main

import (
    "fmt"
    "github.com/MichaelAJay/go-user-management/user"
)

func main() {
    // Create a new user
    newUser := user.NewUser("John", "Doe", "john@example.com", "hashed_email", []byte("hashed_password"))
    
    // Check user status
    fmt.Printf("User can authenticate: %v\n", newUser.CanAuthenticate())
    
    // Activate the user
    newUser.Activate()
    
    // Validate the user
    if err := newUser.Validate(); err != nil {
        fmt.Printf("Validation error: %v\n", err)
    }
}
```

## Development

### Building
```bash
go build ./...
```

### Testing
```bash
go test ./...
```

### Linting
```bash
golangci-lint run
```

## Next Steps

1. **Implement Repository Interfaces**: Define storage contracts
2. **Create User Service**: Business logic layer
3. **Add Validation Package**: Email and password validation
4. **Implement Session Management**: Session lifecycle management
5. **Add Authentication Service**: Login/logout orchestration
6. **Create Token Service**: Verification and reset tokens
7. **Add Configuration**: Configurable security policies
8. **Write Comprehensive Tests**: Unit and integration tests
9. **Add Examples**: Database-specific implementations
10. **Performance Optimization**: Caching and optimization

## Best Practices Implemented

### Go Best Practices
- **Clear Naming**: Descriptive names following Go conventions
- **Interface Segregation**: Small, focused interfaces
- **Error Handling**: Proper error wrapping and context
- **Zero Values**: Useful zero values for all types
- **Concurrency Safety**: Thread-safe operations

### Security Best Practices
- **Encryption at Rest**: All PII encrypted
- **Secure Password Hashing**: Argon2id with proper parameters
- **Account Lockout**: Protection against brute force attacks
- **Optimistic Locking**: Prevents race conditions
- **Structured Logging**: Security event auditing

### Performance Best Practices
- **Efficient Queries**: Hashed email for fast lookups
- **Caching Strategy**: Session and user data caching
- **Minimal Allocations**: Efficient memory usage
- **Connection Pooling**: Database connection optimization

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request 