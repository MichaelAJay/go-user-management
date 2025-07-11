# Go User Management

A production-ready, security-first user management library for Go web applications. This module provides comprehensive user authentication, session management, and account security features with pluggable storage backends.

## Overview

Go User Management is designed as a turnkey solution for applications requiring robust user management capabilities. It follows Go best practices with domain-driven design, interface segregation, and security-first principles.

### Key Features

- **Security-First Design**: PII encryption at rest, Argon2id password hashing, optimistic locking
- **Storage Agnostic**: Repository pattern with pluggable backends (PostgreSQL primary target)
- **Pluggable Authentication**: Interface-based system supporting multiple authentication providers
- **Comprehensive Error Handling**: Structured errors with security context
- **Production Ready**: Logging, metrics, monitoring, and audit trail support
- **Go Idioms**: Small interfaces, dependency injection, explicit error handling

## Architecture

### Core Components

```
go-user-management/
├── user/                    # Core user domain
│   ├── user.go             # User entity with business logic
│   ├── repository.go       # Storage-agnostic interfaces
│   ├── service.go          # Business logic with encryption
│   ├── errors.go           # Structured error handling
│   └── requests.go         # Request/response DTOs
├── auth/                   # Authentication framework (planned)
├── repository/             # Storage implementations (planned)
└── example/               # Usage examples (planned)
```

### Design Principles

1. **Domain-Driven Design**: User entities with encrypted PII at service layer
2. **Repository Pattern**: Storage-agnostic interfaces defined where consumed
3. **Security-First**: Custom error types and comprehensive security measures
4. **Service Layer**: Business logic with go-encrypter integration
5. **Interface Segregation**: Small, focused interfaces following Go idioms

## Quick Start

### Installation

```bash
go get github.com/MichaelAJay/go-user-management
```

### Basic Usage

```go
package main

import (
    "context"
    "log"
    
    "github.com/MichaelAJay/go-encrypter"
    "github.com/MichaelAJay/go-user-management/user"
)

func main() {
    // Initialize encrypter for PII protection
    key := []byte("your-32-byte-key-here-123456789012")
    encrypter, err := encrypter.NewAESEncrypter(key)
    if err != nil {
        log.Fatal(err)
    }
    
    // Initialize your repository implementation
    // repo := postgres.NewUserRepository(db)
    var repo user.UserRepository // Your implementation
    
    // Create user service
    service := user.NewService(repo, encrypter)
    
    // Create a new user
    req := &user.CreateUserRequest{
        Email:     "user@example.com",
        FirstName: "John",
        LastName:  "Doe",
    }
    
    newUser, err := service.CreateUser(context.Background(), req)
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Created user: %s", newUser.ID)
}
```

## Dependencies

### Internal Modules
- **go-encrypter**: PII encryption and password hashing
- **go-cache**: Session storage and rate limiting (planned)
- **go-config**: Configuration management (planned)
- **go-logger**: Security event logging (planned)
- **go-metrics**: Performance monitoring (planned)

### External Dependencies
- **github.com/google/uuid**: UUID generation for user IDs
- **github.com/jackc/pgx/v5**: PostgreSQL driver (for repository implementations)
- **golang.org/x/crypto**: Cryptographic functions

## Security Features

### PII Encryption
- All sensitive data encrypted at rest using AES-GCM
- Encryption occurs at service layer before repository calls
- Automatic decryption when data is retrieved
- Clear separation between encrypted and unencrypted data types
- Key rotation support for operational security

### Password Security
- Argon2id hashing with configurable parameters
- Secure salt generation
- Timing attack resistant verification
- Password policy enforcement (planned)

### Account Protection
- Optimistic locking prevents concurrent update conflicts
- Account lockout mechanisms (planned)
- Rate limiting support (planned)
- Audit logging for security events (planned)

## Error Handling

Structured error handling with security context:

```go
user, err := service.GetUserByEmail(ctx, "user@example.com")
if err != nil {
    var appErr *user.AppError
    if errors.As(err, &appErr) {
        switch appErr.Code {
        case user.ErrCodeNotFound:
            // Handle user not found
        case user.ErrCodeInvalidEmail:
            // Handle invalid email
        case user.ErrCodeEncryption:
            // Handle encryption error
        }
    }
}
```

## Repository Pattern

Implement storage backends using small, focused interfaces:

```go
type UserRepository interface {
    UserReader
    UserWriter
}

type UserReader interface {
    GetByID(ctx context.Context, id uuid.UUID) (*User, error)
    GetByEmail(ctx context.Context, email string) (*User, error)
    Exists(ctx context.Context, email string) (bool, error)
}

type UserWriter interface {
    Create(ctx context.Context, user *User) error
    Update(ctx context.Context, user *User) error
    Delete(ctx context.Context, id uuid.UUID) error
}
```

## Development Status

### ✅ Completed (Core Architecture)
- [x] User domain entity with PII encryption
- [x] Storage-agnostic repository interfaces
- [x] Service layer with business logic
- [x] Structured error handling
- [x] Request/response DTOs
- [x] Optimistic locking support

### 🚧 In Progress
- [ ] Authentication framework
- [ ] PostgreSQL repository implementation
- [ ] Password authentication provider
- [ ] Integration tests

### 📋 Planned
- [ ] Account protection (lockout, rate limiting)
- [ ] Input validation and sanitization
- [ ] Audit logging integration
- [ ] OAuth/OIDC authentication providers
- [ ] Session management
- [ ] Database migrations
- [ ] Mock repositories for testing
- [ ] Comprehensive test suite
- [ ] Performance benchmarks
- [ ] Documentation and examples

## Configuration

The module uses go-config for configuration management:

```go
type Config struct {
    Database DatabaseConfig
    Security SecurityConfig
    Auth     AuthConfig
}

type SecurityConfig struct {
    EncryptionKey    string
    PasswordPolicy   PasswordPolicyConfig
    SessionTimeout   time.Duration
    MaxLoginAttempts int
}
```

## Testing

### Unit Tests
```bash
go test ./user/...
```

### Integration Tests
```bash
go test -tags=integration ./...
```

### Benchmarks
```bash
go test -bench=. ./...
```

## Performance Considerations

- **Encryption Overhead**: PII encryption adds computational cost
- **Database Design**: Optimized indexes for encrypted lookups
- **Connection Pooling**: Efficient database connection management
- **Caching**: Optional Redis integration for session storage
- **Monitoring**: Metrics collection for performance tracking

## Contributing

1. Follow Go conventions and project patterns
2. Write comprehensive tests for new features
3. Update documentation for API changes
4. Ensure security best practices
5. Add benchmarks for performance-critical code

### Code Style
- Use Go fmt and Go vet
- Follow interface segregation principles
- Write table-driven tests
- Use structured logging
- Handle errors explicitly

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
- GitHub Issues: Report bugs and feature requests
- Documentation: Comprehensive package documentation
- Examples: See `/example` directory for usage patterns

## Changelog

### v0.1.0 (Current)
- Initial core architecture implementation
- User domain entity with PII encryption
- Repository pattern with storage abstraction
- Service layer with business logic
- Structured error handling
- Request/response DTOs

### Upcoming v0.2.0
- Authentication framework
- PostgreSQL repository implementation
- Password authentication provider
- Integration tests and examples