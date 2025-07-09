# Go User Management - Module Context

Shorthand module name: "UM" or "the module"

## Project Overview

**Purpose**: Production-ready, pluggable user management library for Go web applications
**Target Audience**: Web applications that need comprehensive user authentication and session management
**Architecture**: Security-first, storage-agnostic library using Repository pattern with PostgreSQL as primary target

## Developer Context

- **Background**: Transitioning from JavaScript/NestJS to Go
- **Learning Focus**: Go idioms, interface design, well-established patterns, testing strategies
- **Current State**: Planning

## Architecture Principles

### Security-First Design

- **PII Encryption**: All sensitive data encrypted at rest using go-encrypter
- **Encryption Point**: Encrypt as early as possible, typically in user/service.go
- **Password Security**: Argon2id hashing with proper parameters
- **Account Protection**: Sophisticated locking mechanisms and rate limiting

### Go Design Patterns

- **Interface Segregation**: Small, focused interfaces defined where consumed
- **Dependency Injection**: Repository pattern for storage abstraction
- **Optimistic Locking**: Version-based concurrency control for user updates
- **Error Wrapping**: Structured errors with context using fmt.Errorf("%w", err)

## Dependencies Integration

### Internal Modules

- **go-encrypter**: PII encryption and password hashing (encrypt in service layer)
- **go-cache**: Session storage and rate limiting (both in-memory and Redis)
- **go-config**: Configuration management (security policies, timeouts)
- **go-logger**: Security event logging and audit trails
- **go-metrics**: Performance monitoring

### External Dependencies

- **github.com/google/uuid**: UUID generation for user IDs
- **Standard library**: crypto, database/sql, context packages

## Development Patterns

### Error Handling

- Return errors as last parameter
- Wrap errors with context: `fmt.Errorf("user creation failed: %w", err)`
- Use structured AppError for business logic errors
- Handle storage errors separately from business logic errors

### Testing Strategy

- Table-driven tests for user entity methods
- Mock repository interfaces for service layer testing
- Integration tests for PostgreSQL repository implementations
- Test security scenarios (account locking, encryption, etc.)

### Interface Design

- Repository interfaces in user/ package (where consumed)
- Single-responsibility interfaces (UserReader, UserWriter vs UserRepository)
- Accept interfaces, return concrete types
- Mock-friendly for testing

## Code Style Preferences

- **Naming**: Follow Go conventions (camelCase for private, PascalCase for public)
- **Comments**: Package-level comments for exported types and functions
- **Error Messages**: Lowercase, no punctuation for wrapped errors
- **Interfaces**: Prefer small interfaces with -er suffix when appropriate
- **Tests**: Use testify/assert for readable assertions, table-driven tests

## Security Considerations

- **Never log PII**: Log hashed identifiers only
- **Encrypt early**: PII encryption in service layer before repository calls
- **Audit trails**: Log all authentication events and user modifications
- **Rate limiting**: Implement at service layer using go-cache
- **Session security**: Secure session tokens with proper expiration

### Initial Context

This module is conceived of as a flexible turnkey solution for basic user management. Examples of its use include

- User creation
- User login

To illustrate the way the module should be created (and split into various packages), consider User Login.

The web server which accepts the request is NOT part of the module. It will call one of the module's packages.

Authentication should allow for flexibility, with multiple authentication providers capable of being configuerd in one application. Examples include password authentication, OAuth, OIDC.

When considering password authentication, data storage consideration must come into play. Thus, further configuration should be available via dependency injection (in the example of password authenticator). As an example, in the root application, there may be a Postgres client which is injected into the "orchestration" entity that one of the module's packages exposes. This would be further passed in to the Password Manager.

Thus, the Password authenticator would use any storage client, which would expose a uniform interface, but concrete providers (such as a Postgres provider) would implement Postgres specific needs.

The module should ultimately handle all basic user management needs, with capability to be extended for a specific application's further needs.
