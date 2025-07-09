# User Package

The `user` package provides core user management functionality with security-first design principles, implementing domain-driven design patterns with comprehensive PII encryption.

## Overview

This package contains the core user domain logic, including:
- User entity with encrypted PII fields
- Storage-agnostic repository interfaces
- Business logic service layer
- Structured error handling
- Request/response DTOs

## Architecture

### Domain-Driven Design
- **User Entity**: Core domain model with business methods
- **Value Objects**: Immutable data structures for requests
- **Repository Pattern**: Storage abstraction with small, focused interfaces
- **Service Layer**: Business logic orchestration with encryption

### Security-First Principles
- **PII Encryption**: All sensitive data encrypted at rest using go-encrypter
- **Optimistic Locking**: Version-based concurrency control
- **Input Validation**: Comprehensive request validation
- **Error Handling**: Structured errors with security context

## Core Components

### User Entity (`user.go`)

```go
type User struct {
    ID           uuid.UUID
    Email        string    // Encrypted PII
    FirstName    string    // Encrypted PII  
    LastName     string    // Encrypted PII
    IsActive     bool
    IsVerified   bool
    CreatedAt    time.Time
    UpdatedAt    time.Time
    LastLoginAt  *time.Time
    Version      int       // Optimistic locking
}
```

**Key Methods:**
- `NewUser()`: Creates new user with defaults
- `UpdateVersion()`: Increments version for concurrency control
- `Activate()`, `Deactivate()`: Status management
- `Verify()`: Email verification
- `RecordLogin()`: Login tracking

### Repository Interfaces (`repository.go`)

Following Go idioms with small, focused interfaces:

```go
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

type UserRepository interface {
    UserReader
    UserWriter
}
```

### Service Layer (`service.go`)

Business logic with encryption integration:

```go
type Service struct {
    repo      UserRepository
    encrypter encrypter.Encrypter
}
```

**Key Methods:**
- `CreateUser()`: User creation with PII encryption
- `GetUserByID()`, `GetUserByEmail()`: Retrieval with decryption
- `UpdateUser()`: Updates with optimistic locking
- `ActivateUser()`, `DeactivateUser()`: Status management
- `RecordLogin()`: Login tracking

### Error Handling (`errors.go`)

Structured error types with security context:

```go
type AppError struct {
    Code    string
    Message string
    Err     error
}
```

**Error Codes:**
- `USER_NOT_FOUND`: User does not exist
- `USER_EXISTS`: User already exists
- `INVALID_EMAIL`: Invalid email format
- `INVALID_INPUT`: Invalid request data
- `VERSION_MISMATCH`: Optimistic locking conflict
- `STORAGE_ERROR`: Repository operation failed
- `ENCRYPTION_ERROR`: Encryption/decryption failed

## Usage Examples

### Service Setup

```go
// Initialize encrypter
key := []byte("your-32-byte-key-here-123456789012")
encrypter, err := encrypter.NewAESEncrypter(key)
if err != nil {
    log.Fatal(err)
}

// Initialize service with repository
service := user.NewService(repository, encrypter)
```

### Creating a User

```go
req := &user.CreateUserRequest{
    Email:     "user@example.com",
    FirstName: "John",
    LastName:  "Doe",
}

newUser, err := service.CreateUser(ctx, req)
if err != nil {
    // Handle error
    var appErr *user.AppError
    if errors.As(err, &appErr) {
        switch appErr.Code {
        case user.ErrCodeExists:
            // User already exists
        case user.ErrCodeInvalidEmail:
            // Invalid email format
        }
    }
}
```

### Retrieving a User

```go
userID := uuid.New()
user, err := service.GetUserByID(ctx, userID)
if err != nil {
    var appErr *user.AppError
    if errors.As(err, &appErr) && appErr.Code == user.ErrCodeNotFound {
        // User not found
    }
}
```

### Updating a User

```go
firstName := "Jane"
updateReq := &user.UpdateUserRequest{
    ID:        user.ID,
    FirstName: &firstName,
    Version:   user.Version, // Required for optimistic locking
}

updatedUser, err := service.UpdateUser(ctx, updateReq)
if err != nil {
    var appErr *user.AppError
    if errors.As(err, &appErr) && appErr.Code == user.ErrCodeVersion {
        // Version conflict - reload and retry
    }
}
```

## Security Considerations

### PII Encryption
- All PII fields are encrypted before storage
- Encryption happens at service layer
- Decryption occurs when data is retrieved
- Uses AES-GCM with go-encrypter

### Optimistic Locking
- Version field prevents concurrent update conflicts
- Version must match for updates to succeed
- Prevents lost update problems

### Input Validation
- Email format validation
- Required field validation
- Trim whitespace from inputs
- Structured error responses

### Error Handling
- No PII in error messages
- Structured error codes for programmatic handling
- Proper error wrapping with context
- Security-aware logging

## Testing

### Unit Tests
```go
func TestCreateUser(t *testing.T) {
    // Mock repository and encrypter
    mockRepo := &MockUserRepository{}
    mockEncrypter := &MockEncrypter{}
    service := NewService(mockRepo, mockEncrypter)
    
    // Test cases
    tests := []struct {
        name    string
        request *CreateUserRequest
        wantErr bool
    }{
        {
            name: "valid user",
            request: &CreateUserRequest{
                Email:     "test@example.com",
                FirstName: "John",
                LastName:  "Doe",
            },
            wantErr: false,
        },
        // Add more test cases...
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            _, err := service.CreateUser(context.Background(), tt.request)
            if (err != nil) != tt.wantErr {
                t.Errorf("CreateUser() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

## Dependencies

- `github.com/google/uuid`: UUID generation
- `github.com/MichaelAJay/go-encrypter`: PII encryption
- Standard library: `context`, `errors`, `fmt`, `regexp`, `strings`, `time`

## Package Structure

```
user/
├── README.md           # This file
├── user.go            # User domain entity
├── repository.go      # Repository interfaces
├── service.go         # Business logic service
├── errors.go          # Custom error types
└── requests.go        # Request/response DTOs
```

## Future Enhancements

- Audit logging integration
- Rate limiting support
- Session management
- Password authentication provider
- OAuth/OIDC integration
- Database migration support