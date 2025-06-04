package repository

import "github.com/MichaelAJay/go-user-management/user"

// Re-export the repository interfaces from the user package
// This allows consumers to import everything they need from the repository package
// instead of having to import from multiple packages

// UserRepository manages user profile data and account state
type UserRepository = user.UserRepository

// AuthenticationRepository manages credential storage and retrieval
type AuthenticationRepository = user.AuthenticationRepository

// UserSecurityRepository manages security state separate from profile data
type UserSecurityRepository = user.UserSecurityRepository
