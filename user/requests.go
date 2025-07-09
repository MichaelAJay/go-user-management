package user

import "github.com/google/uuid"

// CreateUserRequest represents a request to create a new user
type CreateUserRequest struct {
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// UpdateUserRequest represents a request to update a user
type UpdateUserRequest struct {
	ID         uuid.UUID `json:"id"`
	FirstName  *string   `json:"first_name,omitempty"`
	LastName   *string   `json:"last_name,omitempty"`
	IsActive   *bool     `json:"is_active,omitempty"`
	IsVerified *bool     `json:"is_verified,omitempty"`
	Version    int       `json:"version"` // Required for optimistic locking
}