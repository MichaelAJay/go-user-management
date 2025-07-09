package user

import (
	"time"

	"github.com/google/uuid"
)

// User represents a user in the system with encrypted PII fields
type User struct {
	ID           uuid.UUID `json:"id"`
	Email        string    `json:"email"`        // Encrypted PII
	FirstName    string    `json:"first_name"`   // Encrypted PII
	LastName     string    `json:"last_name"`    // Encrypted PII
	IsActive     bool      `json:"is_active"`
	IsVerified   bool      `json:"is_verified"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
	Version      int       `json:"version"` // For optimistic locking
}

// NewUser creates a new user with required fields
func NewUser(email, firstName, lastName string) *User {
	return &User{
		ID:         uuid.New(),
		Email:      email,
		FirstName:  firstName,
		LastName:   lastName,
		IsActive:   true,
		IsVerified: false,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		Version:    1,
	}
}

// UpdateVersion increments the version for optimistic locking
func (u *User) UpdateVersion() {
	u.Version++
	u.UpdatedAt = time.Now()
}

// Activate sets the user as active
func (u *User) Activate() {
	u.IsActive = true
	u.UpdateVersion()
}

// Deactivate sets the user as inactive
func (u *User) Deactivate() {
	u.IsActive = false
	u.UpdateVersion()
}

// Verify marks the user as verified
func (u *User) Verify() {
	u.IsVerified = true
	u.UpdateVersion()
}

// RecordLogin updates the last login timestamp
func (u *User) RecordLogin() {
	now := time.Now()
	u.LastLoginAt = &now
	u.UpdateVersion()
}