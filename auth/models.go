package auth

import (
	"time"

	"github.com/google/uuid"
)

// AuthRecord represents authentication data for a user
type AuthRecord struct {
	UserID                uuid.UUID  `json:"user_id"`
	Provider              string     `json:"provider"`
	PasswordHash          []byte     `json:"password_hash,omitempty"`
	FailedAttempts        int        `json:"failed_attempts"`
	LockedUntil           *time.Time `json:"locked_until,omitempty"`
	LastPasswordChangeAt  *time.Time `json:"last_password_change_at,omitempty"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
	Version               int        `json:"version"`
}

// Session represents a user session
type Session struct {
	ID               string    `json:"id"`
	UserID           uuid.UUID `json:"user_id"`
	CreatedAt        time.Time `json:"created_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	LastAccessedAt   time.Time `json:"last_accessed_at"`
	IsActive         bool      `json:"is_active"`
}

// ResetToken represents a password reset token
type ResetToken struct {
	Token     string    `json:"token"`
	UserID    uuid.UUID `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
	CreatedAt time.Time `json:"created_at"`
}

// AuthRecord domain methods

// IncrementFailedAttempts increments the failed attempt counter and updates the timestamp
func (a *AuthRecord) IncrementFailedAttempts() {
	a.FailedAttempts++
	a.UpdatedAt = time.Now()
}

// ResetFailedAttempts resets the failed attempt counter to zero
func (a *AuthRecord) ResetFailedAttempts() {
	a.FailedAttempts = 0
	a.UpdatedAt = time.Now()
}

// LockAccount locks the account for the specified duration
func (a *AuthRecord) LockAccount(duration time.Duration) {
	lockUntil := time.Now().Add(duration)
	a.LockedUntil = &lockUntil
	a.UpdatedAt = time.Now()
}

// UnlockAccount unlocks the account by clearing the LockedUntil field
func (a *AuthRecord) UnlockAccount() {
	a.LockedUntil = nil
	a.UpdatedAt = time.Now()
}

// IsLocked returns true if the account is currently locked
func (a *AuthRecord) IsLocked() bool {
	if a.LockedUntil == nil {
		return false
	}
	return time.Now().Before(*a.LockedUntil)
}

// SetPasswordHash sets the password hash and updates the last password change timestamp
func (a *AuthRecord) SetPasswordHash(hash []byte) {
	a.PasswordHash = hash
	now := time.Now()
	a.LastPasswordChangeAt = &now
	a.UpdatedAt = now
}

// UpdateVersion increments the version for optimistic locking
func (a *AuthRecord) UpdateVersion() {
	a.Version++
	a.UpdatedAt = time.Now()
}

// Session domain methods

// IsExpired returns true if the session has expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// Refresh extends the session expiry by the specified duration
func (s *Session) Refresh(duration time.Duration) {
	s.ExpiresAt = time.Now().Add(duration)
	s.LastAccessedAt = time.Now()
}

// UpdateLastAccessed updates the last accessed timestamp
func (s *Session) UpdateLastAccessed() {
	s.LastAccessedAt = time.Now()
}

// Deactivate marks the session as inactive
func (s *Session) Deactivate() {
	s.IsActive = false
}