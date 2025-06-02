package user

import (
	"context"
	"sync"
	"time"

	"github.com/MichaelAJay/go-user-management/errors"
)

// InMemorySecurityRepository provides an in-memory implementation of UserSecurityRepository
// for testing purposes. This follows Go best practice of using concrete implementations
// for testing rather than external mocking frameworks.
type InMemorySecurityRepository struct {
	securities map[string]*UserSecurity
	mu         sync.RWMutex
}

// NewInMemorySecurityRepository creates a new in-memory security repository
func NewInMemorySecurityRepository() UserSecurityRepository {
	return &InMemorySecurityRepository{
		securities: make(map[string]*UserSecurity),
	}
}

// CreateSecurity creates a new security record for a user
func (r *InMemorySecurityRepository) CreateSecurity(ctx context.Context, security *UserSecurity) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.securities[security.UserID]; exists {
		return errors.NewAppError(errors.CodeDuplicateEmail, "security record already exists")
	}

	// Clone and set timestamps
	securityCopy := *security
	securityCopy.CreatedAt = time.Now()
	securityCopy.UpdatedAt = time.Now()
	securityCopy.Version = 1

	r.securities[security.UserID] = &securityCopy
	return nil
}

// GetSecurity retrieves security information for a user
func (r *InMemorySecurityRepository) GetSecurity(ctx context.Context, userID string) (*UserSecurity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	security, exists := r.securities[userID]
	if !exists {
		return nil, errors.ErrUserNotFound
	}

	// Return copy to avoid mutations
	securityCopy := *security
	return &securityCopy, nil
}

// UpdateSecurity updates existing security information
func (r *InMemorySecurityRepository) UpdateSecurity(ctx context.Context, security *UserSecurity) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	existing, exists := r.securities[security.UserID]
	if !exists {
		return errors.ErrUserNotFound
	}

	// Check version for optimistic locking
	if existing.Version != security.Version-1 {
		return errors.ErrVersionMismatch
	}

	// Update security record
	securityCopy := *security
	securityCopy.UpdatedAt = time.Now()
	r.securities[security.UserID] = &securityCopy
	return nil
}

// DeleteSecurity removes security information for a user
func (r *InMemorySecurityRepository) DeleteSecurity(ctx context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.securities[userID]; !exists {
		return errors.ErrUserNotFound
	}

	delete(r.securities, userID)
	return nil
}

// IncrementLoginAttempts increments the login attempt counter
func (r *InMemorySecurityRepository) IncrementLoginAttempts(ctx context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	security, exists := r.securities[userID]
	if !exists {
		return errors.ErrUserNotFound
	}

	security.LoginAttempts++
	security.TotalLoginAttempts++
	security.UpdatedAt = time.Now()
	security.Version++
	return nil
}

// ResetLoginAttempts resets the login attempt counter
func (r *InMemorySecurityRepository) ResetLoginAttempts(ctx context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	security, exists := r.securities[userID]
	if !exists {
		return errors.ErrUserNotFound
	}

	security.LoginAttempts = 0
	security.LockedUntil = nil
	security.LockReason = ""
	security.UpdatedAt = time.Now()
	security.Version++
	return nil
}

// RecordSuccessfulLogin records a successful login
func (r *InMemorySecurityRepository) RecordSuccessfulLogin(ctx context.Context, userID string, ipAddress string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	security, exists := r.securities[userID]
	if !exists {
		return errors.ErrUserNotFound
	}

	now := time.Now()
	security.LoginAttempts = 0
	security.SuccessfulLogins++
	security.LastLoginAt = &now
	security.LastLoginIP = ipAddress
	security.LockedUntil = nil
	security.LockReason = ""
	security.UpdatedAt = time.Now()
	security.Version++
	return nil
}

// LockAccount locks a user account
func (r *InMemorySecurityRepository) LockAccount(ctx context.Context, userID string, until *time.Time, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	security, exists := r.securities[userID]
	if !exists {
		return errors.ErrUserNotFound
	}

	security.LockedUntil = until
	security.LockReason = reason
	security.UpdatedAt = time.Now()
	security.Version++
	return nil
}

// UnlockAccount unlocks a user account
func (r *InMemorySecurityRepository) UnlockAccount(ctx context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	security, exists := r.securities[userID]
	if !exists {
		return errors.ErrUserNotFound
	}

	security.LockedUntil = nil
	security.LockReason = ""
	security.LoginAttempts = 0
	security.UpdatedAt = time.Now()
	security.Version++
	return nil
}

// GetLockedAccounts retrieves all locked accounts
func (r *InMemorySecurityRepository) GetLockedAccounts(ctx context.Context) ([]*UserSecurity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var locked []*UserSecurity
	now := time.Now()
	for _, security := range r.securities {
		if security.IsLocked() || (security.LockedUntil != nil && security.LockedUntil.After(now)) {
			securityCopy := *security
			locked = append(locked, &securityCopy)
		}
	}
	return locked, nil
}

// UpdateRiskScore updates the risk score for a user
func (r *InMemorySecurityRepository) UpdateRiskScore(ctx context.Context, userID string, score float64, factors []RiskFactor) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	security, exists := r.securities[userID]
	if !exists {
		return errors.ErrUserNotFound
	}

	security.RiskScore = score
	security.RiskFactors = factors
	security.UpdatedAt = time.Now()
	security.Version++
	return nil
}

// GetHighRiskUsers retrieves users with risk scores above the threshold
func (r *InMemorySecurityRepository) GetHighRiskUsers(ctx context.Context, threshold float64) ([]*UserSecurity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var highRisk []*UserSecurity
	for _, security := range r.securities {
		if security.RiskScore >= threshold {
			securityCopy := *security
			highRisk = append(highRisk, &securityCopy)
		}
	}
	return highRisk, nil
}

// AddSecurityEvent adds a security event to the user's record
func (r *InMemorySecurityRepository) AddSecurityEvent(ctx context.Context, userID string, event SecurityEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	security, exists := r.securities[userID]
	if !exists {
		return errors.ErrUserNotFound
	}

	security.SecurityEvents = append(security.SecurityEvents, event)

	// Keep only the last 100 events to prevent unbounded growth
	if len(security.SecurityEvents) > 100 {
		security.SecurityEvents = security.SecurityEvents[len(security.SecurityEvents)-100:]
	}

	security.UpdatedAt = time.Now()
	security.Version++
	return nil
}

// GetSecurityEvents retrieves security events for a user since a given time
func (r *InMemorySecurityRepository) GetSecurityEvents(ctx context.Context, userID string, since time.Time) ([]SecurityEvent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	security, exists := r.securities[userID]
	if !exists {
		return nil, errors.ErrUserNotFound
	}

	var events []SecurityEvent
	for _, event := range security.SecurityEvents {
		if event.Timestamp.After(since) {
			events = append(events, event)
		}
	}
	return events, nil
}

// GetSecurityBatch retrieves security information for multiple users
func (r *InMemorySecurityRepository) GetSecurityBatch(ctx context.Context, userIDs []string) (map[string]*UserSecurity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]*UserSecurity)
	for _, userID := range userIDs {
		if security, exists := r.securities[userID]; exists {
			securityCopy := *security
			result[userID] = &securityCopy
		}
	}
	return result, nil
}

// UpdateSecurityBatch updates multiple security records
func (r *InMemorySecurityRepository) UpdateSecurityBatch(ctx context.Context, securities []*UserSecurity) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, security := range securities {
		existing, exists := r.securities[security.UserID]
		if !exists {
			continue // Skip non-existent records
		}

		// Check version for optimistic locking
		if existing.Version != security.Version-1 {
			return errors.ErrVersionMismatch
		}

		securityCopy := *security
		securityCopy.UpdatedAt = time.Now()
		r.securities[security.UserID] = &securityCopy
	}
	return nil
}

// CleanupOldEvents removes security events older than the specified time
func (r *InMemorySecurityRepository) CleanupOldEvents(ctx context.Context, before time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var cleaned int64
	for _, security := range r.securities {
		var filteredEvents []SecurityEvent
		for _, event := range security.SecurityEvents {
			if event.Timestamp.After(before) {
				filteredEvents = append(filteredEvents, event)
			} else {
				cleaned++
			}
		}
		security.SecurityEvents = filteredEvents
		if len(filteredEvents) != len(security.SecurityEvents) {
			security.UpdatedAt = time.Now()
			security.Version++
		}
	}
	return cleaned, nil
}

// GetSecurityStats returns aggregated security statistics
func (r *InMemorySecurityRepository) GetSecurityStats(ctx context.Context) (*SecurityStats, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := &SecurityStats{
		TotalUsers:           int64(len(r.securities)),
		LockedUsers:          0,
		HighRiskUsers:        0,
		RecentFailedAttempts: 0,
		AverageRiskScore:     0.0,
		UpdatedAt:            time.Now(),
	}

	var totalRiskScore float64
	now := time.Now()
	oneDayAgo := now.Add(-24 * time.Hour)

	for _, security := range r.securities {
		// Count locked users
		if security.IsLocked() {
			stats.LockedUsers++
		}

		// Count high risk users (>= 70.0)
		if security.RiskScore >= 70.0 {
			stats.HighRiskUsers++
		}

		// Sum risk scores for average
		totalRiskScore += security.RiskScore

		// Count recent failed attempts
		if security.LastFailedAt != nil && security.LastFailedAt.After(oneDayAgo) {
			stats.RecentFailedAttempts += int64(security.LoginAttempts)
		}
	}

	// Calculate average risk score
	if len(r.securities) > 0 {
		stats.AverageRiskScore = totalRiskScore / float64(len(r.securities))
	}

	return stats, nil
}
