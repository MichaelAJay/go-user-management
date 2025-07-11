package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAuthRecord_IncrementFailedAttempts(t *testing.T) {
	tests := []struct {
		name            string
		initialAttempts int
		expectedAttempts int
	}{
		{
			name:            "increment from zero",
			initialAttempts: 0,
			expectedAttempts: 1,
		},
		{
			name:            "increment from existing value",
			initialAttempts: 5,
			expectedAttempts: 6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authRecord := &AuthRecord{
				FailedAttempts: tt.initialAttempts,
				UpdatedAt:      time.Now().Add(-time.Hour),
			}
			oldUpdatedAt := authRecord.UpdatedAt

			authRecord.IncrementFailedAttempts()

			if authRecord.FailedAttempts != tt.expectedAttempts {
				t.Errorf("expected FailedAttempts to be %d, got %d", tt.expectedAttempts, authRecord.FailedAttempts)
			}
			if !authRecord.UpdatedAt.After(oldUpdatedAt) {
				t.Error("expected UpdatedAt to be updated")
			}
		})
	}
}

func TestAuthRecord_ResetFailedAttempts(t *testing.T) {
	authRecord := &AuthRecord{
		FailedAttempts: 5,
		UpdatedAt:      time.Now().Add(-time.Hour),
	}
	oldUpdatedAt := authRecord.UpdatedAt

	authRecord.ResetFailedAttempts()

	if authRecord.FailedAttempts != 0 {
		t.Errorf("expected FailedAttempts to be 0, got %d", authRecord.FailedAttempts)
	}
	if !authRecord.UpdatedAt.After(oldUpdatedAt) {
		t.Error("expected UpdatedAt to be updated")
	}
}

func TestAuthRecord_LockAccount(t *testing.T) {
	authRecord := &AuthRecord{
		LockedUntil: nil,
		UpdatedAt:   time.Now().Add(-time.Hour),
	}
	oldUpdatedAt := authRecord.UpdatedAt
	lockDuration := 30 * time.Minute

	authRecord.LockAccount(lockDuration)

	if authRecord.LockedUntil == nil {
		t.Error("expected LockedUntil to be set")
	}
	if authRecord.LockedUntil.Before(time.Now().Add(lockDuration - time.Minute)) {
		t.Error("expected LockedUntil to be set to approximately lockDuration from now")
	}
	if !authRecord.UpdatedAt.After(oldUpdatedAt) {
		t.Error("expected UpdatedAt to be updated")
	}
}

func TestAuthRecord_UnlockAccount(t *testing.T) {
	lockTime := time.Now().Add(time.Hour)
	authRecord := &AuthRecord{
		LockedUntil: &lockTime,
		UpdatedAt:   time.Now().Add(-time.Hour),
	}
	oldUpdatedAt := authRecord.UpdatedAt

	authRecord.UnlockAccount()

	if authRecord.LockedUntil != nil {
		t.Error("expected LockedUntil to be nil")
	}
	if !authRecord.UpdatedAt.After(oldUpdatedAt) {
		t.Error("expected UpdatedAt to be updated")
	}
}

func TestAuthRecord_IsLocked(t *testing.T) {
	tests := []struct {
		name        string
		lockedUntil *time.Time
		expected    bool
	}{
		{
			name:        "not locked - nil",
			lockedUntil: nil,
			expected:    false,
		},
		{
			name:        "locked - future time",
			lockedUntil: func() *time.Time { t := time.Now().Add(time.Hour); return &t }(),
			expected:    true,
		},
		{
			name:        "not locked - past time",
			lockedUntil: func() *time.Time { t := time.Now().Add(-time.Hour); return &t }(),
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authRecord := &AuthRecord{
				LockedUntil: tt.lockedUntil,
			}

			result := authRecord.IsLocked()

			if result != tt.expected {
				t.Errorf("expected IsLocked to return %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestAuthRecord_SetPasswordHash(t *testing.T) {
	authRecord := &AuthRecord{
		PasswordHash:          nil,
		LastPasswordChangeAt:  nil,
		UpdatedAt:            time.Now().Add(-time.Hour),
	}
	oldUpdatedAt := authRecord.UpdatedAt
	newHash := []byte("newhash")

	authRecord.SetPasswordHash(newHash)

	if string(authRecord.PasswordHash) != string(newHash) {
		t.Errorf("expected PasswordHash to be %s, got %s", newHash, authRecord.PasswordHash)
	}
	if authRecord.LastPasswordChangeAt == nil {
		t.Error("expected LastPasswordChangeAt to be set")
	}
	if !authRecord.UpdatedAt.After(oldUpdatedAt) {
		t.Error("expected UpdatedAt to be updated")
	}
}

func TestAuthRecord_UpdateVersion(t *testing.T) {
	authRecord := &AuthRecord{
		Version:   1,
		UpdatedAt: time.Now().Add(-time.Hour),
	}
	oldUpdatedAt := authRecord.UpdatedAt

	authRecord.UpdateVersion()

	if authRecord.Version != 2 {
		t.Errorf("expected Version to be 2, got %d", authRecord.Version)
	}
	if !authRecord.UpdatedAt.After(oldUpdatedAt) {
		t.Error("expected UpdatedAt to be updated")
	}
}

func TestSession_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{
			name:      "not expired - future time",
			expiresAt: time.Now().Add(time.Hour),
			expected:  false,
		},
		{
			name:      "expired - past time",
			expiresAt: time.Now().Add(-time.Hour),
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{
				ExpiresAt: tt.expiresAt,
			}

			result := session.IsExpired()

			if result != tt.expected {
				t.Errorf("expected IsExpired to return %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestSession_Refresh(t *testing.T) {
	session := &Session{
		ExpiresAt:      time.Now().Add(time.Hour),
		LastAccessedAt: time.Now().Add(-time.Hour),
	}
	oldExpiresAt := session.ExpiresAt
	oldLastAccessedAt := session.LastAccessedAt
	refreshDuration := 2 * time.Hour

	session.Refresh(refreshDuration)

	if !session.ExpiresAt.After(oldExpiresAt) {
		t.Error("expected ExpiresAt to be updated")
	}
	if !session.LastAccessedAt.After(oldLastAccessedAt) {
		t.Error("expected LastAccessedAt to be updated")
	}
	if session.ExpiresAt.Before(time.Now().Add(refreshDuration - time.Minute)) {
		t.Error("expected ExpiresAt to be set to approximately refreshDuration from now")
	}
}

func TestSession_UpdateLastAccessed(t *testing.T) {
	session := &Session{
		LastAccessedAt: time.Now().Add(-time.Hour),
	}
	oldLastAccessedAt := session.LastAccessedAt

	session.UpdateLastAccessed()

	if !session.LastAccessedAt.After(oldLastAccessedAt) {
		t.Error("expected LastAccessedAt to be updated")
	}
}

func TestSession_Deactivate(t *testing.T) {
	session := &Session{
		IsActive: true,
	}

	session.Deactivate()

	if session.IsActive {
		t.Error("expected IsActive to be false")
	}
}

// Test edge cases and boundary conditions
func TestAuthRecord_BoundaryConditions(t *testing.T) {
	t.Run("multiple consecutive increment attempts", func(t *testing.T) {
		authRecord := &AuthRecord{FailedAttempts: 0}
		for i := 1; i <= 10; i++ {
			authRecord.IncrementFailedAttempts()
			if authRecord.FailedAttempts != i {
				t.Errorf("expected FailedAttempts to be %d, got %d", i, authRecord.FailedAttempts)
			}
		}
	})

	t.Run("lock and unlock multiple times", func(t *testing.T) {
		authRecord := &AuthRecord{}
		
		// Lock
		authRecord.LockAccount(time.Hour)
		if !authRecord.IsLocked() {
			t.Error("expected account to be locked")
		}
		
		// Unlock
		authRecord.UnlockAccount()
		if authRecord.IsLocked() {
			t.Error("expected account to be unlocked")
		}
		
		// Lock again
		authRecord.LockAccount(time.Minute)
		if !authRecord.IsLocked() {
			t.Error("expected account to be locked again")
		}
	})
}

func TestSession_BoundaryConditions(t *testing.T) {
	t.Run("session exactly at expiry boundary", func(t *testing.T) {
		now := time.Now()
		session := &Session{
			ExpiresAt: now,
		}
		
		// Should be expired at exactly the expiry time
		if !session.IsExpired() {
			t.Error("expected session to be expired at exactly expiry time")
		}
	})

	t.Run("refresh with zero duration", func(t *testing.T) {
		session := &Session{
			ExpiresAt:      time.Now().Add(-time.Hour),
			LastAccessedAt: time.Now().Add(-time.Hour),
		}
		oldExpiresAt := session.ExpiresAt
		oldLastAccessedAt := session.LastAccessedAt

		session.Refresh(0)

		// Should still update timestamps even with zero duration
		if !session.ExpiresAt.After(oldExpiresAt) {
			t.Error("expected ExpiresAt to be updated even with zero duration")
		}
		if !session.LastAccessedAt.After(oldLastAccessedAt) {
			t.Error("expected LastAccessedAt to be updated")
		}
	})
}

// Test optimistic locking behavior
func TestAuthRecord_OptimisticLocking(t *testing.T) {
	authRecord := &AuthRecord{
		UserID:  uuid.New(),
		Version: 1,
	}

	// Simulate concurrent updates
	originalVersion := authRecord.Version
	
	authRecord.UpdateVersion()
	if authRecord.Version != originalVersion+1 {
		t.Errorf("expected version to be %d, got %d", originalVersion+1, authRecord.Version)
	}
	
	authRecord.UpdateVersion()
	if authRecord.Version != originalVersion+2 {
		t.Errorf("expected version to be %d, got %d", originalVersion+2, authRecord.Version)
	}
}