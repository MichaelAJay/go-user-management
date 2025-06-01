package user

import (
	"context"
	"time"
)

// UserSecurityRepository manages security state separate from profile data.
// This repository focuses solely on security-related operations like login tracking,
// account locking, risk assessment, and security event management.
type UserSecurityRepository interface {
	// Security state management - Core CRUD operations
	CreateSecurity(ctx context.Context, security *UserSecurity) error
	GetSecurity(ctx context.Context, userID string) (*UserSecurity, error)
	UpdateSecurity(ctx context.Context, security *UserSecurity) error
	DeleteSecurity(ctx context.Context, userID string) error

	// Login attempt tracking - High-frequency operations
	IncrementLoginAttempts(ctx context.Context, userID string) error
	ResetLoginAttempts(ctx context.Context, userID string) error
	RecordSuccessfulLogin(ctx context.Context, userID string, ipAddress string) error

	// Account lockout operations
	LockAccount(ctx context.Context, userID string, until *time.Time, reason string) error
	UnlockAccount(ctx context.Context, userID string) error
	GetLockedAccounts(ctx context.Context) ([]*UserSecurity, error)

	// Risk assessment operations
	UpdateRiskScore(ctx context.Context, userID string, score float64, factors []RiskFactor) error
	GetHighRiskUsers(ctx context.Context, threshold float64) ([]*UserSecurity, error)

	// Security event management
	AddSecurityEvent(ctx context.Context, userID string, event SecurityEvent) error
	GetSecurityEvents(ctx context.Context, userID string, since time.Time) ([]SecurityEvent, error)

	// Batch operations for efficiency
	GetSecurityBatch(ctx context.Context, userIDs []string) (map[string]*UserSecurity, error)
	UpdateSecurityBatch(ctx context.Context, securities []*UserSecurity) error

	// Maintenance operations
	CleanupOldEvents(ctx context.Context, before time.Time) (int64, error)
	GetSecurityStats(ctx context.Context) (*SecurityStats, error)
}

// SecurityStats represents aggregated security statistics
type SecurityStats struct {
	TotalUsers           int64     `json:"total_users"`
	LockedUsers          int64     `json:"locked_users"`
	HighRiskUsers        int64     `json:"high_risk_users"`
	RecentFailedAttempts int64     `json:"recent_failed_attempts"`
	AverageRiskScore     float64   `json:"average_risk_score"`
	UpdatedAt            time.Time `json:"updated_at"`
}
