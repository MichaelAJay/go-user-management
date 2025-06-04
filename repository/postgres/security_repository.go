// repository/postgres/security_repository.go
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	usererrors "github.com/MichaelAJay/go-user-management/errors"
	"github.com/MichaelAJay/go-user-management/user"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// securityRepository implements user.UserSecurityRepository for PostgreSQL using pgx/v5
type securityRepository struct {
	pool *pgxpool.Pool
}

// NewSecurityRepository creates a new PostgreSQL security repository
func NewSecurityRepository(pool *pgxpool.Pool) user.UserSecurityRepository {
	return &securityRepository{
		pool: pool,
	}
}

// CreateSecurity creates a new security record for a user
func (r *securityRepository) CreateSecurity(ctx context.Context, security *user.UserSecurity) error {
	// Serialize JSON fields
	riskFactorsJSON, err := json.Marshal(security.RiskFactors)
	if err != nil {
		return fmt.Errorf("failed to marshal risk factors: %w", err)
	}

	securityEventsJSON, err := json.Marshal(security.SecurityEvents)
	if err != nil {
		return fmt.Errorf("failed to marshal security events: %w", err)
	}

	query := `
		INSERT INTO user_security (
			user_id, login_attempts, last_failed_at, locked_until, lock_reason,
			last_login_at, last_login_ip, total_login_attempts, successful_logins,
			risk_score, risk_factors, security_events, mfa_enabled, mfa_backup_codes,
			created_at, updated_at, version
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`

	var lastLoginIP *net.IP
	if security.LastLoginIP != "" {
		ip := net.ParseIP(security.LastLoginIP)
		if ip != nil {
			lastLoginIP = &ip
		}
	}

	_, err = r.pool.Exec(ctx, query,
		security.UserID,
		security.LoginAttempts,
		security.LastFailedAt,
		security.LockedUntil,
		security.LockReason,
		security.LastLoginAt,
		lastLoginIP,
		security.TotalLoginAttempts,
		security.SuccessfulLogins,
		security.RiskScore,
		riskFactorsJSON,
		securityEventsJSON,
		security.MFAEnabled,
		security.MFABackupCodes,
		security.CreatedAt,
		security.UpdatedAt,
		security.Version,
	)

	if err != nil {
		// Check for duplicate user constraint violation
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" && pgErr.ConstraintName == "user_security_pkey" {
				return usererrors.NewAppError(usererrors.CodeDuplicateEmail, "security record already exists for this user")
			}
		}
		return fmt.Errorf("failed to create security record: %w", err)
	}

	return nil
}

// GetSecurity retrieves security information for a user
func (r *securityRepository) GetSecurity(ctx context.Context, userID string) (*user.UserSecurity, error) {
	query := `
		SELECT user_id, login_attempts, last_failed_at, locked_until, lock_reason,
			   last_login_at, last_login_ip, total_login_attempts, successful_logins,
			   risk_score, risk_factors, security_events, mfa_enabled, mfa_backup_codes,
			   created_at, updated_at, version
		FROM user_security 
		WHERE user_id = $1`

	security := &user.UserSecurity{}
	var riskFactorsJSON, securityEventsJSON []byte
	var lastLoginIP *net.IP

	err := r.pool.QueryRow(ctx, query, userID).Scan(
		&security.UserID,
		&security.LoginAttempts,
		&security.LastFailedAt,
		&security.LockedUntil,
		&security.LockReason,
		&security.LastLoginAt,
		&lastLoginIP,
		&security.TotalLoginAttempts,
		&security.SuccessfulLogins,
		&security.RiskScore,
		&riskFactorsJSON,
		&securityEventsJSON,
		&security.MFAEnabled,
		&security.MFABackupCodes,
		&security.CreatedAt,
		&security.UpdatedAt,
		&security.Version,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, usererrors.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get security record: %w", err)
	}

	// Convert IP address
	if lastLoginIP != nil {
		security.LastLoginIP = lastLoginIP.String()
	}

	// Deserialize JSON fields
	if len(riskFactorsJSON) > 0 {
		if err := json.Unmarshal(riskFactorsJSON, &security.RiskFactors); err != nil {
			return nil, fmt.Errorf("failed to unmarshal risk factors: %w", err)
		}
	}

	if len(securityEventsJSON) > 0 {
		if err := json.Unmarshal(securityEventsJSON, &security.SecurityEvents); err != nil {
			return nil, fmt.Errorf("failed to unmarshal security events: %w", err)
		}
	}

	return security, nil
}

// UpdateSecurity updates existing security information
func (r *securityRepository) UpdateSecurity(ctx context.Context, security *user.UserSecurity) error {
	// Serialize JSON fields
	riskFactorsJSON, err := json.Marshal(security.RiskFactors)
	if err != nil {
		return fmt.Errorf("failed to marshal risk factors: %w", err)
	}

	securityEventsJSON, err := json.Marshal(security.SecurityEvents)
	if err != nil {
		return fmt.Errorf("failed to marshal security events: %w", err)
	}

	query := `
		UPDATE user_security 
		SET login_attempts = $2, last_failed_at = $3, locked_until = $4, lock_reason = $5,
			last_login_at = $6, last_login_ip = $7, total_login_attempts = $8, 
			successful_logins = $9, risk_score = $10, risk_factors = $11, 
			security_events = $12, mfa_enabled = $13, mfa_backup_codes = $14,
			updated_at = $15, version = $16
		WHERE user_id = $1 AND version = $17`

	var lastLoginIP *net.IP
	if security.LastLoginIP != "" {
		ip := net.ParseIP(security.LastLoginIP)
		if ip != nil {
			lastLoginIP = &ip
		}
	}

	result, err := r.pool.Exec(ctx, query,
		security.UserID,
		security.LoginAttempts,
		security.LastFailedAt,
		security.LockedUntil,
		security.LockReason,
		security.LastLoginAt,
		lastLoginIP,
		security.TotalLoginAttempts,
		security.SuccessfulLogins,
		security.RiskScore,
		riskFactorsJSON,
		securityEventsJSON,
		security.MFAEnabled,
		security.MFABackupCodes,
		security.UpdatedAt,
		security.Version,
		security.Version-1, // Previous version for optimistic locking
	)

	if err != nil {
		return fmt.Errorf("failed to update security record: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		// Either security record doesn't exist or version mismatch
		// Check if security record exists
		_, err := r.GetSecurity(ctx, security.UserID)
		if err != nil {
			if usererrors.IsErrorType(err, usererrors.ErrUserNotFound) {
				return usererrors.ErrUserNotFound
			}
			return err
		}
		// Security record exists, so it must be a version mismatch
		return usererrors.ErrVersionMismatch
	}

	return nil
}

// DeleteSecurity removes security information for a user
func (r *securityRepository) DeleteSecurity(ctx context.Context, userID string) error {
	query := `DELETE FROM user_security WHERE user_id = $1`

	result, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete security record: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return usererrors.ErrUserNotFound
	}

	return nil
}

// IncrementLoginAttempts increments the login attempt counter
func (r *securityRepository) IncrementLoginAttempts(ctx context.Context, userID string) error {
	query := `
		UPDATE user_security 
		SET login_attempts = login_attempts + 1, 
			total_login_attempts = total_login_attempts + 1,
			updated_at = $2, version = version + 1
		WHERE user_id = $1`

	result, err := r.pool.Exec(ctx, query, userID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to increment login attempts: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return usererrors.ErrUserNotFound
	}

	return nil
}

// ResetLoginAttempts resets the login attempt counter
func (r *securityRepository) ResetLoginAttempts(ctx context.Context, userID string) error {
	query := `
		UPDATE user_security 
		SET login_attempts = 0, locked_until = NULL, lock_reason = '',
			updated_at = $2, version = version + 1
		WHERE user_id = $1`

	result, err := r.pool.Exec(ctx, query, userID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to reset login attempts: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return usererrors.ErrUserNotFound
	}

	return nil
}

// RecordSuccessfulLogin records a successful login
func (r *securityRepository) RecordSuccessfulLogin(ctx context.Context, userID string, ipAddress string) error {
	var lastLoginIP *net.IP
	if ipAddress != "" {
		ip := net.ParseIP(ipAddress)
		if ip != nil {
			lastLoginIP = &ip
		}
	}

	query := `
		UPDATE user_security 
		SET login_attempts = 0, successful_logins = successful_logins + 1,
			last_login_at = $2, last_login_ip = $3, locked_until = NULL, 
			lock_reason = '', updated_at = $4, version = version + 1
		WHERE user_id = $1`

	now := time.Now()
	result, err := r.pool.Exec(ctx, query, userID, now, lastLoginIP, now)
	if err != nil {
		return fmt.Errorf("failed to record successful login: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return usererrors.ErrUserNotFound
	}

	return nil
}

// LockAccount locks a user account
func (r *securityRepository) LockAccount(ctx context.Context, userID string, until *time.Time, reason string) error {
	query := `
		UPDATE user_security 
		SET locked_until = $2, lock_reason = $3, updated_at = $4, version = version + 1
		WHERE user_id = $1`

	result, err := r.pool.Exec(ctx, query, userID, until, reason, time.Now())
	if err != nil {
		return fmt.Errorf("failed to lock account: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return usererrors.ErrUserNotFound
	}

	return nil
}

// UnlockAccount unlocks a user account
func (r *securityRepository) UnlockAccount(ctx context.Context, userID string) error {
	query := `
		UPDATE user_security 
		SET locked_until = NULL, lock_reason = '', login_attempts = 0,
			updated_at = $2, version = version + 1
		WHERE user_id = $1`

	result, err := r.pool.Exec(ctx, query, userID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to unlock account: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return usererrors.ErrUserNotFound
	}

	return nil
}

// GetLockedAccounts retrieves all locked accounts
func (r *securityRepository) GetLockedAccounts(ctx context.Context) ([]*user.UserSecurity, error) {
	query := `
		SELECT user_id, login_attempts, last_failed_at, locked_until, lock_reason,
			   last_login_at, last_login_ip, total_login_attempts, successful_logins,
			   risk_score, risk_factors, security_events, mfa_enabled, mfa_backup_codes,
			   created_at, updated_at, version
		FROM user_security 
		WHERE locked_until IS NOT NULL AND locked_until > NOW()
		ORDER BY locked_until ASC`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get locked accounts: %w", err)
	}
	defer rows.Close()

	var lockedAccounts []*user.UserSecurity
	for rows.Next() {
		security := &user.UserSecurity{}
		var riskFactorsJSON, securityEventsJSON []byte
		var lastLoginIP *net.IP

		err := rows.Scan(
			&security.UserID,
			&security.LoginAttempts,
			&security.LastFailedAt,
			&security.LockedUntil,
			&security.LockReason,
			&security.LastLoginAt,
			&lastLoginIP,
			&security.TotalLoginAttempts,
			&security.SuccessfulLogins,
			&security.RiskScore,
			&riskFactorsJSON,
			&securityEventsJSON,
			&security.MFAEnabled,
			&security.MFABackupCodes,
			&security.CreatedAt,
			&security.UpdatedAt,
			&security.Version,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan locked account row: %w", err)
		}

		// Convert IP address
		if lastLoginIP != nil {
			security.LastLoginIP = lastLoginIP.String()
		}

		// Deserialize JSON fields
		if len(riskFactorsJSON) > 0 {
			if err := json.Unmarshal(riskFactorsJSON, &security.RiskFactors); err != nil {
				return nil, fmt.Errorf("failed to unmarshal risk factors: %w", err)
			}
		}

		if len(securityEventsJSON) > 0 {
			if err := json.Unmarshal(securityEventsJSON, &security.SecurityEvents); err != nil {
				return nil, fmt.Errorf("failed to unmarshal security events: %w", err)
			}
		}

		lockedAccounts = append(lockedAccounts, security)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating locked account rows: %w", err)
	}

	return lockedAccounts, nil
}

// UpdateRiskScore updates the risk score for a user
func (r *securityRepository) UpdateRiskScore(ctx context.Context, userID string, score float64, factors []user.RiskFactor) error {
	riskFactorsJSON, err := json.Marshal(factors)
	if err != nil {
		return fmt.Errorf("failed to marshal risk factors: %w", err)
	}

	query := `
		UPDATE user_security 
		SET risk_score = $2, risk_factors = $3, updated_at = $4, version = version + 1
		WHERE user_id = $1`

	result, err := r.pool.Exec(ctx, query, userID, score, riskFactorsJSON, time.Now())
	if err != nil {
		return fmt.Errorf("failed to update risk score: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return usererrors.ErrUserNotFound
	}

	return nil
}

// GetHighRiskUsers retrieves users with risk scores above the threshold
func (r *securityRepository) GetHighRiskUsers(ctx context.Context, threshold float64) ([]*user.UserSecurity, error) {
	query := `
		SELECT user_id, login_attempts, last_failed_at, locked_until, lock_reason,
			   last_login_at, last_login_ip, total_login_attempts, successful_logins,
			   risk_score, risk_factors, security_events, mfa_enabled, mfa_backup_codes,
			   created_at, updated_at, version
		FROM user_security 
		WHERE risk_score >= $1
		ORDER BY risk_score DESC`

	rows, err := r.pool.Query(ctx, query, threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to get high risk users: %w", err)
	}
	defer rows.Close()

	var highRiskUsers []*user.UserSecurity
	for rows.Next() {
		security := &user.UserSecurity{}
		var riskFactorsJSON, securityEventsJSON []byte
		var lastLoginIP *net.IP

		err := rows.Scan(
			&security.UserID,
			&security.LoginAttempts,
			&security.LastFailedAt,
			&security.LockedUntil,
			&security.LockReason,
			&security.LastLoginAt,
			&lastLoginIP,
			&security.TotalLoginAttempts,
			&security.SuccessfulLogins,
			&security.RiskScore,
			&riskFactorsJSON,
			&securityEventsJSON,
			&security.MFAEnabled,
			&security.MFABackupCodes,
			&security.CreatedAt,
			&security.UpdatedAt,
			&security.Version,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan high risk user row: %w", err)
		}

		// Convert IP address
		if lastLoginIP != nil {
			security.LastLoginIP = lastLoginIP.String()
		}

		// Deserialize JSON fields
		if len(riskFactorsJSON) > 0 {
			if err := json.Unmarshal(riskFactorsJSON, &security.RiskFactors); err != nil {
				return nil, fmt.Errorf("failed to unmarshal risk factors: %w", err)
			}
		}

		if len(securityEventsJSON) > 0 {
			if err := json.Unmarshal(securityEventsJSON, &security.SecurityEvents); err != nil {
				return nil, fmt.Errorf("failed to unmarshal security events: %w", err)
			}
		}

		highRiskUsers = append(highRiskUsers, security)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating high risk user rows: %w", err)
	}

	return highRiskUsers, nil
}

// AddSecurityEvent adds a security event to the user's record
func (r *securityRepository) AddSecurityEvent(ctx context.Context, userID string, event user.SecurityEvent) error {
	// Get current security record to append the event
	security, err := r.GetSecurity(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get security record: %w", err)
	}

	// Add the event
	security.SecurityEvents = append(security.SecurityEvents, event)

	// Keep only the last 100 events to prevent unbounded growth
	const maxEvents = 100
	if len(security.SecurityEvents) > maxEvents {
		security.SecurityEvents = security.SecurityEvents[len(security.SecurityEvents)-maxEvents:]
	}

	// Update the record
	security.UpdatedAt = time.Now()
	security.Version++

	return r.UpdateSecurity(ctx, security)
}

// GetSecurityEvents retrieves security events for a user since a given time
func (r *securityRepository) GetSecurityEvents(ctx context.Context, userID string, since time.Time) ([]user.SecurityEvent, error) {
	security, err := r.GetSecurity(ctx, userID)
	if err != nil {
		return nil, err
	}

	var filteredEvents []user.SecurityEvent
	for _, event := range security.SecurityEvents {
		if event.Timestamp.After(since) {
			filteredEvents = append(filteredEvents, event)
		}
	}

	return filteredEvents, nil
}

// GetSecurityBatch retrieves security information for multiple users
func (r *securityRepository) GetSecurityBatch(ctx context.Context, userIDs []string) (map[string]*user.UserSecurity, error) {
	if len(userIDs) == 0 {
		return make(map[string]*user.UserSecurity), nil
	}

	query := `
		SELECT user_id, login_attempts, last_failed_at, locked_until, lock_reason,
			   last_login_at, last_login_ip, total_login_attempts, successful_logins,
			   risk_score, risk_factors, security_events, mfa_enabled, mfa_backup_codes,
			   created_at, updated_at, version
		FROM user_security 
		WHERE user_id = ANY($1)`

	rows, err := r.pool.Query(ctx, query, userIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to get security batch: %w", err)
	}
	defer rows.Close()

	result := make(map[string]*user.UserSecurity)
	for rows.Next() {
		security := &user.UserSecurity{}
		var riskFactorsJSON, securityEventsJSON []byte
		var lastLoginIP *net.IP

		err := rows.Scan(
			&security.UserID,
			&security.LoginAttempts,
			&security.LastFailedAt,
			&security.LockedUntil,
			&security.LockReason,
			&security.LastLoginAt,
			&lastLoginIP,
			&security.TotalLoginAttempts,
			&security.SuccessfulLogins,
			&security.RiskScore,
			&riskFactorsJSON,
			&securityEventsJSON,
			&security.MFAEnabled,
			&security.MFABackupCodes,
			&security.CreatedAt,
			&security.UpdatedAt,
			&security.Version,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan security batch row: %w", err)
		}

		// Convert IP address
		if lastLoginIP != nil {
			security.LastLoginIP = lastLoginIP.String()
		}

		// Deserialize JSON fields
		if len(riskFactorsJSON) > 0 {
			if err := json.Unmarshal(riskFactorsJSON, &security.RiskFactors); err != nil {
				return nil, fmt.Errorf("failed to unmarshal risk factors: %w", err)
			}
		}

		if len(securityEventsJSON) > 0 {
			if err := json.Unmarshal(securityEventsJSON, &security.SecurityEvents); err != nil {
				return nil, fmt.Errorf("failed to unmarshal security events: %w", err)
			}
		}

		result[security.UserID] = security
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating security batch rows: %w", err)
	}

	return result, nil
}

// UpdateSecurityBatch updates multiple security records
func (r *securityRepository) UpdateSecurityBatch(ctx context.Context, securities []*user.UserSecurity) error {
	if len(securities) == 0 {
		return nil
	}

	// Use a transaction for batch updates
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	query := `
		UPDATE user_security 
		SET login_attempts = $2, last_failed_at = $3, locked_until = $4, lock_reason = $5,
			last_login_at = $6, last_login_ip = $7, total_login_attempts = $8, 
			successful_logins = $9, risk_score = $10, risk_factors = $11, 
			security_events = $12, mfa_enabled = $13, mfa_backup_codes = $14,
			updated_at = $15, version = $16
		WHERE user_id = $1 AND version = $17`

	for _, security := range securities {
		// Serialize JSON fields
		riskFactorsJSON, err := json.Marshal(security.RiskFactors)
		if err != nil {
			return fmt.Errorf("failed to marshal risk factors: %w", err)
		}

		securityEventsJSON, err := json.Marshal(security.SecurityEvents)
		if err != nil {
			return fmt.Errorf("failed to marshal security events: %w", err)
		}

		var lastLoginIP *net.IP
		if security.LastLoginIP != "" {
			ip := net.ParseIP(security.LastLoginIP)
			if ip != nil {
				lastLoginIP = &ip
			}
		}

		result, err := tx.Exec(ctx, query,
			security.UserID,
			security.LoginAttempts,
			security.LastFailedAt,
			security.LockedUntil,
			security.LockReason,
			security.LastLoginAt,
			lastLoginIP,
			security.TotalLoginAttempts,
			security.SuccessfulLogins,
			security.RiskScore,
			riskFactorsJSON,
			securityEventsJSON,
			security.MFAEnabled,
			security.MFABackupCodes,
			security.UpdatedAt,
			security.Version,
			security.Version-1, // Previous version for optimistic locking
		)

		if err != nil {
			return fmt.Errorf("failed to update security record in batch: %w", err)
		}

		rowsAffected := result.RowsAffected()
		if rowsAffected == 0 {
			return usererrors.ErrVersionMismatch
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit batch update: %w", err)
	}

	return nil
}

// CleanupOldEvents removes security events older than the specified time
func (r *securityRepository) CleanupOldEvents(ctx context.Context, before time.Time) (int64, error) {
	// This is complex because we need to update the JSONB field
	// Get all security records with events
	query := `
		SELECT user_id, security_events, version
		FROM user_security 
		WHERE security_events IS NOT NULL AND security_events != 'null'::jsonb`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to get security records for cleanup: %w", err)
	}
	defer rows.Close()

	var toUpdate []*user.UserSecurity
	var totalCleaned int64

	for rows.Next() {
		var userID string
		var securityEventsJSON []byte
		var version int64

		err := rows.Scan(&userID, &securityEventsJSON, &version)
		if err != nil {
			return 0, fmt.Errorf("failed to scan security record for cleanup: %w", err)
		}

		var events []user.SecurityEvent
		if len(securityEventsJSON) > 0 {
			if err := json.Unmarshal(securityEventsJSON, &events); err != nil {
				continue // Skip malformed data
			}
		}

		// Filter events
		var filteredEvents []user.SecurityEvent
		var cleaned int64
		for _, event := range events {
			if event.Timestamp.After(before) {
				filteredEvents = append(filteredEvents, event)
			} else {
				cleaned++
			}
		}

		if cleaned > 0 {
			// Get the full security record to update
			security, err := r.GetSecurity(ctx, userID)
			if err != nil {
				continue // Skip if we can't get the record
			}

			security.SecurityEvents = filteredEvents
			security.UpdatedAt = time.Now()
			security.Version++
			toUpdate = append(toUpdate, security)
			totalCleaned += cleaned
		}
	}

	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("error iterating security records for cleanup: %w", err)
	}

	// Update records with cleaned events
	if len(toUpdate) > 0 {
		if err := r.UpdateSecurityBatch(ctx, toUpdate); err != nil {
			return 0, fmt.Errorf("failed to update cleaned security records: %w", err)
		}
	}

	return totalCleaned, nil
}

// GetSecurityStats returns aggregated security statistics
func (r *securityRepository) GetSecurityStats(ctx context.Context) (*user.SecurityStats, error) {
	query := `
		SELECT 
			COUNT(*) as total_users,
			COUNT(CASE WHEN locked_until IS NOT NULL AND locked_until > NOW() THEN 1 END) as locked_users,
			COUNT(CASE WHEN risk_score >= 75.0 THEN 1 END) as high_risk_users,
			COALESCE(SUM(CASE WHEN last_failed_at >= NOW() - INTERVAL '24 hours' THEN login_attempts ELSE 0 END), 0) as recent_failed_attempts,
			COALESCE(AVG(risk_score), 0.0) as average_risk_score
		FROM user_security`

	stats := &user.SecurityStats{
		UpdatedAt: time.Now(),
	}

	err := r.pool.QueryRow(ctx, query).Scan(
		&stats.TotalUsers,
		&stats.LockedUsers,
		&stats.HighRiskUsers,
		&stats.RecentFailedAttempts,
		&stats.AverageRiskScore,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to get security stats: %w", err)
	}

	return stats, nil
}
