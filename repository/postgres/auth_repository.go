// repository/postgres/auth_repository.go
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/MichaelAJay/go-user-management/auth"
	usererrors "github.com/MichaelAJay/go-user-management/errors"
	"github.com/MichaelAJay/go-user-management/user"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// authRepository implements user.AuthenticationRepository for PostgreSQL using pgx/v5
type authRepository struct {
	pool *pgxpool.Pool
}

// NewAuthRepository creates a new PostgreSQL authentication repository
func NewAuthRepository(pool *pgxpool.Pool) user.AuthenticationRepository {
	return &authRepository{
		pool: pool,
	}
}

// CreateCredentials stores new credentials for a user and provider
func (r *authRepository) CreateCredentials(ctx context.Context, creds *user.UserCredentials) error {
	query := `
		INSERT INTO user_credentials (
			user_id, provider_type, encrypted_auth_data, status, 
			created_at, updated_at, expires_at, last_used_at, 
			failed_attempts, version
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := r.pool.Exec(ctx, query,
		creds.UserID,
		string(creds.ProviderType),
		creds.EncryptedAuthData,
		int(creds.Status),
		creds.CreatedAt,
		creds.UpdatedAt,
		creds.ExpiresAt,
		creds.LastUsedAt,
		creds.FailedAttempts,
		creds.Version,
	)

	if err != nil {
		// Check for duplicate credentials constraint violation
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" && pgErr.ConstraintName == "user_credentials_pkey" {
				return usererrors.NewAppError(usererrors.CodeDuplicateEmail, "credentials already exist for this user and provider")
			}
		}
		return fmt.Errorf("failed to create credentials: %w", err)
	}

	return nil
}

// GetCredentials retrieves credentials for a user and provider
func (r *authRepository) GetCredentials(ctx context.Context, userID string, providerType auth.ProviderType) (*user.UserCredentials, error) {
	query := `
		SELECT user_id, provider_type, encrypted_auth_data, status,
			   created_at, updated_at, expires_at, last_used_at,
			   failed_attempts, version
		FROM user_credentials 
		WHERE user_id = $1 AND provider_type = $2`

	creds := &user.UserCredentials{}
	var statusInt int
	var providerStr string

	err := r.pool.QueryRow(ctx, query, userID, string(providerType)).Scan(
		&creds.UserID,
		&providerStr,
		&creds.EncryptedAuthData,
		&statusInt,
		&creds.CreatedAt,
		&creds.UpdatedAt,
		&creds.ExpiresAt,
		&creds.LastUsedAt,
		&creds.FailedAttempts,
		&creds.Version,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, usererrors.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}

	// Convert database values to Go types
	creds.Status = user.CredentialStatus(statusInt)
	creds.ProviderType = auth.ProviderType(providerStr)

	return creds, nil
}

// UpdateCredentials updates existing credentials
func (r *authRepository) UpdateCredentials(ctx context.Context, creds *user.UserCredentials) error {
	query := `
		UPDATE user_credentials 
		SET encrypted_auth_data = $3, status = $4, updated_at = $5,
			expires_at = $6, last_used_at = $7, failed_attempts = $8, version = $9
		WHERE user_id = $1 AND provider_type = $2 AND version = $10`

	result, err := r.pool.Exec(ctx, query,
		creds.UserID,
		string(creds.ProviderType),
		creds.EncryptedAuthData,
		int(creds.Status),
		creds.UpdatedAt,
		creds.ExpiresAt,
		creds.LastUsedAt,
		creds.FailedAttempts,
		creds.Version,
		creds.Version-1, // Previous version for optimistic locking
	)

	if err != nil {
		return fmt.Errorf("failed to update credentials: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		// Either credentials don't exist or version mismatch
		// Check if credentials exist
		_, err := r.GetCredentials(ctx, creds.UserID, creds.ProviderType)
		if err != nil {
			if usererrors.IsErrorType(err, usererrors.ErrUserNotFound) {
				return usererrors.ErrUserNotFound
			}
			return err
		}
		// Credentials exist, so it must be a version mismatch
		return usererrors.ErrVersionMismatch
	}

	return nil
}

// DeleteCredentials removes credentials for a user and provider
func (r *authRepository) DeleteCredentials(ctx context.Context, userID string, providerType auth.ProviderType) error {
	query := `DELETE FROM user_credentials WHERE user_id = $1 AND provider_type = $2`

	result, err := r.pool.Exec(ctx, query, userID, string(providerType))
	if err != nil {
		return fmt.Errorf("failed to delete credentials: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return usererrors.ErrUserNotFound
	}

	return nil
}

// GetAllCredentials retrieves all credentials for a user
func (r *authRepository) GetAllCredentials(ctx context.Context, userID string) ([]*user.UserCredentials, error) {
	query := `
		SELECT user_id, provider_type, encrypted_auth_data, status,
			   created_at, updated_at, expires_at, last_used_at,
			   failed_attempts, version
		FROM user_credentials 
		WHERE user_id = $1
		ORDER BY created_at ASC`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get all credentials: %w", err)
	}
	defer rows.Close()

	var credentials []*user.UserCredentials
	for rows.Next() {
		creds := &user.UserCredentials{}
		var statusInt int
		var providerStr string

		err := rows.Scan(
			&creds.UserID,
			&providerStr,
			&creds.EncryptedAuthData,
			&statusInt,
			&creds.CreatedAt,
			&creds.UpdatedAt,
			&creds.ExpiresAt,
			&creds.LastUsedAt,
			&creds.FailedAttempts,
			&creds.Version,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan credentials row: %w", err)
		}

		// Convert database values to Go types
		creds.Status = user.CredentialStatus(statusInt)
		creds.ProviderType = auth.ProviderType(providerStr)

		credentials = append(credentials, creds)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating credentials rows: %w", err)
	}

	return credentials, nil
}

// GetActiveProviders returns list of active providers for a user
func (r *authRepository) GetActiveProviders(ctx context.Context, userID string) ([]auth.ProviderType, error) {
	query := `
		SELECT provider_type
		FROM user_credentials 
		WHERE user_id = $1 AND status = $2
		ORDER BY created_at ASC`

	rows, err := r.pool.Query(ctx, query, userID, int(user.CredentialStatusActive))
	if err != nil {
		return nil, fmt.Errorf("failed to get active providers: %w", err)
	}
	defer rows.Close()

	var providers []auth.ProviderType
	for rows.Next() {
		var providerStr string
		err := rows.Scan(&providerStr)
		if err != nil {
			return nil, fmt.Errorf("failed to scan provider row: %w", err)
		}
		providers = append(providers, auth.ProviderType(providerStr))
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating provider rows: %w", err)
	}

	return providers, nil
}

// GetCredentialsBatch retrieves credentials for multiple users
func (r *authRepository) GetCredentialsBatch(ctx context.Context, userIDs []string, providerType auth.ProviderType) (map[string]*user.UserCredentials, error) {
	if len(userIDs) == 0 {
		return make(map[string]*user.UserCredentials), nil
	}

	query := `
		SELECT user_id, provider_type, encrypted_auth_data, status,
			   created_at, updated_at, expires_at, last_used_at,
			   failed_attempts, version
		FROM user_credentials 
		WHERE user_id = ANY($1) AND provider_type = $2`

	rows, err := r.pool.Query(ctx, query, userIDs, string(providerType))
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials batch: %w", err)
	}
	defer rows.Close()

	result := make(map[string]*user.UserCredentials)
	for rows.Next() {
		creds := &user.UserCredentials{}
		var statusInt int
		var providerStr string

		err := rows.Scan(
			&creds.UserID,
			&providerStr,
			&creds.EncryptedAuthData,
			&statusInt,
			&creds.CreatedAt,
			&creds.UpdatedAt,
			&creds.ExpiresAt,
			&creds.LastUsedAt,
			&creds.FailedAttempts,
			&creds.Version,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan credentials batch row: %w", err)
		}

		// Convert database values to Go types
		creds.Status = user.CredentialStatus(statusInt)
		creds.ProviderType = auth.ProviderType(providerStr)

		result[creds.UserID] = creds
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating credentials batch rows: %w", err)
	}

	return result, nil
}

// ExpireCredentials marks credentials as expired
func (r *authRepository) ExpireCredentials(ctx context.Context, userID string, providerType auth.ProviderType) error {
	query := `
		UPDATE user_credentials 
		SET status = $3, updated_at = $4, version = version + 1
		WHERE user_id = $1 AND provider_type = $2`

	result, err := r.pool.Exec(ctx, query,
		userID,
		string(providerType),
		int(user.CredentialStatusExpired),
		time.Now(),
	)

	if err != nil {
		return fmt.Errorf("failed to expire credentials: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return usererrors.ErrUserNotFound
	}

	return nil
}

// RevokeCredentials marks credentials as revoked
func (r *authRepository) RevokeCredentials(ctx context.Context, userID string, providerType auth.ProviderType) error {
	query := `
		UPDATE user_credentials 
		SET status = $3, updated_at = $4, version = version + 1
		WHERE user_id = $1 AND provider_type = $2`

	result, err := r.pool.Exec(ctx, query,
		userID,
		string(providerType),
		int(user.CredentialStatusRevoked),
		time.Now(),
	)

	if err != nil {
		return fmt.Errorf("failed to revoke credentials: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return usererrors.ErrUserNotFound
	}

	return nil
}

// DeleteExpiredCredentials removes credentials that expired before the given time
func (r *authRepository) DeleteExpiredCredentials(ctx context.Context, before time.Time) (int64, error) {
	query := `
		DELETE FROM user_credentials 
		WHERE expires_at IS NOT NULL AND expires_at < $1`

	result, err := r.pool.Exec(ctx, query, before)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired credentials: %w", err)
	}

	return result.RowsAffected(), nil
}

// DeleteUserCredentials removes all credentials for a user
func (r *authRepository) DeleteUserCredentials(ctx context.Context, userID string) error {
	query := `DELETE FROM user_credentials WHERE user_id = $1`

	_, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user credentials: %w", err)
	}

	return nil
}

// RecordCredentialUsage records that credentials were used
func (r *authRepository) RecordCredentialUsage(ctx context.Context, userID string, providerType auth.ProviderType) error {
	query := `
		UPDATE user_credentials 
		SET last_used_at = $3, updated_at = $4, version = version + 1
		WHERE user_id = $1 AND provider_type = $2`

	now := time.Now()
	result, err := r.pool.Exec(ctx, query,
		userID,
		string(providerType),
		now,
		now,
	)

	if err != nil {
		return fmt.Errorf("failed to record credential usage: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return usererrors.ErrUserNotFound
	}

	return nil
}

// RecordFailedAttempt records a failed authentication attempt
func (r *authRepository) RecordFailedAttempt(ctx context.Context, userID string, providerType auth.ProviderType) error {
	query := `
		UPDATE user_credentials 
		SET failed_attempts = failed_attempts + 1, updated_at = $3, version = version + 1
		WHERE user_id = $1 AND provider_type = $2`

	result, err := r.pool.Exec(ctx, query,
		userID,
		string(providerType),
		time.Now(),
	)

	if err != nil {
		return fmt.Errorf("failed to record failed attempt: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return usererrors.ErrUserNotFound
	}

	return nil
}
