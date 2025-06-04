// repository/postgres/user_repository.go
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

// userRepository implements user.UserRepository for PostgreSQL using pgx/v5
type userRepository struct {
	pool *pgxpool.Pool
}

// NewUserRepository creates a new PostgreSQL user repository
func NewUserRepository(pool *pgxpool.Pool) user.UserRepository {
	return &userRepository{
		pool: pool,
	}
}

// Create stores a new user in the repository
func (r *userRepository) Create(ctx context.Context, u *user.User) error {
	query := `
		INSERT INTO users (
			id, encrypted_first_name, encrypted_last_name, encrypted_email, 
			hashed_email, primary_auth_provider, status, created_at, updated_at, version
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := r.pool.Exec(ctx, query,
		u.ID,
		u.FirstName,
		u.LastName,
		u.Email,
		u.HashedEmail,
		string(u.PrimaryAuthProvider),
		int(u.Status),
		u.CreatedAt,
		u.UpdatedAt,
		u.Version,
	)

	if err != nil {
		// Check for duplicate email constraint violation using pgx error handling
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" && pgErr.ConstraintName == "users_hashed_email_key" {
				return usererrors.NewDuplicateEmailError("user with this email already exists")
			}
		}
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// GetByHashedEmail retrieves a user by their hashed email address
func (r *userRepository) GetByHashedEmail(ctx context.Context, hashedEmail string) (*user.User, error) {
	query := `
		SELECT id, encrypted_first_name, encrypted_last_name, encrypted_email,
			   hashed_email, primary_auth_provider, status, created_at, updated_at, version
		FROM users 
		WHERE hashed_email = $1`

	u := &user.User{}
	var statusInt int
	var providerStr string

	err := r.pool.QueryRow(ctx, query, hashedEmail).Scan(
		&u.ID,
		&u.FirstName,
		&u.LastName,
		&u.Email,
		&u.HashedEmail,
		&providerStr,
		&statusInt,
		&u.CreatedAt,
		&u.UpdatedAt,
		&u.Version,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, usererrors.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by hashed email: %w", err)
	}

	// Convert database values to Go types
	u.Status = user.UserStatus(statusInt)
	u.PrimaryAuthProvider = auth.ProviderType(providerStr)

	return u, nil
}

// GetByID retrieves a user by their unique ID
func (r *userRepository) GetByID(ctx context.Context, id string) (*user.User, error) {
	query := `
		SELECT id, encrypted_first_name, encrypted_last_name, encrypted_email,
			   hashed_email, primary_auth_provider, status, created_at, updated_at, version
		FROM users 
		WHERE id = $1`

	u := &user.User{}
	var statusInt int
	var providerStr string

	err := r.pool.QueryRow(ctx, query, id).Scan(
		&u.ID,
		&u.FirstName,
		&u.LastName,
		&u.Email,
		&u.HashedEmail,
		&providerStr,
		&statusInt,
		&u.CreatedAt,
		&u.UpdatedAt,
		&u.Version,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, usererrors.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	// Convert database values to Go types
	u.Status = user.UserStatus(statusInt)
	u.PrimaryAuthProvider = auth.ProviderType(providerStr)

	return u, nil
}

// Update modifies an existing user in the repository
func (r *userRepository) Update(ctx context.Context, u *user.User) error {
	query := `
		UPDATE users 
		SET encrypted_first_name = $2, encrypted_last_name = $3, encrypted_email = $4,
			hashed_email = $5, primary_auth_provider = $6, status = $7, 
			updated_at = $8, version = $9
		WHERE id = $1 AND version = $10`

	result, err := r.pool.Exec(ctx, query,
		u.ID,
		u.FirstName,
		u.LastName,
		u.Email,
		u.HashedEmail,
		string(u.PrimaryAuthProvider),
		int(u.Status),
		u.UpdatedAt,
		u.Version,
		u.Version-1, // Previous version for optimistic locking
	)

	if err != nil {
		// Check for duplicate email constraint violation using pgx error handling
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" && pgErr.ConstraintName == "users_hashed_email_key" {
				return usererrors.NewDuplicateEmailError("user with this email already exists")
			}
		}
		return fmt.Errorf("failed to update user: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		// Either user doesn't exist or version mismatch
		// Check if user exists
		_, err := r.GetByID(ctx, u.ID)
		if err != nil {
			if usererrors.IsErrorType(err, usererrors.ErrUserNotFound) {
				return usererrors.ErrUserNotFound
			}
			return err
		}
		// User exists, so it must be a version mismatch
		return usererrors.ErrVersionMismatch
	}

	return nil
}

// Delete removes a user from the repository by their ID
func (r *userRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM users WHERE id = $1`

	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return usererrors.ErrUserNotFound
	}

	return nil
}

// UpdateLoginAttempts atomically increments the login attempts counter
// NOTE: This is deprecated in favor of UserSecurity repository
func (r *userRepository) UpdateLoginAttempts(ctx context.Context, hashedEmail string, attempts int) error {
	// This method is kept for interface compatibility but should not be used
	// Login attempts are now managed by UserSecurityRepository
	return usererrors.NewAppError(usererrors.CodeNotImplemented,
		"Login attempts are managed by UserSecurityRepository")
}

// ResetLoginAttempts atomically resets the login attempts counter to zero
// NOTE: This is deprecated in favor of UserSecurity repository
func (r *userRepository) ResetLoginAttempts(ctx context.Context, hashedEmail string) error {
	// This method is kept for interface compatibility but should not be used
	// Login attempts are now managed by UserSecurityRepository
	return usererrors.NewAppError(usererrors.CodeNotImplemented,
		"Login attempts are managed by UserSecurityRepository")
}

// LockAccount sets the account lock status for the user
// NOTE: This is deprecated in favor of UserSecurity repository
func (r *userRepository) LockAccount(ctx context.Context, hashedEmail string, until *time.Time) error {
	// This method is kept for interface compatibility but should not be used
	// Account locking is now managed by UserSecurityRepository
	return usererrors.NewAppError(usererrors.CodeNotImplemented,
		"Account locking is managed by UserSecurityRepository")
}

// ListUsers retrieves users with pagination support
func (r *userRepository) ListUsers(ctx context.Context, offset, limit int) ([]*user.User, int64, error) {
	// First, get the total count
	var totalCount int64
	countQuery := `SELECT COUNT(*) FROM users`
	err := r.pool.QueryRow(ctx, countQuery).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	// Then get the paginated results
	query := `
		SELECT id, encrypted_first_name, encrypted_last_name, encrypted_email,
			   hashed_email, primary_auth_provider, status, created_at, updated_at, version
		FROM users 
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2`

	rows, err := r.pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	var users []*user.User
	for rows.Next() {
		u := &user.User{}
		var statusInt int
		var providerStr string

		err := rows.Scan(
			&u.ID,
			&u.FirstName,
			&u.LastName,
			&u.Email,
			&u.HashedEmail,
			&providerStr,
			&statusInt,
			&u.CreatedAt,
			&u.UpdatedAt,
			&u.Version,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan user row: %w", err)
		}

		// Convert database values to Go types
		u.Status = user.UserStatus(statusInt)
		u.PrimaryAuthProvider = auth.ProviderType(providerStr)

		users = append(users, u)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating user rows: %w", err)
	}

	return users, totalCount, nil
}

// GetUserStats returns aggregated statistics about users
func (r *userRepository) GetUserStats(ctx context.Context) (*user.UserStats, error) {
	query := `
		SELECT 
			COUNT(*) as total_users,
			COUNT(CASE WHEN status = 0 THEN 1 END) as active_users,
			COUNT(CASE WHEN status = 2 THEN 1 END) as pending_verification_users,
			COUNT(CASE WHEN status = 1 THEN 1 END) as suspended_users,
			COUNT(CASE WHEN status = 3 THEN 1 END) as deactivated_users,
			COUNT(CASE WHEN created_at >= NOW() - INTERVAL '24 hours' THEN 1 END) as users_created_last_24h,
			COUNT(CASE WHEN created_at >= NOW() - INTERVAL '7 days' THEN 1 END) as users_created_last_7d,
			COUNT(CASE WHEN created_at >= NOW() - INTERVAL '30 days' THEN 1 END) as users_created_last_30d
		FROM users`

	stats := &user.UserStats{}
	err := r.pool.QueryRow(ctx, query).Scan(
		&stats.TotalUsers,
		&stats.ActiveUsers,
		&stats.PendingVerificationUsers,
		&stats.SuspendedUsers,
		&stats.DeactivatedUsers,
		&stats.UsersCreatedLast24h,
		&stats.UsersCreatedLast7d,
		&stats.UsersCreatedLast30d,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to get user stats: %w", err)
	}

	return stats, nil
}
