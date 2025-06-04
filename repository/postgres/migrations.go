// repository/postgres/migrations.go
package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Migration represents a database migration
type Migration struct {
	Version int
	Name    string
	SQL     string
}

// GetMigrations returns all available migrations
func GetMigrations() []Migration {
	return []Migration{
		{
			Version: 1,
			Name:    "create_users_table",
			SQL: `
-- Create users table for core user profile data
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    encrypted_first_name BYTEA NOT NULL,
    encrypted_last_name BYTEA NOT NULL,
    encrypted_email BYTEA NOT NULL,
    hashed_email VARCHAR(255) NOT NULL UNIQUE,
    primary_auth_provider VARCHAR(50) NOT NULL,
    status INTEGER NOT NULL DEFAULT 2, -- 0=active, 1=suspended, 2=pending_verification, 3=deactivated
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    version BIGINT NOT NULL DEFAULT 1
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_hashed_email ON users(hashed_email);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);
CREATE INDEX IF NOT EXISTS idx_users_primary_auth_provider ON users(primary_auth_provider);
			`,
		},
		{
			Version: 2,
			Name:    "create_user_credentials_table",
			SQL: `
-- Create user_credentials table for authentication data
CREATE TABLE IF NOT EXISTS user_credentials (
    user_id UUID NOT NULL,
    provider_type VARCHAR(50) NOT NULL,
    encrypted_auth_data BYTEA NOT NULL,
    status INTEGER NOT NULL DEFAULT 0, -- 0=active, 1=expired, 2=revoked, 3=pending_validation, 4=suspended
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    version BIGINT NOT NULL DEFAULT 1,
    
    PRIMARY KEY (user_id, provider_type),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_user_credentials_user_id ON user_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_user_credentials_provider_type ON user_credentials(provider_type);
CREATE INDEX IF NOT EXISTS idx_user_credentials_status ON user_credentials(status);
CREATE INDEX IF NOT EXISTS idx_user_credentials_expires_at ON user_credentials(expires_at);
CREATE INDEX IF NOT EXISTS idx_user_credentials_last_used_at ON user_credentials(last_used_at);
			`,
		},
		{
			Version: 3,
			Name:    "create_user_security_table",
			SQL: `
-- Create user_security table for security state and tracking
CREATE TABLE IF NOT EXISTS user_security (
    user_id UUID PRIMARY KEY,
    login_attempts INTEGER NOT NULL DEFAULT 0,
    last_failed_at TIMESTAMP WITH TIME ZONE,
    locked_until TIMESTAMP WITH TIME ZONE,
    lock_reason VARCHAR(255),
    last_login_at TIMESTAMP WITH TIME ZONE,
    last_login_ip INET,
    total_login_attempts INTEGER NOT NULL DEFAULT 0,
    successful_logins INTEGER NOT NULL DEFAULT 0,
    risk_score FLOAT NOT NULL DEFAULT 0.0,
    risk_factors JSONB,
    security_events JSONB,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_backup_codes BYTEA,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    version BIGINT NOT NULL DEFAULT 1,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_user_security_locked_until ON user_security(locked_until);
CREATE INDEX IF NOT EXISTS idx_user_security_last_login_at ON user_security(last_login_at);
CREATE INDEX IF NOT EXISTS idx_user_security_risk_score ON user_security(risk_score);
CREATE INDEX IF NOT EXISTS idx_user_security_mfa_enabled ON user_security(mfa_enabled);
CREATE INDEX IF NOT EXISTS idx_user_security_last_failed_at ON user_security(last_failed_at);

-- GIN index for JSONB columns
CREATE INDEX IF NOT EXISTS idx_user_security_risk_factors ON user_security USING GIN(risk_factors);
CREATE INDEX IF NOT EXISTS idx_user_security_events ON user_security USING GIN(security_events);
			`,
		},
		{
			Version: 4,
			Name:    "add_constraints_and_checks",
			SQL: `
-- Add check constraints for data integrity
ALTER TABLE users ADD CONSTRAINT IF NOT EXISTS check_status_valid 
    CHECK (status IN (0, 1, 2, 3));

ALTER TABLE users ADD CONSTRAINT IF NOT EXISTS check_version_positive 
    CHECK (version > 0);

ALTER TABLE user_credentials ADD CONSTRAINT IF NOT EXISTS check_credential_status_valid 
    CHECK (status IN (0, 1, 2, 3, 4));

ALTER TABLE user_credentials ADD CONSTRAINT IF NOT EXISTS check_credential_version_positive 
    CHECK (version > 0);

ALTER TABLE user_credentials ADD CONSTRAINT IF NOT EXISTS check_failed_attempts_non_negative 
    CHECK (failed_attempts >= 0);

ALTER TABLE user_security ADD CONSTRAINT IF NOT EXISTS check_security_version_positive 
    CHECK (version > 0);

ALTER TABLE user_security ADD CONSTRAINT IF NOT EXISTS check_login_attempts_non_negative 
    CHECK (login_attempts >= 0);

ALTER TABLE user_security ADD CONSTRAINT IF NOT EXISTS check_total_login_attempts_non_negative 
    CHECK (total_login_attempts >= 0);

ALTER TABLE user_security ADD CONSTRAINT IF NOT EXISTS check_successful_logins_non_negative 
    CHECK (successful_logins >= 0);

ALTER TABLE user_security ADD CONSTRAINT IF NOT EXISTS check_risk_score_range 
    CHECK (risk_score >= 0.0 AND risk_score <= 100.0);
			`,
		},
		{
			Version: 5,
			Name:    "create_indexes_for_queries",
			SQL: `
-- Additional indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_users_compound_status_created 
    ON users(status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_user_credentials_compound_user_status 
    ON user_credentials(user_id, status);

CREATE INDEX IF NOT EXISTS idx_user_security_compound_risk 
    ON user_security(risk_score DESC, last_login_at DESC);

-- Partial indexes for specific scenarios
CREATE INDEX IF NOT EXISTS idx_users_active_only 
    ON users(created_at DESC) WHERE status = 0;

CREATE INDEX IF NOT EXISTS idx_user_security_locked_only 
    ON user_security(locked_until) WHERE locked_until IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_user_security_high_risk 
    ON user_security(risk_score DESC, user_id) WHERE risk_score >= 75.0;
			`,
		},
	}
}

// RunMigrations applies all migrations to the database
func RunMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	// Create migrations table if it doesn't exist
	if err := createMigrationsTable(ctx, pool); err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Get current migration version
	currentVersion, err := getCurrentMigrationVersion(ctx, pool)
	if err != nil {
		return fmt.Errorf("failed to get current migration version: %w", err)
	}

	// Apply pending migrations
	migrations := GetMigrations()
	for _, migration := range migrations {
		if migration.Version <= currentVersion {
			continue // Skip already applied migrations
		}

		fmt.Printf("Applying migration %d: %s\n", migration.Version, migration.Name)

		// Start transaction
		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("failed to begin transaction for migration %d: %w", migration.Version, err)
		}

		// Apply migration SQL
		if _, err := tx.Exec(ctx, migration.SQL); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("failed to apply migration %d (%s): %w", migration.Version, migration.Name, err)
		}

		// Record migration as applied
		if _, err := tx.Exec(ctx,
			"INSERT INTO schema_migrations (version, name, applied_at) VALUES ($1, $2, NOW())",
			migration.Version, migration.Name); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("failed to record migration %d: %w", migration.Version, err)
		}

		// Commit transaction
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit migration %d: %w", migration.Version, err)
		}

		fmt.Printf("Migration %d applied successfully\n", migration.Version)
	}

	return nil
}

// createMigrationsTable creates the schema_migrations table
func createMigrationsTable(ctx context.Context, pool *pgxpool.Pool) error {
	query := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
		);
	`
	_, err := pool.Exec(ctx, query)
	return err
}

// getCurrentMigrationVersion returns the highest applied migration version
func getCurrentMigrationVersion(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	var version int
	err := pool.QueryRow(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&version)
	return version, err
}

// ResetDatabase drops all tables (useful for testing)
func ResetDatabase(ctx context.Context, pool *pgxpool.Pool) error {
	queries := []string{
		"DROP TABLE IF EXISTS user_security CASCADE;",
		"DROP TABLE IF EXISTS user_credentials CASCADE;",
		"DROP TABLE IF EXISTS users CASCADE;",
		"DROP TABLE IF EXISTS schema_migrations CASCADE;",
	}

	for _, query := range queries {
		if _, err := pool.Exec(ctx, query); err != nil {
			return fmt.Errorf("failed to execute reset query '%s': %w", query, err)
		}
	}

	return nil
}
