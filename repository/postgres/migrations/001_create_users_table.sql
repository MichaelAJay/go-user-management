-- Create users table for core user profile data
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    encrypted_first_name BYTEA NOT NULL,
    encrypted_last_name BYTEA NOT NULL,
    encrypted_email BYTEA NOT NULL,
    hashed_email VARCHAR(255) NOT NULL UNIQUE,
    primary_auth_provider VARCHAR(50) NOT NULL,
    status INTEGER NOT NULL DEFAULT 2, -- 0=active, 1=suspended, 2=pending_verification, 3=deactivated
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    version BIGINT NOT NULL DEFAULT 1
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_hashed_email ON users(hashed_email);

-- repository/postgres/migrations/002_create_user_credentials_table.sql

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

-- repository/postgres/migrations/003_create_user_security_table.sql

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
CREATE INDEX IF NOT EXISTS idx_user_security_mfa_enabled ON user_security(mfa_enabled);

-- repository/postgres/migrations/004_add_constraints_and_checks.sql

-- Add check constraints for data integrity
ALTER TABLE users ADD CONSTRAINT check_status_valid 
    CHECK (status IN (0, 1, 2, 3));

ALTER TABLE users ADD CONSTRAINT check_version_positive 
    CHECK (version > 0);

ALTER TABLE user_credentials ADD CONSTRAINT check_credential_status_valid 
    CHECK (status IN (0, 1, 2, 3, 4));

ALTER TABLE user_credentials ADD CONSTRAINT check_credential_version_positive 
    CHECK (version > 0);

ALTER TABLE user_credentials ADD CONSTRAINT check_failed_attempts_non_negative 
    CHECK (failed_attempts >= 0);

ALTER TABLE user_security ADD CONSTRAINT check_security_version_positive 
    CHECK (version > 0);

ALTER TABLE user_security ADD CONSTRAINT check_login_attempts_non_negative 
    CHECK (login_attempts >= 0);

ALTER TABLE user_security ADD CONSTRAINT check_total_login_attempts_non_negative 
    CHECK (total_login_attempts >= 0);

ALTER TABLE user_security ADD CONSTRAINT check_successful_logins_non_negative 
    CHECK (successful_logins >= 0);

ALTER TABLE user_security ADD CONSTRAINT check_risk_score_range 
    CHECK (risk_score >= 0.0 AND risk_score <= 100.0);

-- repository/postgres/migrations/005_create_indexes_for_queries.sql

-- Additional indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_user_security_locked_only 
    ON user_security(locked_until) WHERE locked_until IS NOT NULL;