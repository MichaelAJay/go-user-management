// repository/provider.go
package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/MichaelAJay/go-user-management/repository/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Provider defines the interface for repository providers
// This follows the same pattern as your auth package
type Provider interface {
	// GetUserRepository returns the user repository implementation
	GetUserRepository() UserRepository

	// GetAuthRepository returns the authentication repository implementation
	GetAuthRepository() AuthenticationRepository

	// GetSecurityRepository returns the security repository implementation
	GetSecurityRepository() UserSecurityRepository

	// Close cleans up any resources held by the provider
	Close() error

	// Ping checks if the underlying storage is accessible
	Ping() error
}

// ProviderType represents different repository provider types
type ProviderType string

const (
	// ProviderTypePostgres represents PostgreSQL repository provider
	ProviderTypePostgres ProviderType = "postgres"

	// ProviderTypeMemory represents in-memory repository provider (for testing)
	ProviderTypeMemory ProviderType = "memory"

	// Future providers could include:
	// ProviderTypeMySQL ProviderType = "mysql"
	// ProviderTypeMongoDB ProviderType = "mongodb"
	// ProviderTypeRedis ProviderType = "redis"
)

// Config contains configuration for repository providers
type Config struct {
	Type ProviderType `json:"type"`

	// Database connection settings (for SQL providers)
	DatabaseURL     string `json:"database_url,omitempty"`
	MaxOpenConns    int    `json:"max_open_conns,omitempty"`
	MaxIdleConns    int    `json:"max_idle_conns,omitempty"`
	ConnMaxLifetime string `json:"conn_max_lifetime,omitempty"`

	// Additional provider-specific settings can be added here
}

// NewProvider creates a new repository provider based on the configuration
func NewProvider(config Config) (Provider, error) {
	switch config.Type {
	case ProviderTypePostgres:
		return NewPostgresProvider(config)
	case ProviderTypeMemory:
		return NewMemoryProvider(config)
	default:
		return nil, fmt.Errorf("unsupported repository provider type: %s", config.Type)
	}
}

// PostgresProvider implements Provider for PostgreSQL using pgx/v5
type PostgresProvider struct {
	pool         *pgxpool.Pool
	userRepo     UserRepository
	authRepo     AuthenticationRepository
	securityRepo UserSecurityRepository
}

// NewPostgresProvider creates a new PostgreSQL repository provider
func NewPostgresProvider(config Config) (*PostgresProvider, error) {
	if config.DatabaseURL == "" {
		return nil, fmt.Errorf("database URL is required for PostgreSQL provider")
	}

	// Configure connection pool
	poolConfig, err := pgxpool.ParseConfig(config.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database URL: %w", err)
	}

	// Configure connection pool settings if specified
	if config.MaxOpenConns > 0 {
		poolConfig.MaxConns = int32(config.MaxOpenConns)
	}
	if config.MaxIdleConns > 0 {
		poolConfig.MinConns = int32(config.MaxIdleConns)
	}
	if config.ConnMaxLifetime != "" {
		if duration, err := time.ParseDuration(config.ConnMaxLifetime); err == nil {
			poolConfig.MaxConnLifetime = duration
		}
	}

	// Create connection pool
	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test the connection
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Create repository implementations
	userRepo := postgres.NewUserRepository(pool)
	authRepo := postgres.NewAuthRepository(pool)
	securityRepo := postgres.NewSecurityRepository(pool)

	return &PostgresProvider{
		pool:         pool,
		userRepo:     userRepo,
		authRepo:     authRepo,
		securityRepo: securityRepo,
	}, nil
}

// GetUserRepository returns the user repository implementation
func (p *PostgresProvider) GetUserRepository() UserRepository {
	return p.userRepo
}

// GetAuthRepository returns the authentication repository implementation
func (p *PostgresProvider) GetAuthRepository() AuthenticationRepository {
	return p.authRepo
}

// GetSecurityRepository returns the security repository implementation
func (p *PostgresProvider) GetSecurityRepository() UserSecurityRepository {
	return p.securityRepo
}

// Close closes the database connection
func (p *PostgresProvider) Close() error {
	if p.db != nil {
		return p.db.Close()
	}
	return nil
}

// Ping checks if the database is accessible
func (p *PostgresProvider) Ping() error {
	if p.db != nil {
		return p.db.Ping()
	}
	return fmt.Errorf("database connection is nil")
}

// MemoryProvider implements Provider for in-memory storage (useful for testing)
type MemoryProvider struct {
	userRepo     UserRepository
	authRepo     AuthenticationRepository
	securityRepo UserSecurityRepository
}

// NewMemoryProvider creates a new in-memory repository provider
func NewMemoryProvider(config Config) (*MemoryProvider, error) {
	// Import would be: "github.com/MichaelAJay/go-user-management/repository/memory"
	// For now, return a basic implementation
	return &MemoryProvider{
		// userRepo:     memory.NewUserRepository(),
		// authRepo:     memory.NewAuthRepository(),
		// securityRepo: memory.NewSecurityRepository(),
	}, nil
}

// GetUserRepository returns the user repository implementation
func (p *MemoryProvider) GetUserRepository() UserRepository {
	return p.userRepo
}

// GetAuthRepository returns the authentication repository implementation
func (p *MemoryProvider) GetAuthRepository() AuthenticationRepository {
	return p.authRepo
}

// GetSecurityRepository returns the security repository implementation
func (p *MemoryProvider) GetSecurityRepository() UserSecurityRepository {
	return p.securityRepo
}

// Close cleans up any resources (no-op for memory provider)
func (p *MemoryProvider) Close() error {
	return nil
}

// Ping checks if the provider is accessible (always true for memory provider)
func (p *MemoryProvider) Ping() error {
	return nil
}
