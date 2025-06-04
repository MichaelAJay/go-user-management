// repository/postgres/postgres_test.go
package postgres

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/MichaelAJay/go-user-management/auth"
	"github.com/MichaelAJay/go-user-management/errors"
	"github.com/MichaelAJay/go-user-management/user"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	testPool *pgxpool.Pool
)

func TestMain(m *testing.M) {
	// Setup test database
	ctx := context.Background()
	
	// Skip if no test database URL provided
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		// Skip integration tests if no database available
		os.Exit(0)
	}

	// Create connection pool
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		panic("Failed to create test database pool: " + err.Error())
	}

	// Test connection
	if err := pool.Ping(ctx); err != nil {
		panic("Failed to ping test database: " + err.Error())
	}

	testPool = pool

	// Reset database before tests
	if err := ResetDatabase(ctx, testPool); err != nil {
		panic("Failed to reset test database: " + err.Error())
	}

	// Run migrations
	if err := RunMigrations(ctx, testPool); err != nil {
		panic("Failed to run migrations: " + err.Error())
	}

	// Run tests
	code := m.Run()

	// Cleanup
	testPool.Close()

	os.Exit(code)
}

// Test helper functions
func createTestUser() *user.User {
	return user.NewUser("John", "Doe", "john.doe@example.com", "hashed_email_123", auth.ProviderTypePassword)
}

func createTestCredentials(userID string) *user.UserCredentials {
	return user.NewUserCredentials(userID, auth.ProviderTypePassword, []byte("encrypted_auth_data"))
}

func createTestSecurity(userID string) *user.UserSecurity {
	return user.NewUserSecurity(userID)
}

// User Repository Integration Tests
func TestUserRepository_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()
	repo := NewUserRepository(testPool)

	t.Run("Create and Get User", func(t *testing.T) {
		// Clean up any existing test data
		cleanupTestData(t, ctx)

		testUser := createTestUser()

		// Create user
		err := repo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		// Get by ID
		retrieved, err := repo.GetByID(ctx, testUser.ID)
		if err != nil {
			t.Fatalf("Failed to get user by ID: %v", err)
		}
		if retrieved.ID != testUser.ID {
			t.Errorf("Expected ID %s, got %s", testUser.ID, retrieved.ID)
		}
		if retrieved.HashedEmail != testUser.HashedEmail {
			t.Errorf("Expected HashedEmail %s, got %s", testUser.HashedEmail, retrieved.HashedEmail)
		}
		if retrieved.PrimaryAuthProvider != testUser.PrimaryAuthProvider {
			t.Errorf("Expected PrimaryAuthProvider %s, got %s", testUser.PrimaryAuthProvider, retrieved.PrimaryAuthProvider)
		}
		if retrieved.Status != testUser.Status {
			t.Errorf("Expected Status %v, got %v", testUser.Status, retrieved.Status)
		}

		// Get by hashed email
		retrievedByEmail, err := repo.GetByHashedEmail(ctx, testUser.HashedEmail)
		if err != nil {
			t.Fatalf("Failed to get user by hashed email: %v", err)
		}
		if retrievedByEmail.ID != testUser.ID {
			t.Errorf("Expected ID %s, got %s", testUser.ID, retrievedByEmail.ID)
		}
	})

	t.Run("Update User", func(t *testing.T) {
		cleanupTestData(t, ctx)

		testUser := createTestUser()
		err := repo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		// Update user status
		testUser.Status = user.UserStatusActive
		testUser.Version++
		testUser.UpdatedAt = time.Now()

		err = repo.Update(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to update user: %v", err)
		}

		// Verify update
		retrieved, err := repo.GetByID(ctx, testUser.ID)
		if err != nil {
			t.Fatalf("Failed to retrieve updated user: %v", err)
		}
		if retrieved.Status != user.UserStatusActive {
			t.Errorf("Expected status %v, got %v", user.UserStatusActive, retrieved.Status)
		}
		if retrieved.Version != testUser.Version {
			t.Errorf("Expected version %d, got %d", testUser.Version, retrieved.Version)
		}
	})

	t.Run("Delete User", func(t *testing.T) {
		cleanupTestData(t, ctx)

		testUser := createTestUser()
		err := repo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		// Delete user
		err = repo.Delete(ctx, testUser.ID)
		if err != nil {
			t.Fatalf("Failed to delete user: %v", err)
		}

		// Verify deletion
		_, err = repo.GetByID(ctx, testUser.ID)
		if !errors.IsErrorType(err, errors.ErrUserNotFound) {
			t.Errorf("Expected user not found error after deletion, got: %v", err)
		}
	})

	t.Run("Duplicate Email Error", func(t *testing.T) {
		cleanupTestData(t, ctx)

		testUser1 := createTestUser()
		err := repo.Create(ctx, testUser1)
		if err != nil {
			t.Fatalf("Failed to create first user: %v", err)
		}

		// Try to create another user with same hashed email
		testUser2 := createTestUser()
		testUser2.ID = "different-id"
		err = repo.Create(ctx, testUser2)
		if !errors.IsErrorType(err, errors.ErrDuplicateEmail) {
			t.Errorf("Expected duplicate email error, got: %v", err)
		}
	})

	t.Run("Version Mismatch Error", func(t *testing.T) {
		cleanupTestData(t, ctx)

		testUser := createTestUser()
		err := repo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		// Try to update with wrong version
		testUser.Status = user.UserStatusActive
		testUser.Version = 999 // Wrong version
		testUser.UpdatedAt = time.Now()

		err = repo.Update(ctx, testUser)
		if !errors.IsErrorType(err, errors.ErrVersionMismatch) {
			t.Errorf("Expected version mismatch error, got: %v", err)
		}
	})

	t.Run("List Users", func(t *testing.T) {
		cleanupTestData(t, ctx)

		// Create multiple users
		for i := 0; i < 5; i++ {
			testUser := createTestUser()
			testUser.ID = fmt.Sprintf("user-%d", i)
			testUser.HashedEmail = fmt.Sprintf("hashed_email_%d", i)
			err := repo.Create(ctx, testUser)
			if err != nil {
				t.Fatalf("Failed to create user %d: %v", i, err)
			}
		}

		// List users with pagination
		users, total, err := repo.ListUsers(ctx, 0, 3)
		if err != nil {
			t.Fatalf("Failed to list users: %v", err)
		}
		if total != 5 {
			t.Errorf("Expected total count 5, got %d", total)
		}
		if len(users) != 3 {
			t.Errorf("Expected 3 users in first page, got %d", len(users))
		}

		// List remaining users
		users, total, err = repo.ListUsers(ctx, 3, 3)
		if err != nil {
			t.Fatalf("Failed to list remaining users: %v", err)
		}
		if total != 5 {
			t.Errorf("Expected total count 5, got %d", total)
		}
		if len(users) != 2 {
			t.Errorf("Expected 2 users in second page, got %d", len(users))
		}
	})

	t.Run("Get User Stats", func(t *testing.T) {
		cleanupTestData(t, ctx)

		// Create users with different statuses
		statuses := []user.UserStatus{
			user.UserStatusActive,
			user.UserStatusActive,
			user.UserStatusSuspended,
			user.UserStatusPendingVerification,
		}

		for i, status := range statuses {
			testUser := createTestUser()
			testUser.ID = fmt.Sprintf("stats-user-%d", i)
			testUser.HashedEmail = fmt.Sprintf("stats_email_%d", i)
			testUser.Status = status
			err := repo.Create(ctx, testUser)
			if err != nil {
				t.Fatalf("Failed to create user %d: %v", i, err)
			}
		}

		stats, err := repo.GetUserStats(ctx)
		if err != nil {
			t.Fatalf("Failed to get user stats: %v", err)
		}
		if stats.TotalUsers != 4 {
			t.Errorf("Expected total users 4, got %d", stats.TotalUsers)
		}
		if stats.ActiveUsers != 2 {
			t.Errorf("Expected active users 2, got %d", stats.ActiveUsers)
		}
		if stats.SuspendedUsers != 1 {
			t.Errorf("Expected suspended users 1, got %d", stats.SuspendedUsers)
		}
		if stats.PendingVerificationUsers != 1 {
			t.Errorf("Expected pending verification users 1, got %d", stats.PendingVerificationUsers)
		}
	})
}

// Auth Repository Integration Tests
func TestAuthRepository_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()
	userRepo := NewUserRepository(testPool)
	authRepo := NewAuthRepository(testPool)

	t.Run("Create and Get Credentials", func(t *testing.T) {
		cleanupTestData(t, ctx)

		// Create user first
		testUser := createTestUser()
		err := userRepo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		// Create credentials
		creds := createTestCredentials(testUser.ID)
		err = authRepo.CreateCredentials(ctx, creds)
		if err != nil {
			t.Fatalf("Failed to create credentials: %v", err)
		}

		// Get credentials
		retrieved, err := authRepo.GetCredentials(ctx, testUser.ID, auth.ProviderTypePassword)
		if err != nil {
			t.Fatalf("Failed to get credentials: %v", err)
		}
		if retrieved.UserID != testUser.ID {
			t.Errorf("Expected UserID %s, got %s", testUser.ID, retrieved.UserID)
		}
		if retrieved.ProviderType != auth.ProviderTypePassword {
			t.Errorf("Expected ProviderType %s, got %s", auth.ProviderTypePassword, retrieved.ProviderType)
		}
		if retrieved.Status != user.CredentialStatusActive {
			t.Errorf("Expected Status %v, got %v", user.CredentialStatusActive, retrieved.Status)
		}
	})

	t.Run("Update Credentials", func(t *testing.T) {
		cleanupTestData(t, ctx)

		testUser := createTestUser()
		err := userRepo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		creds := createTestCredentials(testUser.ID)
		err = authRepo.CreateCredentials(ctx, creds)
		if err != nil {
			t.Fatalf("Failed to create credentials: %v", err)
		}

		// Update credentials
		creds.EncryptedAuthData = []byte("new_encrypted_data")
		creds.Version++
		creds.UpdatedAt = time.Now()

		err = authRepo.UpdateCredentials(ctx, creds)
		if err != nil {
			t.Fatalf("Failed to update credentials: %v", err)
		}

		// Verify update
		retrieved, err := authRepo.GetCredentials(ctx, testUser.ID, auth.ProviderTypePassword)
		if err != nil {
			t.Fatalf("Failed to get updated credentials: %v", err)
		}
		if string(retrieved.EncryptedAuthData) != "new_encrypted_data" {
			t.Errorf("Expected EncryptedAuthData 'new_encrypted_data', got %s", string(retrieved.EncryptedAuthData))
		}
	})

	t.Run("Get Active Providers", func(t *testing.T) {
		cleanupTestData(t, ctx)

		testUser := createTestUser()
		err := userRepo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		// Create multiple credentials
		passwordCreds := createTestCredentials(testUser.ID)
		err = authRepo.CreateCredentials(ctx, passwordCreds)
		if err != nil {
			t.Fatalf("Failed to create password credentials: %v", err)
		}

		oauthCreds := user.NewUserCredentials(testUser.ID, auth.ProviderTypeOAuth, []byte("oauth_data"))
		err = authRepo.CreateCredentials(ctx, oauthCreds)
		if err != nil {
			t.Fatalf("Failed to create oauth credentials: %v", err)
		}

		// Get active providers
		providers, err := authRepo.GetActiveProviders(ctx, testUser.ID)
		if err != nil {
			t.Fatalf("Failed to get active providers: %v", err)
		}
		if len(providers) != 2 {
			t.Errorf("Expected 2 providers, got %d", len(providers))
		}

		// Check both providers are present
		foundPassword := false
		foundOAuth := false
		for _, provider := range providers {
			if provider == auth.ProviderTypePassword {
				foundPassword = true
			}
			if provider == auth.ProviderTypeOAuth {
				foundOAuth = true
			}
		}
		if !foundPassword {
			t.Error("Expected to find password provider")
		}
		if !foundOAuth {
			t.Error("Expected to find oauth provider")
		}
	})

	t.Run("Delete Credentials", func(t *testing.T) {
		cleanupTestData(t, ctx)

		testUser := createTestUser()
		err := userRepo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		creds := createTestCredentials(testUser.ID)
		err = authRepo.CreateCredentials(ctx, creds)
		if err != nil {
			t.Fatalf("Failed to create credentials: %v", err)
		}

		// Delete credentials
		err = authRepo.DeleteCredentials(ctx, testUser.ID, auth.ProviderTypePassword)
		if err != nil {
			t.Fatalf("Failed to delete credentials: %v", err)
		}

		// Verify deletion
		_, err = authRepo.GetCredentials(ctx, testUser.ID, auth.ProviderTypePassword)
		if !errors.IsErrorType(err, errors.ErrUserNotFound) {
			t.Errorf("Expected user not found error after credential deletion, got: %v", err)
		}
	})
}

// Security Repository Integration Tests
func TestSecurityRepository_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()
	userRepo := NewUserRepository(testPool)
	securityRepo := NewSecurityRepository(testPool)

	t.Run("Create and Get Security", func(t *testing.T) {
		cleanupTestData(t, ctx)

		// Create user first
		testUser := createTestUser()
		err := userRepo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		// Create security
		security := createTestSecurity(testUser.ID)
		err = securityRepo.CreateSecurity(ctx, security)
		if err != nil {
			t.Fatalf("Failed to create security: %v", err)
		}

		// Get security
		retrieved, err := securityRepo.GetSecurity(ctx, testUser.ID)
		if err != nil {
			t.Fatalf("Failed to get security: %v", err)
		}
		if retrieved.UserID != testUser.ID {
			t.Errorf("Expected UserID %s, got %s", testUser.ID, retrieved.UserID)
		}
		if retrieved.LoginAttempts != 0 {
			t.Errorf("Expected LoginAttempts 0, got %d", retrieved.LoginAttempts)
		}
		if retrieved.RiskScore != 0.0 {
			t.Errorf("Expected RiskScore 0.0, got %f", retrieved.RiskScore)
		}
	})

	t.Run("Update Security", func(t *testing.T) {
		cleanupTestData(t, ctx)

		testUser := createTestUser()
		err := userRepo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		security := createTestSecurity(testUser.ID)
		err = securityRepo.CreateSecurity(ctx, security)
		if err != nil {
			t.Fatalf("Failed to create security: %v", err)
		}