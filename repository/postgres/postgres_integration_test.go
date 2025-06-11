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
		fmt.Println("Skipping integration tests - TEST_DATABASE_URL not set")
		fmt.Println("To run integration tests, set TEST_DATABASE_URL environment variable")
		fmt.Println("Example: TEST_DATABASE_URL=postgres://user:pass@localhost/testdb?sslmode=disable")
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
func createUserParams() *user.CreateUserParams {
	return &user.CreateUserParams{
		FirstName:           []byte("John"),
		LastName:            []byte("Doe"),
		Email:               []byte("john.doe@example.com"),
		HashedEmail:         "hashed_email_123",
		PrimaryAuthProvider: auth.ProviderTypePassword,
	}
}

func createTestCredentials(userID string) *user.UserCredentials {
	return user.NewUserCredentials(userID, auth.ProviderTypePassword, []byte("encrypted_auth_data"))
}

func createTestSecurity(userID string) *user.UserSecurity {
	return user.NewUserSecurity(userID)
}

func cleanupTestData(t *testing.T, ctx context.Context) {
	// Clean up in reverse dependency order
	queries := []string{
		"DELETE FROM user_security",
		"DELETE FROM user_credentials",
		"DELETE FROM users",
	}

	for _, query := range queries {
		if _, err := testPool.Exec(ctx, query); err != nil {
			t.Logf("Warning: failed to cleanup with query '%s': %v", query, err)
		}
	}
}

// User Repository Integration Tests
func TestUserRepository_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()
	repo := NewUserRepository(testPool)

	t.Run("Create and Get User", func(t *testing.T) {
		cleanupTestData(t, ctx)

		testUser := createUserParams()

		// Create user
		createdUser, err := repo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		// Get by ID
		retrieved, err := repo.GetByID(ctx, createdUser.ID)
		if err != nil {
			t.Fatalf("Failed to get user by ID: %v", err)
		}

		// Verify basic fields
		if retrieved.ID != createdUser.ID {
			t.Errorf("Expected ID %s, got %s", createdUser.ID, retrieved.ID)
		}
		if retrieved.HashedEmail != createdUser.HashedEmail {
			t.Errorf("Expected HashedEmail %s, got %s", createdUser.HashedEmail, retrieved.HashedEmail)
		}
		if retrieved.PrimaryAuthProvider != createdUser.PrimaryAuthProvider {
			t.Errorf("Expected PrimaryAuthProvider %s, got %s", createdUser.PrimaryAuthProvider, retrieved.PrimaryAuthProvider)
		}
		if retrieved.Status != createdUser.Status {
			t.Errorf("Expected Status %v, got %v", createdUser.Status, retrieved.Status)
		}

		// Get by hashed email
		retrievedByEmail, err := repo.GetByHashedEmail(ctx, createdUser.HashedEmail)
		if err != nil {
			t.Fatalf("Failed to get user by hashed email: %v", err)
		}
		if retrievedByEmail.ID != createdUser.ID {
			t.Errorf("Expected ID %s, got %s", createdUser.ID, retrievedByEmail.ID)
		}
	})

	t.Run("Update User", func(t *testing.T) {
		cleanupTestData(t, ctx)

		testUser := createUserParams()
		createUser, err := repo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		// Update user status
		createUser.Status = user.UserStatusActive
		createUser.Version++
		createUser.UpdatedAt = time.Now()

		err = repo.Update(ctx, createUser)
		if err != nil {
			t.Fatalf("Failed to update user: %v", err)
		}

		// Verify update
		retrieved, err := repo.GetByID(ctx, createUser.ID)
		if err != nil {
			t.Fatalf("Failed to retrieve updated user: %v", err)
		}
		if retrieved.Status != user.UserStatusActive {
			t.Errorf("Expected status %v, got %v", user.UserStatusActive, retrieved.Status)
		}
		if retrieved.Version != createUser.Version {
			t.Errorf("Expected version %d, got %d", createUser.Version, retrieved.Version)
		}
	})

	t.Run("Delete User", func(t *testing.T) {
		cleanupTestData(t, ctx)

		testUser := createUserParams()
		createUser, err := repo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		// Delete user
		err = repo.Delete(ctx, createUser.ID)
		if err != nil {
			t.Fatalf("Failed to delete user: %v", err)
		}

		// Verify deletion
		_, err = repo.GetByID(ctx, createUser.ID)
		if !errors.IsErrorType(err, errors.ErrUserNotFound) {
			t.Errorf("Expected user not found error after deletion, got: %v", err)
		}
	})

	t.Run("Duplicate Email Error", func(t *testing.T) {
		cleanupTestData(t, ctx)

		testUser1 := createUserParams()
		_, err := repo.Create(ctx, testUser1)
		if err != nil {
			t.Fatalf("Failed to create first user: %v", err)
		}

		// Try to create another user with same hashed email
		testUser2 := createUserParams()
		_, err = repo.Create(ctx, testUser2)
		if !errors.IsErrorType(err, errors.ErrDuplicateEmail) {
			t.Errorf("Expected duplicate email error, got: %v", err)
		}
	})

	t.Run("Version Mismatch Error", func(t *testing.T) {
		cleanupTestData(t, ctx)

		testUser := createUserParams()
		createUser, err := repo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		// Try to update with wrong version
		createUser.Status = user.UserStatusActive
		createUser.Version = 999 // Wrong version
		createUser.UpdatedAt = time.Now()

		err = repo.Update(ctx, createUser)
		if !errors.IsErrorType(err, errors.ErrVersionMismatch) {
			t.Errorf("Expected version mismatch error, got: %v", err)
		}
	})

	t.Run("List Users", func(t *testing.T) {
		cleanupTestData(t, ctx)

		// Create multiple users
		for i := 0; i < 5; i++ {
			testUser := createUserParams()
			testUser.HashedEmail = fmt.Sprintf("hashed_email_%d", i)
			_, err := repo.Create(ctx, testUser)
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

		for i, _ := range statuses {
			testUser := createUserParams()
			testUser.HashedEmail = fmt.Sprintf("stats_email_%d", i)
			_, err := repo.Create(ctx, testUser)
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
		testUser := createUserParams()
		createdUser, err := userRepo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		// Create credentials
		creds := createTestCredentials(createdUser.ID)
		err = authRepo.CreateCredentials(ctx, creds)
		if err != nil {
			t.Fatalf("Failed to create credentials: %v", err)
		}

		// Get credentials
		retrieved, err := authRepo.GetCredentials(ctx, createdUser.ID, auth.ProviderTypePassword)
		if err != nil {
			t.Fatalf("Failed to get credentials: %v", err)
		}
		if retrieved.UserID != createdUser.ID {
			t.Errorf("Expected UserID %s, got %s", createdUser.ID, retrieved.UserID)
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

		testUser := createUserParams()
		createdUser, err := userRepo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		creds := createTestCredentials(createdUser.ID)
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
		retrieved, err := authRepo.GetCredentials(ctx, createdUser.ID, auth.ProviderTypePassword)
		if err != nil {
			t.Fatalf("Failed to get updated credentials: %v", err)
		}
		if string(retrieved.EncryptedAuthData) != "new_encrypted_data" {
			t.Errorf("Expected EncryptedAuthData 'new_encrypted_data', got %s", string(retrieved.EncryptedAuthData))
		}
	})

	t.Run("Get Active Providers", func(t *testing.T) {
		cleanupTestData(t, ctx)

		testUser := createUserParams()
		createdUser, err := userRepo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		// Create multiple credentials
		passwordCreds := createTestCredentials(createdUser.ID)
		err = authRepo.CreateCredentials(ctx, passwordCreds)
		if err != nil {
			t.Fatalf("Failed to create password credentials: %v", err)
		}

		oauthCreds := user.NewUserCredentials(createdUser.ID, auth.ProviderTypeOAuth, []byte("oauth_data"))
		err = authRepo.CreateCredentials(ctx, oauthCreds)
		if err != nil {
			t.Fatalf("Failed to create oauth credentials: %v", err)
		}

		// Get active providers
		providers, err := authRepo.GetActiveProviders(ctx, createdUser.ID)
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

		testUser := createUserParams()
		createdUser, err := userRepo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		creds := createTestCredentials(createdUser.ID)
		err = authRepo.CreateCredentials(ctx, creds)
		if err != nil {
			t.Fatalf("Failed to create credentials: %v", err)
		}

		// Delete credentials
		err = authRepo.DeleteCredentials(ctx, createdUser.ID, auth.ProviderTypePassword)
		if err != nil {
			t.Fatalf("Failed to delete credentials: %v", err)
		}

		// Verify deletion
		_, err = authRepo.GetCredentials(ctx, createdUser.ID, auth.ProviderTypePassword)
		if !errors.IsErrorType(err, errors.ErrUserNotFound) {
			t.Errorf("Expected user not found error after credential deletion, got: %v", err)
		}
	})

	t.Run("Expire and Revoke Credentials", func(t *testing.T) {
		cleanupTestData(t, ctx)

		testUser := createUserParams()
		createdUser, err := userRepo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		// Create credentials for expiration test
		passwordCreds := createTestCredentials(createdUser.ID)
		err = authRepo.CreateCredentials(ctx, passwordCreds)
		if err != nil {
			t.Fatalf("Failed to create password credentials: %v", err)
		}

		// Create credentials for revocation test
		oauthCreds := user.NewUserCredentials(createdUser.ID, auth.ProviderTypeOAuth, []byte("oauth_data"))
		err = authRepo.CreateCredentials(ctx, oauthCreds)
		if err != nil {
			t.Fatalf("Failed to create oauth credentials: %v", err)
		}

		// Expire password credentials
		err = authRepo.ExpireCredentials(ctx, createdUser.ID, auth.ProviderTypePassword)
		if err != nil {
			t.Fatalf("Failed to expire credentials: %v", err)
		}

		// Revoke oauth credentials
		err = authRepo.RevokeCredentials(ctx, createdUser.ID, auth.ProviderTypeOAuth)
		if err != nil {
			t.Fatalf("Failed to revoke credentials: %v", err)
		}

		// Verify expired credentials
		expiredCreds, err := authRepo.GetCredentials(ctx, createdUser.ID, auth.ProviderTypePassword)
		if err != nil {
			t.Fatalf("Failed to get expired credentials: %v", err)
		}
		if expiredCreds.Status != user.CredentialStatusExpired {
			t.Errorf("Expected status %v, got %v", user.CredentialStatusExpired, expiredCreds.Status)
		}

		// Verify revoked credentials
		revokedCreds, err := authRepo.GetCredentials(ctx, createdUser.ID, auth.ProviderTypeOAuth)
		if err != nil {
			t.Fatalf("Failed to get revoked credentials: %v", err)
		}
		if revokedCreds.Status != user.CredentialStatusRevoked {
			t.Errorf("Expected status %v, got %v", user.CredentialStatusRevoked, revokedCreds.Status)
		}

		// Verify active providers only returns active credentials
		activeProviders, err := authRepo.GetActiveProviders(ctx, createdUser.ID)
		if err != nil {
			t.Fatalf("Failed to get active providers: %v", err)
		}
		if len(activeProviders) != 0 {
			t.Errorf("Expected 0 active providers, got %d", len(activeProviders))
		}
	})

	t.Run("Credentials Batch Operations", func(t *testing.T) {
		cleanupTestData(t, ctx)

		// Create multiple users
		var userIDs []string
		for i := 0; i < 3; i++ {
			testUser := createUserParams()
			testUser.HashedEmail = fmt.Sprintf("batch_email_%d", i)
			createdUser, err := userRepo.Create(ctx, testUser)
			if err != nil {
				t.Fatalf("Failed to create user %d: %v", i, err)
			}
			userIDs = append(userIDs, createdUser.ID)

			// Create credentials for each user
			creds := createTestCredentials(createdUser.ID)
			err = authRepo.CreateCredentials(ctx, creds)
			if err != nil {
				t.Fatalf("Failed to create credentials for user %d: %v", i, err)
			}
		}

		// Test batch get
		batchCreds, err := authRepo.GetCredentialsBatch(ctx, userIDs, auth.ProviderTypePassword)
		if err != nil {
			t.Fatalf("Failed to get credentials batch: %v", err)
		}
		if len(batchCreds) != 3 {
			t.Errorf("Expected 3 credentials in batch, got %d", len(batchCreds))
		}

		for _, userID := range userIDs {
			if _, exists := batchCreds[userID]; !exists {
				t.Errorf("Expected credentials for user %s in batch", userID)
			}
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
		testUser := createUserParams()
		createdUser, err := userRepo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		// Create security
		security := createTestSecurity(createdUser.ID)
		err = securityRepo.CreateSecurity(ctx, security)
		if err != nil {
			t.Fatalf("Failed to create security: %v", err)
		}

		// Get security
		retrieved, err := securityRepo.GetSecurity(ctx, createdUser.ID)
		if err != nil {
			t.Fatalf("Failed to get security: %v", err)
		}
		if retrieved.UserID != createdUser.ID {
			t.Errorf("Expected UserID %s, got %s", createdUser.ID, retrieved.UserID)
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

		testUser := createUserParams()
		createdUser, err := userRepo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		security := createTestSecurity(createdUser.ID)
		err = securityRepo.CreateSecurity(ctx, security)
		if err != nil {
			t.Fatalf("Failed to create security: %v", err)
		}

		// Update security
		security.LoginAttempts = 3
		security.RiskScore = 75.5
		security.Version++
		security.UpdatedAt = time.Now()

		err = securityRepo.UpdateSecurity(ctx, security)
		if err != nil {
			t.Fatalf("Failed to update security: %v", err)
		}

		// Verify update
		retrieved, err := securityRepo.GetSecurity(ctx, createdUser.ID)
		if err != nil {
			t.Fatalf("Failed to get updated security: %v", err)
		}
		if retrieved.LoginAttempts != 3 {
			t.Errorf("Expected LoginAttempts 3, got %d", retrieved.LoginAttempts)
		}
		if retrieved.RiskScore != 75.5 {
			t.Errorf("Expected RiskScore 75.5, got %f", retrieved.RiskScore)
		}
	})

	t.Run("Lock and Unlock Account", func(t *testing.T) {
		cleanupTestData(t, ctx)

		testUser := createUserParams()
		createdUser, err := userRepo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		security := createTestSecurity(createdUser.ID)
		err = securityRepo.CreateSecurity(ctx, security)
		if err != nil {
			t.Fatalf("Failed to create security: %v", err)
		}

		// Lock account
		lockUntil := time.Now().Add(time.Hour)
		err = securityRepo.LockAccount(ctx, createdUser.ID, &lockUntil, "too_many_attempts")
		if err != nil {
			t.Fatalf("Failed to lock account: %v", err)
		}

		// Verify lock
		retrieved, err := securityRepo.GetSecurity(ctx, createdUser.ID)
		if err != nil {
			t.Fatalf("Failed to get locked security: %v", err)
		}
		if retrieved.LockedUntil == nil {
			t.Error("Expected LockedUntil to be set")
		}
		if retrieved.LockReason != "too_many_attempts" {
			t.Errorf("Expected LockReason 'too_many_attempts', got %s", retrieved.LockReason)
		}

		// Unlock account
		err = securityRepo.UnlockAccount(ctx, createdUser.ID)
		if err != nil {
			t.Fatalf("Failed to unlock account: %v", err)
		}

		// Verify unlock
		retrieved, err = securityRepo.GetSecurity(ctx, createdUser.ID)
		if err != nil {
			t.Fatalf("Failed to get unlocked security: %v", err)
		}
		if retrieved.LockedUntil != nil {
			t.Error("Expected LockedUntil to be cleared")
		}
		if retrieved.LockReason != "" {
			t.Errorf("Expected LockReason to be cleared, got %s", retrieved.LockReason)
		}
	})

	t.Run("Record Login Attempts", func(t *testing.T) {
		cleanupTestData(t, ctx)

		testUser := createUserParams()
		createdUser, err := userRepo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		security := createTestSecurity(createdUser.ID)
		err = securityRepo.CreateSecurity(ctx, security)
		if err != nil {
			t.Fatalf("Failed to create security: %v", err)
		}

		// Increment login attempts
		err = securityRepo.IncrementLoginAttempts(ctx, createdUser.ID)
		if err != nil {
			t.Fatalf("Failed to increment login attempts: %v", err)
		}

		// Verify increment
		retrieved, err := securityRepo.GetSecurity(ctx, createdUser.ID)
		if err != nil {
			t.Fatalf("Failed to get security after increment: %v", err)
		}
		if retrieved.LoginAttempts != 1 {
			t.Errorf("Expected LoginAttempts 1, got %d", retrieved.LoginAttempts)
		}
		if retrieved.TotalLoginAttempts != 1 {
			t.Errorf("Expected TotalLoginAttempts 1, got %d", retrieved.TotalLoginAttempts)
		}

		// Record successful login
		err = securityRepo.RecordSuccessfulLogin(ctx, createdUser.ID, "192.168.1.1")
		if err != nil {
			t.Fatalf("Failed to record successful login: %v", err)
		}

		// Verify successful login
		retrieved, err = securityRepo.GetSecurity(ctx, createdUser.ID)
		if err != nil {
			t.Fatalf("Failed to get security after successful login: %v", err)
		}
		if retrieved.LoginAttempts != 0 {
			t.Errorf("Expected LoginAttempts to be reset to 0, got %d", retrieved.LoginAttempts)
		}
		if retrieved.SuccessfulLogins != 1 {
			t.Errorf("Expected SuccessfulLogins 1, got %d", retrieved.SuccessfulLogins)
		}
		if retrieved.LastLoginIP != "192.168.1.1" {
			t.Errorf("Expected LastLoginIP '192.168.1.1', got %s", retrieved.LastLoginIP)
		}
	})

	t.Run("Risk Score Management", func(t *testing.T) {
		cleanupTestData(t, ctx)

		testUser := createUserParams()
		createdUser, err := userRepo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		security := createTestSecurity(createdUser.ID)
		err = securityRepo.CreateSecurity(ctx, security)
		if err != nil {
			t.Fatalf("Failed to create security: %v", err)
		}

		// Update risk score
		riskFactors := []user.RiskFactor{
			user.RiskFactorUnknownDevice,
			user.RiskFactorUnknownLocation,
		}
		err = securityRepo.UpdateRiskScore(ctx, createdUser.ID, 85.0, riskFactors)
		if err != nil {
			t.Fatalf("Failed to update risk score: %v", err)
		}

		// Verify risk score update
		retrieved, err := securityRepo.GetSecurity(ctx, createdUser.ID)
		if err != nil {
			t.Fatalf("Failed to get security after risk score update: %v", err)
		}
		if retrieved.RiskScore != 85.0 {
			t.Errorf("Expected RiskScore 85.0, got %f", retrieved.RiskScore)
		}
		if len(retrieved.RiskFactors) != 2 {
			t.Errorf("Expected 2 risk factors, got %d", len(retrieved.RiskFactors))
		}

		// Test high risk users query
		highRiskUsers, err := securityRepo.GetHighRiskUsers(ctx, 75.0)
		if err != nil {
			t.Fatalf("Failed to get high risk users: %v", err)
		}
		if len(highRiskUsers) != 1 {
			t.Errorf("Expected 1 high risk user, got %d", len(highRiskUsers))
		}
		if highRiskUsers[0].UserID != createdUser.ID {
			t.Errorf("Expected high risk user %s, got %s", createdUser.ID, highRiskUsers[0].UserID)
		}
	})

	t.Run("Security Events Management", func(t *testing.T) {
		cleanupTestData(t, ctx)

		testUser := createUserParams()
		createdUser, err := userRepo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		security := createTestSecurity(createdUser.ID)
		err = securityRepo.CreateSecurity(ctx, security)
		if err != nil {
			t.Fatalf("Failed to create security: %v", err)
		}

		// Add security events
		event1 := user.SecurityEvent{
			Type:      user.SecurityEventLoginFailure,
			Timestamp: time.Now().Add(-2 * time.Hour),
			IPAddress: "192.168.1.1",
			Details: map[string]interface{}{
				"attempt_count": 1,
			},
		}

		event2 := user.SecurityEvent{
			Type:      user.SecurityEventLoginSuccess,
			Timestamp: time.Now().Add(-1 * time.Hour),
			IPAddress: "192.168.1.1",
			Details: map[string]interface{}{
				"successful_login_count": 1,
			},
		}

		err = securityRepo.AddSecurityEvent(ctx, createdUser.ID, event1)
		if err != nil {
			t.Fatalf("Failed to add security event 1: %v", err)
		}

		err = securityRepo.AddSecurityEvent(ctx, createdUser.ID, event2)
		if err != nil {
			t.Fatalf("Failed to add security event 2: %v", err)
		}

		// Verify events were added
		retrieved, err := securityRepo.GetSecurity(ctx, createdUser.ID)
		if err != nil {
			t.Fatalf("Failed to get security after adding events: %v", err)
		}
		if len(retrieved.SecurityEvents) != 2 {
			t.Errorf("Expected 2 security events, got %d", len(retrieved.SecurityEvents))
		}

		// Test getting events since a specific time
		since := time.Now().Add(-90 * time.Minute)
		recentEvents, err := securityRepo.GetSecurityEvents(ctx, createdUser.ID, since)
		if err != nil {
			t.Fatalf("Failed to get recent security events: %v", err)
		}
		if len(recentEvents) != 1 {
			t.Errorf("Expected 1 recent event, got %d", len(recentEvents))
		}
		if recentEvents[0].Type != user.SecurityEventLoginSuccess {
			t.Errorf("Expected recent event type %s, got %s", user.SecurityEventLoginSuccess, recentEvents[0].Type)
		}
	})

	t.Run("Security Batch Operations", func(t *testing.T) {
		cleanupTestData(t, ctx)

		// Create multiple users with security records
		var userIDs []string
		var securities []*user.UserSecurity

		for i := 0; i < 3; i++ {
			testUser := createUserParams()
			createdUser, err := userRepo.Create(ctx, testUser)
			if err != nil {
				t.Fatalf("Failed to create user %d: %v", i, err)
			}
			userIDs = append(userIDs, createdUser.ID)

			// Create security record
			security := createTestSecurity(createdUser.ID)
			security.RiskScore = float64(i * 25) // 0, 25, 50
			err = securityRepo.CreateSecurity(ctx, security)
			if err != nil {
				t.Fatalf("Failed to create security for user %d: %v", i, err)
			}
			securities = append(securities, security)
		}

		// Test batch get
		batchSecurity, err := securityRepo.GetSecurityBatch(ctx, userIDs)
		if err != nil {
			t.Fatalf("Failed to get security batch: %v", err)
		}
		if len(batchSecurity) != 3 {
			t.Errorf("Expected 3 security records in batch, got %d", len(batchSecurity))
		}

		for i, userID := range userIDs {
			if sec, exists := batchSecurity[userID]; !exists {
				t.Errorf("Expected security for user %s in batch", userID)
			} else if sec.RiskScore != float64(i*25) {
				t.Errorf("Expected risk score %f for user %s, got %f", float64(i*25), userID, sec.RiskScore)
			}
		}

		// Test batch update
		for _, sec := range securities {
			sec.LoginAttempts = 1
			sec.Version++
			sec.UpdatedAt = time.Now()
		}

		err = securityRepo.UpdateSecurityBatch(ctx, securities)
		if err != nil {
			t.Fatalf("Failed to update security batch: %v", err)
		}

		// Verify batch update
		for _, userID := range userIDs {
			retrieved, err := securityRepo.GetSecurity(ctx, userID)
			if err != nil {
				t.Fatalf("Failed to get security after batch update for user %s: %v", userID, err)
			}
			if retrieved.LoginAttempts != 1 {
				t.Errorf("Expected LoginAttempts 1 for user %s, got %d", userID, retrieved.LoginAttempts)
			}
		}
	})

	t.Run("Get Security Stats", func(t *testing.T) {
		cleanupTestData(t, ctx)

		// Create users with different security states
		for i := 0; i < 5; i++ {
			testUser := createUserParams()
			createdUser, err := userRepo.Create(ctx, testUser)
			if err != nil {
				t.Fatalf("Failed to create user %d: %v", i, err)
			}

			security := createTestSecurity(createdUser.ID)
			// Vary the security states
			switch i {
			case 0, 1:
				// High risk users
				security.RiskScore = 80.0
			case 2:
				// Locked user
				lockUntil := time.Now().Add(time.Hour)
				security.LockedUntil = &lockUntil
				security.LockReason = "test_lock"
			case 3:
				// Recent failed attempts
				security.LoginAttempts = 3
				recent := time.Now().Add(-30 * time.Minute)
				security.LastFailedAt = &recent
			default:
				// Normal user
				security.RiskScore = 20.0
			}

			err = securityRepo.CreateSecurity(ctx, security)
			if err != nil {
				t.Fatalf("Failed to create security for user %d: %v", i, err)
			}
		}

		// Get security stats
		stats, err := securityRepo.GetSecurityStats(ctx)
		if err != nil {
			t.Fatalf("Failed to get security stats: %v", err)
		}

		if stats.TotalUsers != 5 {
			t.Errorf("Expected total users 5, got %d", stats.TotalUsers)
		}
		if stats.HighRiskUsers != 2 {
			t.Errorf("Expected high risk users 2, got %d", stats.HighRiskUsers)
		}
		if stats.LockedUsers != 1 {
			t.Errorf("Expected locked users 1, got %d", stats.LockedUsers)
		}
		if stats.RecentFailedAttempts != 3 {
			t.Errorf("Expected recent failed attempts 3, got %d", stats.RecentFailedAttempts)
		}
		// Average should be (80 + 80 + 0 + 0 + 20) / 5 = 36.0
		expectedAvg := 36.0
		if stats.AverageRiskScore != expectedAvg {
			t.Errorf("Expected average risk score %.1f, got %.1f", expectedAvg, stats.AverageRiskScore)
		}
	})

	t.Run("Cleanup Old Events", func(t *testing.T) {
		cleanupTestData(t, ctx)

		testUser := createUserParams()
		createdUser, err := userRepo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		security := createTestSecurity(createdUser.ID)
		err = securityRepo.CreateSecurity(ctx, security)
		if err != nil {
			t.Fatalf("Failed to create security: %v", err)
		}

		// Add old and new events
		oldEvent := user.SecurityEvent{
			Type:      user.SecurityEventLoginFailure,
			Timestamp: time.Now().Add(-2 * 24 * time.Hour), // 2 days ago
			IPAddress: "192.168.1.1",
		}

		newEvent := user.SecurityEvent{
			Type:      user.SecurityEventLoginSuccess,
			Timestamp: time.Now().Add(-1 * time.Hour), // 1 hour ago
			IPAddress: "192.168.1.1",
		}

		err = securityRepo.AddSecurityEvent(ctx, createdUser.ID, oldEvent)
		if err != nil {
			t.Fatalf("Failed to add old event: %v", err)
		}

		err = securityRepo.AddSecurityEvent(ctx, createdUser.ID, newEvent)
		if err != nil {
			t.Fatalf("Failed to add new event: %v", err)
		}

		// Cleanup events older than 1 day
		cleanupBefore := time.Now().Add(-24 * time.Hour)
		cleaned, err := securityRepo.CleanupOldEvents(ctx, cleanupBefore)
		if err != nil {
			t.Fatalf("Failed to cleanup old events: %v", err)
		}

		if cleaned != 1 {
			t.Errorf("Expected 1 event cleaned, got %d", cleaned)
		}

		// Verify only new event remains
		retrieved, err := securityRepo.GetSecurity(ctx, createdUser.ID)
		if err != nil {
			t.Fatalf("Failed to get security after cleanup: %v", err)
		}
		if len(retrieved.SecurityEvents) != 1 {
			t.Errorf("Expected 1 event after cleanup, got %d", len(retrieved.SecurityEvents))
		}
		if retrieved.SecurityEvents[0].Type != user.SecurityEventLoginSuccess {
			t.Errorf("Expected remaining event type %s, got %s", user.SecurityEventLoginSuccess, retrieved.SecurityEvents[0].Type)
		}
	})

	t.Run("Delete Security", func(t *testing.T) {
		cleanupTestData(t, ctx)

		testUser := createUserParams()
		createdUser, err := userRepo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		security := createTestSecurity(createdUser.ID)
		err = securityRepo.CreateSecurity(ctx, security)
		if err != nil {
			t.Fatalf("Failed to create security: %v", err)
		}

		// Delete security
		err = securityRepo.DeleteSecurity(ctx, createdUser.ID)
		if err != nil {
			t.Fatalf("Failed to delete security: %v", err)
		}

		// Verify deletion
		_, err = securityRepo.GetSecurity(ctx, createdUser.ID)
		if !errors.IsErrorType(err, errors.ErrUserNotFound) {
			t.Errorf("Expected user not found error after security deletion, got: %v", err)
		}
	})
}

// Integration test for cascading operations
func TestCascadingOperations_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()
	userRepo := NewUserRepository(testPool)
	authRepo := NewAuthRepository(testPool)
	securityRepo := NewSecurityRepository(testPool)

	t.Run("Delete User Cascades to Credentials and Security", func(t *testing.T) {
		cleanupTestData(t, ctx)

		// Create complete user with credentials and security
		testUser := createUserParams()
		createdUser, err := userRepo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		creds := createTestCredentials(createdUser.ID)
		err = authRepo.CreateCredentials(ctx, creds)
		if err != nil {
			t.Fatalf("Failed to create credentials: %v", err)
		}

		security := createTestSecurity(createdUser.ID)
		err = securityRepo.CreateSecurity(ctx, security)
		if err != nil {
			t.Fatalf("Failed to create security: %v", err)
		}

		// Delete user - should cascade to credentials and security
		err = userRepo.Delete(ctx, createdUser.ID)
		if err != nil {
			t.Fatalf("Failed to delete user: %v", err)
		}

		// Verify user is deleted
		_, err = userRepo.GetByID(ctx, createdUser.ID)
		if !errors.IsErrorType(err, errors.ErrUserNotFound) {
			t.Errorf("Expected user not found error after deletion, got: %v", err)
		}

		// Verify credentials are deleted due to cascade
		_, err = authRepo.GetCredentials(ctx, createdUser.ID, auth.ProviderTypePassword)
		if !errors.IsErrorType(err, errors.ErrUserNotFound) {
			t.Errorf("Expected credentials to be deleted by cascade, got: %v", err)
		}

		// Verify security is deleted due to cascade
		_, err = securityRepo.GetSecurity(ctx, createdUser.ID)
		if !errors.IsErrorType(err, errors.ErrUserNotFound) {
			t.Errorf("Expected security to be deleted by cascade, got: %v", err)
		}
	})
}

// Performance and stress tests
func TestPerformanceScenarios_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	ctx := context.Background()
	userRepo := NewUserRepository(testPool)
	authRepo := NewAuthRepository(testPool)
	securityRepo := NewSecurityRepository(testPool)

	t.Run("Bulk User Creation Performance", func(t *testing.T) {
		cleanupTestData(t, ctx)

		const userCount = 100
		start := time.Now()

		// Create many users
		for i := 0; i < userCount; i++ {
			testUser := createUserParams()
			createdUser, err := userRepo.Create(ctx, testUser)
			if err != nil {
				t.Fatalf("Failed to create user %d: %v", i, err)
			}

			// Create associated records
			creds := createTestCredentials(createdUser.ID)
			err = authRepo.CreateCredentials(ctx, creds)
			if err != nil {
				t.Fatalf("Failed to create credentials for user %d: %v", i, err)
			}

			security := createTestSecurity(createdUser.ID)
			err = securityRepo.CreateSecurity(ctx, security)
			if err != nil {
				t.Fatalf("Failed to create security for user %d: %v", i, err)
			}
		}

		duration := time.Since(start)
		t.Logf("Created %d complete user records in %v (%.2f users/sec)",
			userCount, duration, float64(userCount)/duration.Seconds())

		// Verify count
		stats, err := userRepo.GetUserStats(ctx)
		if err != nil {
			t.Fatalf("Failed to get user stats: %v", err)
		}
		if stats.TotalUsers != userCount {
			t.Errorf("Expected %d users, got %d", userCount, stats.TotalUsers)
		}
	})

	t.Run("Concurrent Access Safety", func(t *testing.T) {
		cleanupTestData(t, ctx)

		// Create a user for concurrent access
		testUser := createUserParams()
		createdUser, err := userRepo.Create(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		security := createTestSecurity(createdUser.ID)
		err = securityRepo.CreateSecurity(ctx, security)
		if err != nil {
			t.Fatalf("Failed to create security: %v", err)
		}

		// Test concurrent login attempt increments
		const goroutines = 10
		const increments = 10
		errors := make(chan error, goroutines)

		for i := 0; i < goroutines; i++ {
			go func() {
				for j := 0; j < increments; j++ {
					err := securityRepo.IncrementLoginAttempts(ctx, createdUser.ID)
					if err != nil {
						errors <- err
						return
					}
				}
				errors <- nil
			}()
		}

		// Wait for all goroutines
		for i := 0; i < goroutines; i++ {
			if err := <-errors; err != nil {
				t.Errorf("Concurrent increment failed: %v", err)
			}
		}

		// Verify final count
		retrieved, err := securityRepo.GetSecurity(ctx, createdUser.ID)
		if err != nil {
			t.Fatalf("Failed to get security after concurrent increments: %v", err)
		}

		expected := goroutines * increments
		if retrieved.LoginAttempts != expected {
			t.Errorf("Expected %d login attempts after concurrent increments, got %d",
				expected, retrieved.LoginAttempts)
		}
	})
}
