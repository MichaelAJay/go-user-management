package user

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/MichaelAJay/go-user-management/auth"
	"github.com/MichaelAJay/go-user-management/errors"
)

// Test user state transitions comprehensively
func TestUser_StateTransitions(t *testing.T) {
	tests := []struct {
		name           string
		initialStatus  UserStatus
		action         func(*User)
		expectedStatus UserStatus
		shouldPanic    bool
	}{
		{
			name:           "activate pending user",
			initialStatus:  UserStatusPendingVerification,
			action:         (*User).Activate,
			expectedStatus: UserStatusActive,
		},
		{
			name:           "activate already active user",
			initialStatus:  UserStatusActive,
			action:         (*User).Activate,
			expectedStatus: UserStatusActive,
		},
		{
			name:           "suspend active user",
			initialStatus:  UserStatusActive,
			action:         (*User).Suspend,
			expectedStatus: UserStatusSuspended,
		},
		{
			name:           "deactivate active user",
			initialStatus:  UserStatusActive,
			action:         (*User).Deactivate,
			expectedStatus: UserStatusDeactivated,
		},
		{
			name:           "deactivate suspended user",
			initialStatus:  UserStatusSuspended,
			action:         (*User).Deactivate,
			expectedStatus: UserStatusDeactivated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := createTestUser()
			user.Status = tt.initialStatus
			initialVersion := user.Version
			initialUpdatedAt := user.UpdatedAt

			// Wait to ensure timestamp changes
			time.Sleep(time.Millisecond)

			if tt.shouldPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Error("Expected panic but got none")
					}
				}()
			}

			tt.action(user)

			if user.Status != tt.expectedStatus {
				t.Errorf("Expected status %v, got %v", tt.expectedStatus, user.Status)
			}

			// Verify version increment and timestamp update
			if user.Version != initialVersion+1 {
				t.Errorf("Expected version %d, got %d", initialVersion+1, user.Version)
			}
			if !user.UpdatedAt.After(initialUpdatedAt) {
				t.Error("Expected UpdatedAt to be updated")
			}
		})
	}
}

// Test account locking logic with edge cases
func TestUser_AccountLocking(t *testing.T) {
	tests := []struct {
		name            string
		initialStatus   UserStatus
		lockUntil       *time.Time
		expectedStatus  UserStatus
		expectedLocked  bool
		expectedCanAuth bool
	}{
		{
			name:            "permanent lock",
			initialStatus:   UserStatusActive,
			lockUntil:       nil,
			expectedStatus:  UserStatusLocked,
			expectedLocked:  true,
			expectedCanAuth: false,
		},
		{
			name:            "temporary lock - future",
			initialStatus:   UserStatusActive,
			lockUntil:       timePtr(time.Now().Add(time.Hour)),
			expectedStatus:  UserStatusActive,
			expectedLocked:  true,
			expectedCanAuth: false,
		},
		{
			name:            "temporary lock - past (expired)",
			initialStatus:   UserStatusActive,
			lockUntil:       timePtr(time.Now().Add(-time.Hour)),
			expectedStatus:  UserStatusActive,
			expectedLocked:  false,
			expectedCanAuth: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := createTestUser()
			user.Status = tt.initialStatus

			user.LockAccount(tt.lockUntil)

			if user.Status != tt.expectedStatus {
				t.Errorf("Expected status %v, got %v", tt.expectedStatus, user.Status)
			}
			if user.IsLocked() != tt.expectedLocked {
				t.Errorf("Expected IsLocked() %v, got %v", tt.expectedLocked, user.IsLocked())
			}
			if user.CanAuthenticate() != tt.expectedCanAuth {
				t.Errorf("Expected CanAuthenticate() %v, got %v", tt.expectedCanAuth, user.CanAuthenticate())
			}
		})
	}
}

// Test unlock account logic
func TestUser_UnlockAccount(t *testing.T) {
	tests := []struct {
		name                 string
		initialStatus        UserStatus
		initialLockedUntil   *time.Time
		initialLoginAttempts int
		expectedStatus       UserStatus
		expectedLocked       bool
	}{
		{
			name:                 "unlock permanently locked",
			initialStatus:        UserStatusLocked,
			initialLockedUntil:   nil,
			initialLoginAttempts: 5,
			expectedStatus:       UserStatusActive,
			expectedLocked:       false,
		},
		{
			name:                 "unlock temporarily locked",
			initialStatus:        UserStatusActive,
			initialLockedUntil:   timePtr(time.Now().Add(time.Hour)),
			initialLoginAttempts: 3,
			expectedStatus:       UserStatusActive,
			expectedLocked:       false,
		},
		{
			name:                 "unlock already unlocked",
			initialStatus:        UserStatusActive,
			initialLockedUntil:   nil,
			initialLoginAttempts: 0,
			expectedStatus:       UserStatusActive,
			expectedLocked:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := createTestUser()
			user.Status = tt.initialStatus
			user.LockedUntil = tt.initialLockedUntil
			user.LoginAttempts = tt.initialLoginAttempts

			user.UnlockAccount()

			if user.Status != tt.expectedStatus {
				t.Errorf("Expected status %v, got %v", tt.expectedStatus, user.Status)
			}
			if user.IsLocked() != tt.expectedLocked {
				t.Errorf("Expected IsLocked() %v, got %v", tt.expectedLocked, user.IsLocked())
			}
			if user.LoginAttempts != 0 {
				t.Errorf("Expected LoginAttempts to be reset to 0, got %d", user.LoginAttempts)
			}
			if user.LockedUntil != nil {
				t.Error("Expected LockedUntil to be nil after unlock")
			}
		})
	}
}

// Test login attempts with edge cases
func TestUser_LoginAttempts(t *testing.T) {
	user := createTestUser()

	// Test multiple increments
	for i := 1; i <= 5; i++ {
		initialVersion := user.Version
		user.IncrementLoginAttempts()

		if user.LoginAttempts != i {
			t.Errorf("Expected LoginAttempts %d, got %d", i, user.LoginAttempts)
		}
		if user.Version != initialVersion+1 {
			t.Errorf("Expected version increment, got %d", user.Version)
		}
	}

	// Test reset
	initialVersion := user.Version
	user.ResetLoginAttempts()

	if user.LoginAttempts != 0 {
		t.Errorf("Expected LoginAttempts 0 after reset, got %d", user.LoginAttempts)
	}
	if user.Version != initialVersion+1 {
		t.Error("Expected version increment after reset")
	}
}

// Test authentication data management
func TestUser_AuthenticationDataManagement(t *testing.T) {
	user := createTestUser()

	// Initially should have password provider
	if !user.HasAuthenticationProvider(auth.ProviderTypePassword) {
		t.Error("Expected user to have password provider initially")
	}

	// Test adding new provider
	oauthData := map[string]interface{}{"token": "oauth_token", "expires": time.Now()}
	user.AddAuthenticationProvider(auth.ProviderTypeOAuth, oauthData)

	if !user.HasAuthenticationProvider(auth.ProviderTypeOAuth) {
		t.Error("Expected user to have OAuth provider after adding")
	}

	retrievedData, exists := user.GetAuthenticationData(auth.ProviderTypeOAuth)
	if !exists {
		t.Error("Expected OAuth data to exist")
	}

	retrievedMap, ok := retrievedData.(map[string]interface{})
	if !ok {
		t.Error("Expected OAuth data to be a map")
	} else if retrievedMap["token"] != "oauth_token" {
		t.Error("Expected OAuth token to match")
	}

	// Test updating existing provider
	newPasswordData := map[string]interface{}{"password": "new_hashed_password"}
	user.UpdateAuthenticationData(auth.ProviderTypePassword, newPasswordData)

	updatedData, exists := user.GetAuthenticationData(auth.ProviderTypePassword)
	if !exists {
		t.Error("Expected password data to still exist after update")
	}

	updatedMap, ok := updatedData.(map[string]interface{})
	if !ok {
		t.Error("Expected password data to be a map")
	} else if updatedMap["password"] != "new_hashed_password" {
		t.Error("Expected password to be updated")
	}

	// Test removing provider
	user.RemoveAuthenticationProvider(auth.ProviderTypeOAuth)
	if user.HasAuthenticationProvider(auth.ProviderTypeOAuth) {
		t.Error("Expected OAuth provider to be removed")
	}
}

// Test user validation with comprehensive scenarios
func TestUser_Validation_Comprehensive(t *testing.T) {
	tests := []struct {
		name      string
		setupUser func() *User
		wantErr   bool
		errType   error
	}{
		{
			name: "valid user",
			setupUser: func() *User {
				return createTestUser()
			},
			wantErr: false,
		},
		{
			name: "empty ID",
			setupUser: func() *User {
				user := createTestUser()
				user.ID = ""
				return user
			},
			wantErr: true,
			errType: errors.ErrInvalidUserID,
		},
		{
			name: "invalid UUID format",
			setupUser: func() *User {
				user := createTestUser()
				user.ID = "not-a-uuid"
				return user
			},
			wantErr: true,
			errType: errors.ErrInvalidUserID,
		},
		{
			name: "empty hashed email",
			setupUser: func() *User {
				user := createTestUser()
				user.HashedEmail = ""
				return user
			},
			wantErr: true,
			errType: errors.ErrInvalidEmail,
		},
		{
			name: "nil authentication data",
			setupUser: func() *User {
				user := createTestUser()
				user.AuthenticationData = nil
				return user
			},
			wantErr: true,
			errType: errors.ErrInvalidPassword,
		},
		{
			name: "empty authentication data",
			setupUser: func() *User {
				user := createTestUser()
				user.AuthenticationData = make(map[auth.ProviderType]any)
				return user
			},
			wantErr: true,
			errType: errors.ErrInvalidPassword,
		},
		{
			name: "missing primary auth provider",
			setupUser: func() *User {
				user := createTestUser()
				user.PrimaryAuthProvider = auth.ProviderTypeOAuth
				// AuthenticationData still only has password
				return user
			},
			wantErr: true,
			errType: errors.ErrInvalidPassword,
		},
		{
			name: "invalid status",
			setupUser: func() *User {
				user := createTestUser()
				user.Status = UserStatus(999)
				return user
			},
			wantErr: true,
			errType: errors.ErrInvalidUserStatus,
		},
		{
			name: "zero version",
			setupUser: func() *User {
				user := createTestUser()
				user.Version = 0
				return user
			},
			wantErr: true,
			errType: errors.ErrInvalidVersion,
		},
		{
			name: "negative version",
			setupUser: func() *User {
				user := createTestUser()
				user.Version = -1
				return user
			},
			wantErr: true,
			errType: errors.ErrInvalidVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := tt.setupUser()
			err := user.Validate()

			if tt.wantErr {
				if err == nil {
					t.Error("Expected validation error but got none")
					return
				}
				if tt.errType != nil && err != tt.errType {
					t.Errorf("Expected error %v, got %v", tt.errType, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no validation error, got %v", err)
				}
			}
		})
	}
}

// Test deep copy integrity during concurrent modification
func TestUser_Clone_ConcurrentSafety(t *testing.T) {
	user := createTestUser()
	user.FirstName = []byte("OriginalFirstName")
	user.LastName = []byte("OriginalLastName")
	user.Email = []byte("original@example.com")
	user.LastLoginAt = timePtr(time.Now())
	user.LockedUntil = timePtr(time.Now().Add(time.Hour))

	clone := user.Clone()

	// Verify deep copy
	if &user.FirstName[0] == &clone.FirstName[0] {
		t.Error("FirstName not deep copied")
	}
	if &user.LastName[0] == &clone.LastName[0] {
		t.Error("LastName not deep copied")
	}
	if &user.Email[0] == &clone.Email[0] {
		t.Error("Email not deep copied")
	}
	if user.LastLoginAt == clone.LastLoginAt {
		t.Error("LastLoginAt not deep copied")
	}
	if user.LockedUntil == clone.LockedUntil {
		t.Error("LockedUntil not deep copied")
	}

	// Test concurrent modification safety
	const numGoroutines = 10
	var wg sync.WaitGroup

	// Modify original concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			user.FirstName = []byte(fmt.Sprintf("Modified%d", id))
			user.IncrementLoginAttempts()
		}(i)
	}

	// Modify clone concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			clone.LastName = []byte(fmt.Sprintf("CloneModified%d", id))
			clone.Activate()
		}(i)
	}

	wg.Wait()

	// Verify independence - clone should not have original's changes
	if string(clone.FirstName) == string(user.FirstName) {
		t.Error("Clone was affected by original modifications")
	}
	if clone.LoginAttempts == user.LoginAttempts {
		t.Error("Clone login attempts affected by original")
	}
}

// Test version consistency across operations
func TestUser_VersionConsistency(t *testing.T) {
	user := createTestUser()
	initialVersion := user.Version

	operations := []struct {
		name string
		op   func()
	}{
		{"IncrementLoginAttempts", func() { user.IncrementLoginAttempts() }},
		{"ResetLoginAttempts", func() { user.ResetLoginAttempts() }},
		{"UpdateLastLogin", func() { user.UpdateLastLogin() }},
		{"Activate", func() { user.Activate() }},
		{"Suspend", func() { user.Suspend() }},
		{"UpdateProfile", func() { user.UpdateProfile() }},
		{"LockAccount", func() { user.LockAccount(nil) }},
	}

	expectedVersion := initialVersion
	for _, op := range operations {
		t.Run(op.name, func(t *testing.T) {
			prevVersion := user.Version
			prevUpdatedAt := user.UpdatedAt

			// Small delay to ensure timestamp changes
			time.Sleep(time.Millisecond)

			op.op()
			expectedVersion++

			if user.Version != expectedVersion {
				t.Errorf("Expected version %d after %s, got %d", expectedVersion, op.name, user.Version)
			}
			if user.Version != prevVersion+1 {
				t.Errorf("Expected version increment of 1 for %s, got %d->%d", op.name, prevVersion, user.Version)
			}
			if !user.UpdatedAt.After(prevUpdatedAt) {
				t.Errorf("Expected UpdatedAt to be updated for %s", op.name)
			}
		})
	}
}

// Test timestamp consistency
func TestUser_TimestampConsistency(t *testing.T) {
	user := createTestUser()

	// Test that CreatedAt and UpdatedAt are initially the same
	if !user.CreatedAt.Equal(user.UpdatedAt) {
		t.Error("Expected CreatedAt and UpdatedAt to be equal initially")
	}

	// Test that operations update UpdatedAt but not CreatedAt
	originalCreatedAt := user.CreatedAt
	time.Sleep(time.Millisecond)

	user.UpdateProfile()

	if !user.CreatedAt.Equal(originalCreatedAt) {
		t.Error("Expected CreatedAt to remain unchanged")
	}
	if !user.UpdatedAt.After(originalCreatedAt) {
		t.Error("Expected UpdatedAt to be updated")
	}
}

// Test authentication provider edge cases
func TestUser_AuthenticationProvider_EdgeCases(t *testing.T) {
	user := createTestUser()

	// Test removing non-existent provider
	user.RemoveAuthenticationProvider(auth.ProviderTypeOAuth)
	// Should not panic or cause issues

	// Test getting non-existent provider
	data, exists := user.GetAuthenticationData(auth.ProviderTypeOAuth)
	if exists {
		t.Error("Expected non-existent provider to return false")
	}
	if data != nil {
		t.Error("Expected nil data for non-existent provider")
	}

	// Test adding provider with nil data
	user.AddAuthenticationProvider(auth.ProviderTypeOAuth, nil)
	data, exists = user.GetAuthenticationData(auth.ProviderTypeOAuth)
	if !exists {
		t.Error("Expected provider to exist even with nil data")
	}
	if data != nil {
		t.Error("Expected nil data to be preserved")
	}

	// Test updating with different data types
	user.UpdateAuthenticationData(auth.ProviderTypeOAuth, "string_data")
	data, exists = user.GetAuthenticationData(auth.ProviderTypeOAuth)
	if !exists {
		t.Error("Expected provider to exist after update")
	}
	if str, ok := data.(string); !ok || str != "string_data" {
		t.Error("Expected string data to be preserved")
	}
}

// Test UserStatus enum behavior
func TestUserStatus_Comprehensive(t *testing.T) {
	tests := []struct {
		status  UserStatus
		str     string
		isValid bool
		canAuth bool
	}{
		{UserStatusActive, "active", true, true},
		{UserStatusSuspended, "suspended", true, false},
		{UserStatusPendingVerification, "pending_verification", true, false},
		{UserStatusLocked, "locked", true, false},
		{UserStatusDeactivated, "deactivated", true, false},
		{UserStatus(-1), "unknown", false, false},
		{UserStatus(999), "unknown", false, false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("status_%d", int(tt.status)), func(t *testing.T) {
			if tt.status.String() != tt.str {
				t.Errorf("Expected String() %s, got %s", tt.str, tt.status.String())
			}
			if tt.status.IsValid() != tt.isValid {
				t.Errorf("Expected IsValid() %v, got %v", tt.isValid, tt.status.IsValid())
			}
			if tt.status.CanAuthenticate() != tt.canAuth {
				t.Errorf("Expected CanAuthenticate() %v, got %v", tt.canAuth, tt.status.CanAuthenticate())
			}
		})
	}
}
