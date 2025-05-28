package user

import (
	"testing"
	"time"

	"github.com/MichaelAJay/go-user-management/auth"
	"github.com/google/uuid"
)

func TestUserStatus_String(t *testing.T) {
	tests := []struct {
		name     string
		status   UserStatus
		expected string
	}{
		{"Active", UserStatusActive, "active"},
		{"Suspended", UserStatusSuspended, "suspended"},
		{"PendingVerification", UserStatusPendingVerification, "pending_verification"},
		{"Locked", UserStatusLocked, "locked"},
		{"Deactivated", UserStatusDeactivated, "deactivated"},
		{"Unknown", UserStatus(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.String(); got != tt.expected {
				t.Errorf("UserStatus.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestUserStatus_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		status   UserStatus
		expected bool
	}{
		{"Active", UserStatusActive, true},
		{"Suspended", UserStatusSuspended, true},
		{"PendingVerification", UserStatusPendingVerification, true},
		{"Locked", UserStatusLocked, true},
		{"Deactivated", UserStatusDeactivated, true},
		{"Invalid", UserStatus(-1), false},
		{"Invalid", UserStatus(999), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.IsValid(); got != tt.expected {
				t.Errorf("UserStatus.IsValid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestUserStatus_CanAuthenticate(t *testing.T) {
	tests := []struct {
		name     string
		status   UserStatus
		expected bool
	}{
		{"Active", UserStatusActive, true},
		{"Suspended", UserStatusSuspended, false},
		{"PendingVerification", UserStatusPendingVerification, false},
		{"Locked", UserStatusLocked, false},
		{"Deactivated", UserStatusDeactivated, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.CanAuthenticate(); got != tt.expected {
				t.Errorf("UserStatus.CanAuthenticate() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNewUser(t *testing.T) {
	firstName := "John"
	lastName := "Doe"
	email := "john.doe@example.com"
	hashedEmail := "hashed_email"
	provider := auth.ProviderTypePassword
	authData := map[string]interface{}{"password": "hashed_password"}

	user := NewUser(firstName, lastName, email, hashedEmail, provider, authData)

	// Validate basic fields
	if user.ID == "" {
		t.Error("Expected user ID to be set")
	}
	if _, err := uuid.Parse(user.ID); err != nil {
		t.Errorf("Expected valid UUID for user ID, got %s", user.ID)
	}
	if user.HashedEmail != hashedEmail {
		t.Errorf("Expected HashedEmail %s, got %s", hashedEmail, user.HashedEmail)
	}
	if user.PrimaryAuthProvider != provider {
		t.Errorf("Expected PrimaryAuthProvider %s, got %s", provider, user.PrimaryAuthProvider)
	}
	if user.Status != UserStatusPendingVerification {
		t.Errorf("Expected Status %s, got %s", UserStatusPendingVerification, user.Status)
	}
	if user.LoginAttempts != 0 {
		t.Errorf("Expected LoginAttempts 0, got %d", user.LoginAttempts)
	}
	if user.Version != 1 {
		t.Errorf("Expected Version 1, got %d", user.Version)
	}

	// Validate authentication data
	if len(user.AuthenticationData) != 1 {
		t.Errorf("Expected 1 authentication provider, got %d", len(user.AuthenticationData))
	}
	if data, exists := user.AuthenticationData[provider]; !exists {
		t.Error("Expected authentication data to exist")
	} else {
		// Compare the map contents
		dataMap, ok := data.(map[string]interface{})
		if !ok {
			t.Error("Expected authentication data to be a map")
		} else if dataMap["password"] != authData["password"] {
			t.Error("Expected authentication data to be set correctly")
		}
	}

	// Validate timestamps
	now := time.Now()
	if user.CreatedAt.After(now) || user.CreatedAt.Before(now.Add(-time.Second)) {
		t.Error("Expected CreatedAt to be set to current time")
	}
	if user.UpdatedAt.After(now) || user.UpdatedAt.Before(now.Add(-time.Second)) {
		t.Error("Expected UpdatedAt to be set to current time")
	}
}

func TestUser_GetID(t *testing.T) {
	user := createTestUser()
	if got := user.GetID(); got != user.ID {
		t.Errorf("GetID() = %v, want %v", got, user.ID)
	}
}

func TestUser_IsActive(t *testing.T) {
	tests := []struct {
		name     string
		status   UserStatus
		expected bool
	}{
		{"Active", UserStatusActive, true},
		{"Suspended", UserStatusSuspended, false},
		{"PendingVerification", UserStatusPendingVerification, false},
		{"Locked", UserStatusLocked, false},
		{"Deactivated", UserStatusDeactivated, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := createTestUser()
			user.Status = tt.status
			if got := user.IsActive(); got != tt.expected {
				t.Errorf("IsActive() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestUser_IsLocked(t *testing.T) {
	tests := []struct {
		name        string
		status      UserStatus
		lockedUntil *time.Time
		expected    bool
	}{
		{"StatusLocked", UserStatusLocked, nil, true},
		{"TemporaryLock_Future", UserStatusActive, timePtr(time.Now().Add(time.Hour)), true},
		{"TemporaryLock_Past", UserStatusActive, timePtr(time.Now().Add(-time.Hour)), false},
		{"NotLocked", UserStatusActive, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := createTestUser()
			user.Status = tt.status
			user.LockedUntil = tt.lockedUntil
			if got := user.IsLocked(); got != tt.expected {
				t.Errorf("IsLocked() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestUser_CanAuthenticate(t *testing.T) {
	tests := []struct {
		name        string
		status      UserStatus
		lockedUntil *time.Time
		expected    bool
	}{
		{"Active_NotLocked", UserStatusActive, nil, true},
		{"Active_Locked", UserStatusActive, timePtr(time.Now().Add(time.Hour)), false},
		{"Suspended", UserStatusSuspended, nil, false},
		{"PendingVerification", UserStatusPendingVerification, nil, false},
		{"StatusLocked", UserStatusLocked, nil, false},
		{"Deactivated", UserStatusDeactivated, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := createTestUser()
			user.Status = tt.status
			user.LockedUntil = tt.lockedUntil
			if got := user.CanAuthenticate(); got != tt.expected {
				t.Errorf("CanAuthenticate() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestUser_IncrementLoginAttempts(t *testing.T) {
	user := createTestUser()
	initialAttempts := user.LoginAttempts
	initialVersion := user.Version
	initialUpdatedAt := user.UpdatedAt

	// Wait a small amount to ensure timestamp changes
	time.Sleep(time.Millisecond)

	user.IncrementLoginAttempts()

	if user.LoginAttempts != initialAttempts+1 {
		t.Errorf("Expected LoginAttempts %d, got %d", initialAttempts+1, user.LoginAttempts)
	}
	if user.Version != initialVersion+1 {
		t.Errorf("Expected Version %d, got %d", initialVersion+1, user.Version)
	}
	if !user.UpdatedAt.After(initialUpdatedAt) {
		t.Error("Expected UpdatedAt to be updated")
	}
}

func TestUser_ResetLoginAttempts(t *testing.T) {
	user := createTestUser()
	user.LoginAttempts = 5
	user.LockedUntil = timePtr(time.Now().Add(time.Hour))
	initialVersion := user.Version
	initialUpdatedAt := user.UpdatedAt

	// Wait a small amount to ensure timestamp changes
	time.Sleep(time.Millisecond)

	user.ResetLoginAttempts()

	if user.LoginAttempts != 0 {
		t.Errorf("Expected LoginAttempts 0, got %d", user.LoginAttempts)
	}
	if user.LockedUntil != nil {
		t.Error("Expected LockedUntil to be nil")
	}
	if user.Version != initialVersion+1 {
		t.Errorf("Expected Version %d, got %d", initialVersion+1, user.Version)
	}
	if !user.UpdatedAt.After(initialUpdatedAt) {
		t.Error("Expected UpdatedAt to be updated")
	}
}

func TestUser_LockAccount(t *testing.T) {
	tests := []struct {
		name           string
		until          *time.Time
		expectedStatus UserStatus
	}{
		{"PermanentLock", nil, UserStatusLocked},
		{"TemporaryLock", timePtr(time.Now().Add(time.Hour)), UserStatusActive},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := createTestUser()
			user.Status = UserStatusActive
			initialVersion := user.Version
			initialUpdatedAt := user.UpdatedAt

			// Wait a small amount to ensure timestamp changes
			time.Sleep(time.Millisecond)

			user.LockAccount(tt.until)

			if user.Status != tt.expectedStatus {
				t.Errorf("Expected Status %s, got %s", tt.expectedStatus, user.Status)
			}
			if tt.until == nil && user.LockedUntil != nil {
				t.Error("Expected LockedUntil to be nil for permanent lock")
			}
			if tt.until != nil && (user.LockedUntil == nil || !user.LockedUntil.Equal(*tt.until)) {
				t.Error("Expected LockedUntil to be set correctly for temporary lock")
			}
			if user.Version != initialVersion+1 {
				t.Errorf("Expected Version %d, got %d", initialVersion+1, user.Version)
			}
			if !user.UpdatedAt.After(initialUpdatedAt) {
				t.Error("Expected UpdatedAt to be updated")
			}
		})
	}
}

func TestUser_UnlockAccount(t *testing.T) {
	user := createTestUser()
	user.Status = UserStatusLocked
	user.LockedUntil = timePtr(time.Now().Add(time.Hour))
	user.LoginAttempts = 5

	user.UnlockAccount()

	if user.Status != UserStatusActive {
		t.Errorf("Expected Status %s, got %s", UserStatusActive, user.Status)
	}
	if user.LockedUntil != nil {
		t.Error("Expected LockedUntil to be nil")
	}
	if user.LoginAttempts != 0 {
		t.Errorf("Expected LoginAttempts 0, got %d", user.LoginAttempts)
	}
}

func TestUser_UpdateLastLogin(t *testing.T) {
	user := createTestUser()
	initialVersion := user.Version
	initialUpdatedAt := user.UpdatedAt

	// Wait a small amount to ensure timestamp changes
	time.Sleep(time.Millisecond)

	user.UpdateLastLogin()

	if user.LastLoginAt == nil {
		t.Error("Expected LastLoginAt to be set")
	}
	if user.Version != initialVersion+1 {
		t.Errorf("Expected Version %d, got %d", initialVersion+1, user.Version)
	}
	if !user.UpdatedAt.After(initialUpdatedAt) {
		t.Error("Expected UpdatedAt to be updated")
	}
}

func TestUser_Activate(t *testing.T) {
	user := createTestUser()
	user.Status = UserStatusPendingVerification
	initialVersion := user.Version
	initialUpdatedAt := user.UpdatedAt

	// Wait a small amount to ensure timestamp changes
	time.Sleep(time.Millisecond)

	user.Activate()

	if user.Status != UserStatusActive {
		t.Errorf("Expected Status %s, got %s", UserStatusActive, user.Status)
	}
	if user.Version != initialVersion+1 {
		t.Errorf("Expected Version %d, got %d", initialVersion+1, user.Version)
	}
	if !user.UpdatedAt.After(initialUpdatedAt) {
		t.Error("Expected UpdatedAt to be updated")
	}
}

func TestUser_Suspend(t *testing.T) {
	user := createTestUser()
	user.Status = UserStatusActive
	initialVersion := user.Version
	initialUpdatedAt := user.UpdatedAt

	// Wait a small amount to ensure timestamp changes
	time.Sleep(time.Millisecond)

	user.Suspend()

	if user.Status != UserStatusSuspended {
		t.Errorf("Expected Status %s, got %s", UserStatusSuspended, user.Status)
	}
	if user.Version != initialVersion+1 {
		t.Errorf("Expected Version %d, got %d", initialVersion+1, user.Version)
	}
	if !user.UpdatedAt.After(initialUpdatedAt) {
		t.Error("Expected UpdatedAt to be updated")
	}
}

func TestUser_Deactivate(t *testing.T) {
	user := createTestUser()
	user.Status = UserStatusActive
	initialVersion := user.Version
	initialUpdatedAt := user.UpdatedAt

	// Wait a small amount to ensure timestamp changes
	time.Sleep(time.Millisecond)

	user.Deactivate()

	if user.Status != UserStatusDeactivated {
		t.Errorf("Expected Status %s, got %s", UserStatusDeactivated, user.Status)
	}
	if user.Version != initialVersion+1 {
		t.Errorf("Expected Version %d, got %d", initialVersion+1, user.Version)
	}
	if !user.UpdatedAt.After(initialUpdatedAt) {
		t.Error("Expected UpdatedAt to be updated")
	}
}

func TestUser_UpdateProfile(t *testing.T) {
	user := createTestUser()
	initialVersion := user.Version
	initialUpdatedAt := user.UpdatedAt

	// Wait a small amount to ensure timestamp changes
	time.Sleep(time.Millisecond)

	user.UpdateProfile()

	if user.Version != initialVersion+1 {
		t.Errorf("Expected Version %d, got %d", initialVersion+1, user.Version)
	}
	if !user.UpdatedAt.After(initialUpdatedAt) {
		t.Error("Expected UpdatedAt to be updated")
	}
}

func TestUser_UpdateAuthenticationData(t *testing.T) {
	user := createTestUser()
	newProvider := auth.ProviderTypeOAuth
	newAuthData := map[string]interface{}{"token": "oauth_token"}
	initialVersion := user.Version
	initialUpdatedAt := user.UpdatedAt

	// Wait a small amount to ensure timestamp changes
	time.Sleep(time.Millisecond)

	user.UpdateAuthenticationData(newProvider, newAuthData)

	if len(user.AuthenticationData) != 2 {
		t.Errorf("Expected 2 authentication providers, got %d", len(user.AuthenticationData))
	}
	if data, exists := user.AuthenticationData[newProvider]; !exists {
		t.Error("Expected new authentication data to exist")
	} else {
		// Compare the map contents
		dataMap, ok := data.(map[string]interface{})
		if !ok {
			t.Error("Expected authentication data to be a map")
		} else if dataMap["token"] != newAuthData["token"] {
			t.Error("Expected new authentication data to be set correctly")
		}
	}
	if user.Version != initialVersion+1 {
		t.Errorf("Expected Version %d, got %d", initialVersion+1, user.Version)
	}
	if !user.UpdatedAt.After(initialUpdatedAt) {
		t.Error("Expected UpdatedAt to be updated")
	}
}

func TestUser_GetAuthenticationData(t *testing.T) {
	user := createTestUser()
	provider := auth.ProviderTypePassword

	data, exists := user.GetAuthenticationData(provider)
	if !exists {
		t.Error("Expected authentication data to exist")
	}

	// Verify the data is a map with the expected password field
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		t.Error("Expected authentication data to be a map")
	} else if dataMap["password"] != "hashed_password" {
		t.Error("Expected authentication data to contain correct password")
	}

	// Test non-existent provider
	_, exists = user.GetAuthenticationData(auth.ProviderTypeOAuth)
	if exists {
		t.Error("Expected authentication data to not exist for OAuth provider")
	}
}

func TestUser_HasAuthenticationProvider(t *testing.T) {
	user := createTestUser()

	if !user.HasAuthenticationProvider(auth.ProviderTypePassword) {
		t.Error("Expected user to have password provider")
	}
	if user.HasAuthenticationProvider(auth.ProviderTypeOAuth) {
		t.Error("Expected user to not have OAuth provider")
	}
}

func TestUser_AddAuthenticationProvider(t *testing.T) {
	user := createTestUser()
	newProvider := auth.ProviderTypeOAuth
	newAuthData := map[string]interface{}{"token": "oauth_token"}
	initialCount := len(user.AuthenticationData)

	user.AddAuthenticationProvider(newProvider, newAuthData)

	if len(user.AuthenticationData) != initialCount+1 {
		t.Errorf("Expected %d authentication providers, got %d", initialCount+1, len(user.AuthenticationData))
	}
	if !user.HasAuthenticationProvider(newProvider) {
		t.Error("Expected user to have new authentication provider")
	}
}

func TestUser_RemoveAuthenticationProvider(t *testing.T) {
	user := createTestUser()
	// Add a second provider first
	user.AddAuthenticationProvider(auth.ProviderTypeOAuth, map[string]interface{}{"token": "oauth_token"})
	initialCount := len(user.AuthenticationData)

	user.RemoveAuthenticationProvider(auth.ProviderTypeOAuth)

	if len(user.AuthenticationData) != initialCount-1 {
		t.Errorf("Expected %d authentication providers, got %d", initialCount-1, len(user.AuthenticationData))
	}
	if user.HasAuthenticationProvider(auth.ProviderTypeOAuth) {
		t.Error("Expected user to not have OAuth provider after removal")
	}
}

func TestUser_GetDisplayName(t *testing.T) {
	user := createTestUser()
	displayName := user.GetDisplayName()

	// Since we don't have encryption in tests, it should return a placeholder
	if displayName == "" {
		t.Error("Expected display name to not be empty")
	}
	if len(user.ID) >= 8 && displayName != "User "+user.ID[:8] {
		t.Errorf("Expected display name 'User %s', got '%s'", user.ID[:8], displayName)
	}
}

func TestUser_Clone(t *testing.T) {
	user := createTestUser()
	user.FirstName = []byte("encrypted_first_name")
	user.LastName = []byte("encrypted_last_name")
	user.Email = []byte("encrypted_email")
	user.LastLoginAt = timePtr(time.Now())
	user.LockedUntil = timePtr(time.Now().Add(time.Hour))

	clone := user.Clone()

	// Verify it's a different instance
	if clone == user {
		t.Error("Expected clone to be a different instance")
	}

	// Verify all fields are copied
	if clone.ID != user.ID {
		t.Error("Expected ID to be copied")
	}
	if clone.Status != user.Status {
		t.Error("Expected Status to be copied")
	}
	if clone.Version != user.Version {
		t.Error("Expected Version to be copied")
	}

	// Verify slices are deep copied
	if &clone.FirstName[0] == &user.FirstName[0] {
		t.Error("Expected FirstName to be deep copied")
	}
	if &clone.LastName[0] == &user.LastName[0] {
		t.Error("Expected LastName to be deep copied")
	}
	if &clone.Email[0] == &user.Email[0] {
		t.Error("Expected Email to be deep copied")
	}

	// Verify maps are deep copied
	if &clone.AuthenticationData == &user.AuthenticationData {
		t.Error("Expected AuthenticationData to be deep copied")
	}

	// Verify time pointers are deep copied
	if clone.LastLoginAt == user.LastLoginAt {
		t.Error("Expected LastLoginAt to be deep copied")
	}
	if clone.LockedUntil == user.LockedUntil {
		t.Error("Expected LockedUntil to be deep copied")
	}

	// Verify modifying clone doesn't affect original
	clone.Status = UserStatusSuspended
	if user.Status == UserStatusSuspended {
		t.Error("Expected original user status to remain unchanged")
	}
}

func TestUser_Validate(t *testing.T) {
	tests := []struct {
		name      string
		setupUser func() *User
		wantError bool
	}{
		{
			name: "ValidUser",
			setupUser: func() *User {
				return createTestUser()
			},
			wantError: false,
		},
		{
			name: "EmptyID",
			setupUser: func() *User {
				user := createTestUser()
				user.ID = ""
				return user
			},
			wantError: true,
		},
		{
			name: "InvalidUUID",
			setupUser: func() *User {
				user := createTestUser()
				user.ID = "invalid-uuid"
				return user
			},
			wantError: true,
		},
		{
			name: "EmptyHashedEmail",
			setupUser: func() *User {
				user := createTestUser()
				user.HashedEmail = ""
				return user
			},
			wantError: true,
		},
		{
			name: "NoAuthenticationData",
			setupUser: func() *User {
				user := createTestUser()
				user.AuthenticationData = nil
				return user
			},
			wantError: true,
		},
		{
			name: "EmptyAuthenticationData",
			setupUser: func() *User {
				user := createTestUser()
				user.AuthenticationData = make(map[auth.ProviderType]any)
				return user
			},
			wantError: true,
		},
		{
			name: "MissingPrimaryAuthProvider",
			setupUser: func() *User {
				user := createTestUser()
				user.PrimaryAuthProvider = auth.ProviderTypeOAuth
				return user
			},
			wantError: true,
		},
		{
			name: "InvalidStatus",
			setupUser: func() *User {
				user := createTestUser()
				user.Status = UserStatus(999)
				return user
			},
			wantError: true,
		},
		{
			name: "InvalidVersion",
			setupUser: func() *User {
				user := createTestUser()
				user.Version = 0
				return user
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := tt.setupUser()
			err := user.Validate()
			if (err != nil) != tt.wantError {
				t.Errorf("Validate() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// Helper functions

func createTestUser() *User {
	return NewUser(
		"John",
		"Doe",
		"john.doe@example.com",
		"hashed_email",
		auth.ProviderTypePassword,
		map[string]interface{}{"password": "hashed_password"},
	)
}

func timePtr(t time.Time) *time.Time {
	return &t
}
