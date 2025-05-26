package user

import (
	"testing"
	"time"

	"github.com/MichaelAJay/go-user-management/errors"
	"github.com/google/uuid"
)

func TestNewUser(t *testing.T) {
	firstName := "John"
	lastName := "Doe"
	email := "john@example.com"
	hashedEmail := "hashed_email_123"
	hashedPassword := []byte("hashed_password")

	user := NewUser(firstName, lastName, email, hashedEmail, hashedPassword)

	// Test basic fields
	if user.ID == "" {
		t.Error("Expected ID to be set")
	}

	if user.HashedEmail != hashedEmail {
		t.Errorf("Expected HashedEmail to be %s, got %s", hashedEmail, user.HashedEmail)
	}

	if string(user.Password) != string(hashedPassword) {
		t.Error("Expected Password to match")
	}

	// Test defaults
	if user.Status != UserStatusPendingVerification {
		t.Errorf("Expected Status to be %v, got %v", UserStatusPendingVerification, user.Status)
	}

	if user.LoginAttempts != 0 {
		t.Errorf("Expected LoginAttempts to be 0, got %d", user.LoginAttempts)
	}

	if user.Version != 1 {
		t.Errorf("Expected Version to be 1, got %d", user.Version)
	}

	// Test that ID is valid UUID
	if _, err := uuid.Parse(user.ID); err != nil {
		t.Errorf("Expected ID to be valid UUID, got error: %v", err)
	}

	// Test timestamps
	if user.CreatedAt.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}

	if user.UpdatedAt.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	if user.LastLoginAt != nil {
		t.Error("Expected LastLoginAt to be nil for new user")
	}

	if user.LockedUntil != nil {
		t.Error("Expected LockedUntil to be nil for new user")
	}
}

func TestUserStatus_String(t *testing.T) {
	tests := []struct {
		status   UserStatus
		expected string
	}{
		{UserStatusActive, "active"},
		{UserStatusSuspended, "suspended"},
		{UserStatusPendingVerification, "pending_verification"},
		{UserStatusLocked, "locked"},
		{UserStatusDeactivated, "deactivated"},
		{UserStatus(999), "unknown"},
	}

	for _, test := range tests {
		if got := test.status.String(); got != test.expected {
			t.Errorf("UserStatus(%d).String() = %s, want %s", test.status, got, test.expected)
		}
	}
}

func TestUserStatus_IsValid(t *testing.T) {
	validStatuses := []UserStatus{
		UserStatusActive,
		UserStatusSuspended,
		UserStatusPendingVerification,
		UserStatusLocked,
		UserStatusDeactivated,
	}

	for _, status := range validStatuses {
		if !status.IsValid() {
			t.Errorf("Expected status %v to be valid", status)
		}
	}

	// Test invalid status
	invalidStatus := UserStatus(999)
	if invalidStatus.IsValid() {
		t.Error("Expected invalid status to return false")
	}
}

func TestUserStatus_CanAuthenticate(t *testing.T) {
	tests := []struct {
		status   UserStatus
		expected bool
	}{
		{UserStatusActive, true},
		{UserStatusSuspended, false},
		{UserStatusPendingVerification, false},
		{UserStatusLocked, false},
		{UserStatusDeactivated, false},
	}

	for _, test := range tests {
		if got := test.status.CanAuthenticate(); got != test.expected {
			t.Errorf("UserStatus(%v).CanAuthenticate() = %v, want %v", test.status, got, test.expected)
		}
	}
}

func TestUser_IsActive(t *testing.T) {
	user := NewUser("John", "Doe", "john@example.com", "hashed_email", []byte("password"))

	// Initially pending verification
	if user.IsActive() {
		t.Error("Expected new user to not be active")
	}

	// Activate user
	user.Status = UserStatusActive
	if !user.IsActive() {
		t.Error("Expected activated user to be active")
	}

	// Suspend user
	user.Status = UserStatusSuspended
	if user.IsActive() {
		t.Error("Expected suspended user to not be active")
	}
}

func TestUser_IsLocked(t *testing.T) {
	user := NewUser("John", "Doe", "john@example.com", "hashed_email", []byte("password"))

	// Initially not locked
	if user.IsLocked() {
		t.Error("Expected new user to not be locked")
	}

	// Lock permanently
	user.Status = UserStatusLocked
	if !user.IsLocked() {
		t.Error("Expected user with locked status to be locked")
	}

	// Reset status but set temporary lock
	user.Status = UserStatusActive
	future := time.Now().Add(time.Hour)
	user.LockedUntil = &future
	if !user.IsLocked() {
		t.Error("Expected user with LockedUntil in future to be locked")
	}

	// Set lock in the past (expired)
	past := time.Now().Add(-time.Hour)
	user.LockedUntil = &past
	if user.IsLocked() {
		t.Error("Expected user with expired lock to not be locked")
	}
}

func TestUser_CanAuthenticate(t *testing.T) {
	user := NewUser("John", "Doe", "john@example.com", "hashed_email", []byte("password"))

	// Initially pending verification - cannot authenticate
	if user.CanAuthenticate() {
		t.Error("Expected user pending verification to not authenticate")
	}

	// Activate user
	user.Status = UserStatusActive
	if !user.CanAuthenticate() {
		t.Error("Expected active user to authenticate")
	}

	// Lock user
	user.Status = UserStatusLocked
	if user.CanAuthenticate() {
		t.Error("Expected locked user to not authenticate")
	}

	// Reset status but set temporary lock
	user.Status = UserStatusActive
	future := time.Now().Add(time.Hour)
	user.LockedUntil = &future
	if user.CanAuthenticate() {
		t.Error("Expected temporarily locked user to not authenticate")
	}
}

func TestUser_IncrementLoginAttempts(t *testing.T) {
	user := NewUser("John", "Doe", "john@example.com", "hashed_email", []byte("password"))
	initialVersion := user.Version
	initialUpdateTime := user.UpdatedAt

	// Wait a tiny bit to ensure timestamp changes
	time.Sleep(time.Millisecond)

	user.IncrementLoginAttempts()

	if user.LoginAttempts != 1 {
		t.Errorf("Expected LoginAttempts to be 1, got %d", user.LoginAttempts)
	}

	if user.Version != initialVersion+1 {
		t.Errorf("Expected Version to be incremented, got %d", user.Version)
	}

	if !user.UpdatedAt.After(initialUpdateTime) {
		t.Error("Expected UpdatedAt to be updated")
	}

	// Test multiple increments
	user.IncrementLoginAttempts()
	if user.LoginAttempts != 2 {
		t.Errorf("Expected LoginAttempts to be 2, got %d", user.LoginAttempts)
	}
}

func TestUser_ResetLoginAttempts(t *testing.T) {
	user := NewUser("John", "Doe", "john@example.com", "hashed_email", []byte("password"))
	user.LoginAttempts = 5
	lockTime := time.Now().Add(time.Hour)
	user.LockedUntil = &lockTime
	initialVersion := user.Version

	user.ResetLoginAttempts()

	if user.LoginAttempts != 0 {
		t.Errorf("Expected LoginAttempts to be 0, got %d", user.LoginAttempts)
	}

	if user.LockedUntil != nil {
		t.Error("Expected LockedUntil to be nil")
	}

	if user.Version != initialVersion+1 {
		t.Errorf("Expected Version to be incremented, got %d", user.Version)
	}
}

func TestUser_LockAccount(t *testing.T) {
	user := NewUser("John", "Doe", "john@example.com", "hashed_email", []byte("password"))
	initialVersion := user.Version

	// Test permanent lock
	user.LockAccount(nil)
	if user.Status != UserStatusLocked {
		t.Errorf("Expected Status to be %v, got %v", UserStatusLocked, user.Status)
	}
	if user.Version != initialVersion+1 {
		t.Error("Expected Version to be incremented")
	}

	// Test temporary lock
	user.Status = UserStatusActive
	lockTime := time.Now().Add(time.Hour)
	user.LockAccount(&lockTime)
	if user.LockedUntil == nil || !user.LockedUntil.Equal(lockTime) {
		t.Error("Expected LockedUntil to be set correctly")
	}
}

func TestUser_UnlockAccount(t *testing.T) {
	user := NewUser("John", "Doe", "john@example.com", "hashed_email", []byte("password"))
	user.Status = UserStatusLocked
	user.LoginAttempts = 5
	lockTime := time.Now().Add(time.Hour)
	user.LockedUntil = &lockTime

	user.UnlockAccount()

	if user.Status != UserStatusActive {
		t.Errorf("Expected Status to be %v, got %v", UserStatusActive, user.Status)
	}
	if user.LoginAttempts != 0 {
		t.Errorf("Expected LoginAttempts to be 0, got %d", user.LoginAttempts)
	}
	if user.LockedUntil != nil {
		t.Error("Expected LockedUntil to be nil")
	}
}

func TestUser_UpdateLastLogin(t *testing.T) {
	user := NewUser("John", "Doe", "john@example.com", "hashed_email", []byte("password"))
	initialVersion := user.Version

	if user.LastLoginAt != nil {
		t.Error("Expected LastLoginAt to be nil initially")
	}

	beforeUpdate := time.Now()
	user.UpdateLastLogin()
	afterUpdate := time.Now()

	if user.LastLoginAt == nil {
		t.Error("Expected LastLoginAt to be set")
	}

	if user.LastLoginAt.Before(beforeUpdate) || user.LastLoginAt.After(afterUpdate) {
		t.Error("Expected LastLoginAt to be within update timeframe")
	}

	if user.Version != initialVersion+1 {
		t.Error("Expected Version to be incremented")
	}
}

func TestUser_StatusTransitions(t *testing.T) {
	user := NewUser("John", "Doe", "john@example.com", "hashed_email", []byte("password"))
	initialVersion := user.Version

	// Test Activate
	user.Activate()
	if user.Status != UserStatusActive {
		t.Errorf("Expected Status to be %v, got %v", UserStatusActive, user.Status)
	}
	if user.Version != initialVersion+1 {
		t.Error("Expected Version to be incremented")
	}

	// Test Suspend
	user.Suspend()
	if user.Status != UserStatusSuspended {
		t.Errorf("Expected Status to be %v, got %v", UserStatusSuspended, user.Status)
	}

	// Test Deactivate
	user.Deactivate()
	if user.Status != UserStatusDeactivated {
		t.Errorf("Expected Status to be %v, got %v", UserStatusDeactivated, user.Status)
	}
}

func TestUser_UpdatePassword(t *testing.T) {
	user := NewUser("John", "Doe", "john@example.com", "hashed_email", []byte("old_password"))
	initialVersion := user.Version
	newPassword := []byte("new_password")

	user.UpdatePassword(newPassword)

	if string(user.Password) != string(newPassword) {
		t.Error("Expected Password to be updated")
	}

	if user.Version != initialVersion+1 {
		t.Error("Expected Version to be incremented")
	}
}

func TestUser_Clone(t *testing.T) {
	user := NewUser("John", "Doe", "john@example.com", "hashed_email", []byte("password"))
	user.Status = UserStatusActive
	user.LoginAttempts = 3
	loginTime := time.Now()
	user.LastLoginAt = &loginTime
	lockTime := time.Now().Add(time.Hour)
	user.LockedUntil = &lockTime

	clone := user.Clone()

	// Test that basic fields are copied
	if clone.ID != user.ID {
		t.Error("Expected ID to be copied")
	}
	if clone.Status != user.Status {
		t.Error("Expected Status to be copied")
	}
	if clone.LoginAttempts != user.LoginAttempts {
		t.Error("Expected LoginAttempts to be copied")
	}

	// Test that slices are deep copied
	if &clone.Password[0] == &user.Password[0] {
		t.Error("Expected Password to be deep copied")
	}

	// Test that time pointers are deep copied
	if clone.LastLoginAt == user.LastLoginAt {
		t.Error("Expected LastLoginAt to be deep copied")
	}
	if clone.LockedUntil == user.LockedUntil {
		t.Error("Expected LockedUntil to be deep copied")
	}

	// Test that values are equal
	if !clone.LastLoginAt.Equal(*user.LastLoginAt) {
		t.Error("Expected LastLoginAt values to be equal")
	}
	if !clone.LockedUntil.Equal(*user.LockedUntil) {
		t.Error("Expected LockedUntil values to be equal")
	}
}

func TestUser_Validate(t *testing.T) {
	// Test valid user
	user := NewUser("John", "Doe", "john@example.com", "hashed_email", []byte("password"))
	user.Status = UserStatusActive

	if err := user.Validate(); err != nil {
		t.Errorf("Expected valid user to pass validation, got error: %v", err)
	}

	// Test invalid ID
	user.ID = ""
	if err := user.Validate(); err != errors.ErrInvalidUserID {
		t.Errorf("Expected ErrInvalidUserID, got %v", err)
	}

	// Test invalid UUID format
	user.ID = "invalid-uuid"
	if err := user.Validate(); err != errors.ErrInvalidUserID {
		t.Errorf("Expected ErrInvalidUserID for invalid UUID, got %v", err)
	}

	// Reset to valid ID
	user.ID = uuid.New().String()

	// Test invalid email
	user.HashedEmail = ""
	if err := user.Validate(); err != errors.ErrInvalidEmail {
		t.Errorf("Expected ErrInvalidEmail, got %v", err)
	}

	// Reset email
	user.HashedEmail = "hashed_email"

	// Test invalid password
	user.Password = []byte{}
	if err := user.Validate(); err != errors.ErrInvalidPassword {
		t.Errorf("Expected ErrInvalidPassword, got %v", err)
	}

	// Reset password
	user.Password = []byte("password")

	// Test invalid status
	user.Status = UserStatus(999)
	if err := user.Validate(); err != errors.ErrInvalidUserStatus {
		t.Errorf("Expected ErrInvalidUserStatus, got %v", err)
	}

	// Reset status
	user.Status = UserStatusActive

	// Test invalid version
	user.Version = 0
	if err := user.Validate(); err != errors.ErrInvalidVersion {
		t.Errorf("Expected ErrInvalidVersion, got %v", err)
	}
}

func TestUser_GetDisplayName(t *testing.T) {
	user := NewUser("John", "Doe", "john@example.com", "hashed_email", []byte("password"))
	displayName := user.GetDisplayName()

	// Since encryption is not implemented yet, check for placeholder
	expected := "User " + user.ID[:8]
	if displayName != expected {
		t.Errorf("Expected display name to be %s, got %s", expected, displayName)
	}
}

func TestUser_ConcurrentSafety(t *testing.T) {
	user := NewUser("John", "Doe", "john@example.com", "hashed_email", []byte("password"))

	// Test that version increments work properly in concurrent scenarios
	// This is a basic test - real concurrent testing would require more complex scenarios
	originalVersion := user.Version

	user.IncrementLoginAttempts()
	user.UpdateLastLogin()
	user.Activate()

	expectedVersion := originalVersion + 3
	if user.Version != expectedVersion {
		t.Errorf("Expected Version to be %d, got %d", expectedVersion, user.Version)
	}
}
