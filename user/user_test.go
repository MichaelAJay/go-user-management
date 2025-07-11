package user

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNewUser(t *testing.T) {
	tests := []struct {
		name      string
		email     []byte
		firstName []byte
		lastName  []byte
	}{
		{
			name:      "valid user creation",
			email:     []byte("encrypted:test@example.com"),
			firstName: []byte("encrypted:John"),
			lastName:  []byte("encrypted:Doe"),
		},
		{
			name:      "user with empty fields",
			email:     []byte(""),
			firstName: []byte(""),
			lastName:  []byte(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := NewUser(tt.email, tt.firstName, tt.lastName)

			if user == nil {
				t.Fatal("NewUser() returned nil")
			}

			if user.ID == uuid.Nil {
				t.Error("NewUser() should generate a valid UUID")
			}

			if string(user.Email) != string(tt.email) {
				t.Errorf("NewUser() email = %v, want %v", string(user.Email), string(tt.email))
			}

			if string(user.FirstName) != string(tt.firstName) {
				t.Errorf("NewUser() firstName = %v, want %v", string(user.FirstName), string(tt.firstName))
			}

			if string(user.LastName) != string(tt.lastName) {
				t.Errorf("NewUser() lastName = %v, want %v", string(user.LastName), string(tt.lastName))
			}

			if !user.IsActive {
				t.Error("NewUser() should create active user by default")
			}

			if user.IsVerified {
				t.Error("NewUser() should create unverified user by default")
			}

			if user.Version != 1 {
				t.Errorf("NewUser() version = %v, want 1", user.Version)
			}

			if user.CreatedAt.IsZero() {
				t.Error("NewUser() should set CreatedAt")
			}

			if user.UpdatedAt.IsZero() {
				t.Error("NewUser() should set UpdatedAt")
			}

			if user.LastLoginAt != nil {
				t.Error("NewUser() should not set LastLoginAt initially")
			}
		})
	}
}

func TestUser_UpdateVersion(t *testing.T) {
	user := NewUser([]byte("encrypted:test@example.com"), []byte("encrypted:John"), []byte("encrypted:Doe"))
	originalVersion := user.Version
	originalUpdatedAt := user.UpdatedAt

	// Small delay to ensure UpdatedAt changes
	time.Sleep(1 * time.Millisecond)

	user.UpdateVersion()

	if user.Version != originalVersion+1 {
		t.Errorf("UpdateVersion() version = %v, want %v", user.Version, originalVersion+1)
	}

	if !user.UpdatedAt.After(originalUpdatedAt) {
		t.Error("UpdateVersion() should update UpdatedAt timestamp")
	}
}

func TestUser_Activate(t *testing.T) {
	user := NewUser([]byte("encrypted:test@example.com"), []byte("encrypted:John"), []byte("encrypted:Doe"))
	originalVersion := user.Version
	// Deactivate first
	user.IsActive = false
	user.UpdateVersion()
	currentVersion := user.Version

	user.Activate()

	if !user.IsActive {
		t.Error("Activate() should set IsActive to true")
	}

	if user.Version != currentVersion+1 {
		t.Errorf("Activate() version = %v, want %v", user.Version, currentVersion+1)
	}

	if user.Version <= originalVersion {
		t.Error("Activate() should increment version")
	}
}

func TestUser_Deactivate(t *testing.T) {
	user := NewUser([]byte("encrypted:test@example.com"), []byte("encrypted:John"), []byte("encrypted:Doe"))
	originalVersion := user.Version

	user.Deactivate()

	if user.IsActive {
		t.Error("Deactivate() should set IsActive to false")
	}

	if user.Version != originalVersion+1 {
		t.Errorf("Deactivate() version = %v, want %v", user.Version, originalVersion+1)
	}
}

func TestUser_Verify(t *testing.T) {
	user := NewUser([]byte("encrypted:test@example.com"), []byte("encrypted:John"), []byte("encrypted:Doe"))
	originalVersion := user.Version

	if user.IsVerified {
		t.Error("NewUser() should create unverified user")
	}

	user.Verify()

	if !user.IsVerified {
		t.Error("Verify() should set IsVerified to true")
	}

	if user.Version != originalVersion+1 {
		t.Errorf("Verify() version = %v, want %v", user.Version, originalVersion+1)
	}
}

func TestUser_RecordLogin(t *testing.T) {
	user := NewUser([]byte("encrypted:test@example.com"), []byte("encrypted:John"), []byte("encrypted:Doe"))
	originalVersion := user.Version

	if user.LastLoginAt != nil {
		t.Error("NewUser() should not set LastLoginAt initially")
	}

	beforeLogin := time.Now()
	user.RecordLogin()
	afterLogin := time.Now()

	if user.LastLoginAt == nil {
		t.Error("RecordLogin() should set LastLoginAt")
	}

	if user.LastLoginAt.Before(beforeLogin) || user.LastLoginAt.After(afterLogin) {
		t.Error("RecordLogin() should set LastLoginAt to current time")
	}

	if user.Version != originalVersion+1 {
		t.Errorf("RecordLogin() version = %v, want %v", user.Version, originalVersion+1)
	}

	// Test multiple logins
	firstLogin := *user.LastLoginAt
	time.Sleep(1 * time.Millisecond)
	user.RecordLogin()

	if !user.LastLoginAt.After(firstLogin) {
		t.Error("RecordLogin() should update LastLoginAt on subsequent calls")
	}
}

func TestUser_VersionIncrement(t *testing.T) {
	user := NewUser([]byte("encrypted:test@example.com"), []byte("encrypted:John"), []byte("encrypted:Doe"))
	initialVersion := user.Version

	// Test that all mutating methods increment version
	user.Activate()
	if user.Version != initialVersion+1 {
		t.Errorf("Activate() should increment version to %v, got %v", initialVersion+1, user.Version)
	}

	user.Deactivate()
	if user.Version != initialVersion+2 {
		t.Errorf("Deactivate() should increment version to %v, got %v", initialVersion+2, user.Version)
	}

	user.Verify()
	if user.Version != initialVersion+3 {
		t.Errorf("Verify() should increment version to %v, got %v", initialVersion+3, user.Version)
	}

	user.RecordLogin()
	if user.Version != initialVersion+4 {
		t.Errorf("RecordLogin() should increment version to %v, got %v", initialVersion+4, user.Version)
	}
}

func TestUser_ImmutableFields(t *testing.T) {
	user := NewUser([]byte("encrypted:test@example.com"), []byte("encrypted:John"), []byte("encrypted:Doe"))

	originalID := user.ID
	originalCreatedAt := user.CreatedAt

	// Perform various operations
	user.Activate()
	user.Deactivate()
	user.Verify()
	user.RecordLogin()

	// ID and CreatedAt should remain unchanged
	if user.ID != originalID {
		t.Error("ID should not change after operations")
	}

	if !user.CreatedAt.Equal(originalCreatedAt) {
		t.Error("CreatedAt should not change after operations")
	}

	// UpdatedAt should change
	if user.UpdatedAt.Equal(originalCreatedAt) {
		t.Error("UpdatedAt should change after operations")
	}
}
