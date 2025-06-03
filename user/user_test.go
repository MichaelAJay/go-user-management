package user

import (
	"testing"
	"time"

	"github.com/MichaelAJay/go-user-management/auth"
	"github.com/MichaelAJay/go-user-management/errors"
	"github.com/google/uuid"
)

// Test helper functions and mock implementations

// Test helper to create a valid user for testing
func createValidUser() *User {
	return NewUser("John", "Doe", "john.doe@example.com", "hashedEmail123", auth.ProviderTypePassword)
}

// Test helper to create encrypted data
func createEncryptedData(data string) []byte {
	return []byte("encrypted:" + data)
}

// Factory and Validation Tests (8 tests)

func TestNewUser_Success(t *testing.T) {
	firstName := "John"
	lastName := "Doe"
	email := "john.doe@example.com"
	hashedEmail := "hashedEmail123"
	provider := auth.ProviderTypePassword

	user := NewUser(firstName, lastName, email, hashedEmail, provider)

	// Verify all required fields are set correctly
	if user.ID == "" {
		t.Error("Expected ID to be generated, got empty string")
	}

	if user.HashedEmail != hashedEmail {
		t.Errorf("Expected HashedEmail %s, got %s", hashedEmail, user.HashedEmail)
	}

	if user.PrimaryAuthProvider != provider {
		t.Errorf("Expected PrimaryAuthProvider %s, got %s", provider, user.PrimaryAuthProvider)
	}

	if user.Version != 1 {
		t.Errorf("Expected Version 1, got %d", user.Version)
	}

	// Verify timestamps are set
	if user.CreatedAt.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}

	if user.UpdatedAt.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	// Verify UUID format
	if _, err := uuid.Parse(user.ID); err != nil {
		t.Errorf("Expected valid UUID, got %s: %v", user.ID, err)
	}
}

func TestNewUser_DefaultStatus(t *testing.T) {
	user := NewUser("John", "Doe", "john.doe@example.com", "hashedEmail123", auth.ProviderTypePassword)

	if user.Status != UserStatusPendingVerification {
		t.Errorf("Expected default status %s, got %s", UserStatusPendingVerification, user.Status)
	}
}

func TestNewUser_GeneratesUniqueIDs(t *testing.T) {
	user1 := NewUser("John", "Doe", "john1@example.com", "hashedEmail1", auth.ProviderTypePassword)
	user2 := NewUser("Jane", "Smith", "jane@example.com", "hashedEmail2", auth.ProviderTypePassword)

	if user1.ID == user2.ID {
		t.Errorf("Expected unique IDs, but both users have ID: %s", user1.ID)
	}
}

func TestUser_Validate_Success(t *testing.T) {
	user := createValidUser()

	err := user.Validate()
	if err != nil {
		t.Errorf("Expected validation to pass, got error: %v", err)
	}
}

func TestUser_Validate_MissingID(t *testing.T) {
	user := createValidUser()
	user.ID = ""

	err := user.Validate()
	if err != errors.ErrInvalidUserID {
		t.Errorf("Expected ErrInvalidUserID, got: %v", err)
	}
}

func TestUser_Validate_MissingHashedEmail(t *testing.T) {
	user := createValidUser()
	user.HashedEmail = ""

	err := user.Validate()
	if err != errors.ErrInvalidEmail {
		t.Errorf("Expected ErrInvalidEmail, got: %v", err)
	}
}

func TestUser_Validate_InvalidStatus(t *testing.T) {
	user := createValidUser()
	user.Status = UserStatus(999) // Invalid status

	err := user.Validate()
	if err != errors.ErrInvalidUserStatus {
		t.Errorf("Expected ErrInvalidUserStatus, got: %v", err)
	}
}

func TestUser_Validate_InvalidVersion(t *testing.T) {
	user := createValidUser()
	user.Version = 0

	err := user.Validate()
	if err != errors.ErrInvalidVersion {
		t.Errorf("Expected ErrInvalidVersion, got: %v", err)
	}

	user.Version = -1
	err = user.Validate()
	if err != errors.ErrInvalidVersion {
		t.Errorf("Expected ErrInvalidVersion for negative version, got: %v", err)
	}
}

// State Transition Tests (12 tests)

func TestUser_ActivateAccount_FromPending(t *testing.T) {
	user := createValidUser()
	user.Status = UserStatusPendingVerification
	initialVersion := user.Version

	err := user.ActivateAccount()
	if err != nil {
		t.Errorf("Expected successful activation, got error: %v", err)
	}

	if user.Status != UserStatusActive {
		t.Errorf("Expected status %s, got %s", UserStatusActive, user.Status)
	}

	if user.Version != initialVersion+1 {
		t.Errorf("Expected version to increment to %d, got %d", initialVersion+1, user.Version)
	}
}

func TestUser_ActivateAccount_FromLocked(t *testing.T) {
	user := createValidUser()
	user.Status = UserStatusLocked

	err := user.ActivateAccount()
	if err != nil {
		t.Errorf("Expected successful activation, got error: %v", err)
	}

	if user.Status != UserStatusActive {
		t.Errorf("Expected status %s, got %s", UserStatusActive, user.Status)
	}
}

func TestUser_ActivateAccount_AlreadyActive(t *testing.T) {
	user := createValidUser()
	user.Status = UserStatusActive
	initialVersion := user.Version

	err := user.ActivateAccount()
	if err != nil {
		t.Errorf("Expected no error for already active user, got: %v", err)
	}

	if user.Status != UserStatusActive {
		t.Errorf("Expected status to remain %s, got %s", UserStatusActive, user.Status)
	}

	// Version should not change for no-op
	if user.Version != initialVersion {
		t.Errorf("Expected version to remain %d, got %d", initialVersion, user.Version)
	}
}

func TestUser_ActivateAccount_FromDeactivated(t *testing.T) {
	user := createValidUser()
	user.Status = UserStatusDeactivated

	err := user.ActivateAccount()
	if err == nil {
		t.Error("Expected error when activating deactivated user")
	}

	appErr, ok := err.(*errors.AppError)
	if !ok || appErr.Code != errors.CodeUserDeactivated {
		t.Errorf("Expected CodeUserDeactivated, got: %v", err)
	}
}

func TestUser_ActivateAccount_FromSuspended(t *testing.T) {
	user := createValidUser()
	user.Status = UserStatusSuspended

	err := user.ActivateAccount()
	if err == nil {
		t.Error("Expected error when activating suspended user")
	}

	appErr, ok := err.(*errors.AppError)
	if !ok || appErr.Code != errors.CodeUserSuspended {
		t.Errorf("Expected CodeUserSuspended, got: %v", err)
	}
}

func TestUser_SuspendAccount_fromActive(t *testing.T) {
	user := createValidUser()
	user.Status = UserStatusActive
	initialVersion := user.Version

	err := user.SuspendAccount("Test reason")
	if err != nil {
		t.Errorf("Expected successful suspension, got error: %v", err)
	}

	if user.Status != UserStatusSuspended {
		t.Errorf("Expected status %s, got %s", UserStatusSuspended, user.Status)
	}

	if user.Version != initialVersion+1 {
		t.Errorf("Expected version to increment to %d, got %d", initialVersion+1, user.Version)
	}
}

func TestUser_SuspendAccount_AlreadySuspended(t *testing.T) {
	user := createValidUser()
	user.Status = UserStatusSuspended
	initialVersion := user.Version

	err := user.SuspendAccount("Test reason")
	if err != nil {
		t.Errorf("Expected no error for already suspended user, got: %v", err)
	}

	if user.Status != UserStatusSuspended {
		t.Errorf("Expected status to remain %s, got %s", UserStatusSuspended, user.Status)
	}

	// Version should not change for no-op
	if user.Version != initialVersion {
		t.Errorf("Expected version to remain %d, got %d", initialVersion, user.Version)
	}
}

func TestUser_SuspendAccount_FromDeactivated(t *testing.T) {
	user := createValidUser()
	user.Status = UserStatusDeactivated

	err := user.SuspendAccount("Test reason")
	if err == nil {
		t.Error("Expected error when suspending deactivated user")
	}

	appErr, ok := err.(*errors.AppError)
	if !ok || appErr.Code != errors.CodeUserDeactivated {
		t.Errorf("Expected CodeUserDeactivated, got: %v", err)
	}
}

func TestUser_DeactivateAccount_FromAnyStatus(t *testing.T) {
	statuses := []UserStatus{
		UserStatusActive,
		UserStatusSuspended,
		UserStatusPendingVerification,
		UserStatusLocked,
	}

	for _, status := range statuses {
		user := createValidUser()
		user.Status = status
		initialVersion := user.Version

		err := user.DeactivateAccount("Test reason")
		if err != nil {
			t.Errorf("Expected successful deactivation from %s, got error: %v", status, err)
		}

		if user.Status != UserStatusDeactivated {
			t.Errorf("Expected status %s from %s, got %s", UserStatusDeactivated, status, user.Status)
		}

		if user.Version != initialVersion+1 {
			t.Errorf("Expected version to increment from %s status, got %d", status, user.Version)
		}
	}
}

func TestUser_DeactivateAccount_AlreadyDeactivated(t *testing.T) {
	user := createValidUser()
	user.Status = UserStatusDeactivated
	initialVersion := user.Version

	err := user.DeactivateAccount("Test reason")
	if err != nil {
		t.Errorf("Expected no error for already deactivated user, got: %v", err)
	}

	if user.Status != UserStatusDeactivated {
		t.Errorf("Expected status to remain %s, got %s", UserStatusDeactivated, user.Status)
	}

	// Version should not change for no-op
	if user.Version != initialVersion {
		t.Errorf("Expected version to remain %d, got %d", initialVersion, user.Version)
	}
}

func TestUser_LockAccount_FromActive(t *testing.T) {
	user := createValidUser()
	user.Status = UserStatusActive
	initialVersion := user.Version

	err := user.LockAccountPermanently()
	if err != nil {
		t.Errorf("Expected successful lock, got error: %v", err)
	}

	if user.Status != UserStatusLocked {
		t.Errorf("Expected status %s, got %s", UserStatusLocked, user.Status)
	}

	if user.Version != initialVersion+1 {
		t.Errorf("Expected version to increment to %d, got %d", initialVersion+1, user.Version)
	}
}

func TestUser_LockAccount_FromDeactivated(t *testing.T) {
	user := createValidUser()
	user.Status = UserStatusDeactivated

	err := user.LockAccountPermanently()
	if err == nil {
		t.Error("Expected error when locking deactivated user")
	}

	appErr, ok := err.(*errors.AppError)
	if !ok || appErr.Code != errors.CodeUserDeactivated {
		t.Errorf("Expected CodeUserDeactivated, got: %v", err)
	}
}

// Profile Update Tests (8 tests)

func TestUser_UpdateProfileData_FirstNameOnly(t *testing.T) {
	user := createValidUser()
	initialVersion := user.Version

	encryptedFirstName := createEncryptedData("Jane")
	err := user.UpdateProfileData(encryptedFirstName, nil, nil, "")

	if err != nil {
		t.Errorf("Expected successful update, got error: %v", err)
	}

	if string(user.FirstName) != string(encryptedFirstName) {
		t.Errorf("Expected FirstName to be updated")
	}

	if user.Version != initialVersion+1 {
		t.Errorf("Expected version to increment to %d, got %d", initialVersion+1, user.Version)
	}
}

func TestUser_UpdateProfileData_LastNameOnly(t *testing.T) {
	user := createValidUser()
	initialVersion := user.Version

	encryptedLastName := createEncryptedData("Smith")
	err := user.UpdateProfileData(nil, encryptedLastName, nil, "")

	if err != nil {
		t.Errorf("Expected successful update, got error: %v", err)
	}

	if string(user.LastName) != string(encryptedLastName) {
		t.Errorf("Expected LastName to be updated")
	}

	if user.Version != initialVersion+1 {
		t.Errorf("Expected version to increment to %d, got %d", initialVersion+1, user.Version)
	}
}

func TestUser_UpdateProfileData_EmailOnly(t *testing.T) {
	user := createValidUser()
	initialVersion := user.Version

	encryptedEmail := createEncryptedData("new@example.com")
	newHashedEmail := "newHashedEmail123"
	err := user.UpdateProfileData(nil, nil, encryptedEmail, newHashedEmail)

	if err != nil {
		t.Errorf("Expected successful update, got error: %v", err)
	}

	if string(user.Email) != string(encryptedEmail) {
		t.Errorf("Expected Email to be updated")
	}

	if user.HashedEmail != newHashedEmail {
		t.Errorf("Expected HashedEmail to be updated to %s, got %s", newHashedEmail, user.HashedEmail)
	}

	if user.Version != initialVersion+1 {
		t.Errorf("Expected version to increment to %d, got %d", initialVersion+1, user.Version)
	}
}

func TestUser_UpdateProfileData_AllFields(t *testing.T) {
	user := createValidUser()
	initialVersion := user.Version

	encryptedFirstName := createEncryptedData("Jane")
	encryptedLastName := createEncryptedData("Smith")
	encryptedEmail := createEncryptedData("jane.smith@example.com")
	newHashedEmail := "newHashedEmail456"

	err := user.UpdateProfileData(encryptedFirstName, encryptedLastName, encryptedEmail, newHashedEmail)

	if err != nil {
		t.Errorf("Expected successful update, got error: %v", err)
	}

	if string(user.FirstName) != string(encryptedFirstName) {
		t.Errorf("Expected FirstName to be updated")
	}

	if string(user.LastName) != string(encryptedLastName) {
		t.Errorf("Expected LastName to be updated")
	}

	if string(user.Email) != string(encryptedEmail) {
		t.Errorf("Expected Email to be updated")
	}

	if user.HashedEmail != newHashedEmail {
		t.Errorf("Expected HashedEmail to be updated to %s, got %s", newHashedEmail, user.HashedEmail)
	}

	if user.Version != initialVersion+1 {
		t.Errorf("Expected version to increment to %d, got %d", initialVersion+1, user.Version)
	}
}

func TestUser_UpdateProfileData_EmptyUpdate(t *testing.T) {
	user := createValidUser()

	err := user.UpdateProfileData(nil, nil, nil, "")
	if err == nil {
		t.Error("Expected error for empty update")
	}

	appErr, ok := err.(*errors.AppError)
	if !ok || appErr.Code != errors.CodeValidationFailed {
		t.Errorf("Expected validation error with CodeValidationFailed, got: %v", err)
	}
}

func TestUser_UpdateProfileData_EmailWithoutHash(t *testing.T) {
	user := createValidUser()

	encryptedEmail := createEncryptedData("new@example.com")
	err := user.UpdateProfileData(nil, nil, encryptedEmail, "")
	if err == nil {
		t.Error("Expected error when providing email without hashed email")
	}

	appErr, ok := err.(*errors.AppError)
	if !ok || appErr.Code != errors.CodeValidationFailed {
		t.Errorf("Expected validation error with CodeValidationFailed, got: %v", err)
	}
}

func TestUser_UpdateProfileData_HashWithoutEmail(t *testing.T) {
	user := createValidUser()

	err := user.UpdateProfileData(nil, nil, nil, "newHashedEmail123")
	if err == nil {
		t.Error("Expected error when providing hashed email without email")
	}

	appErr, ok := err.(*errors.AppError)
	if !ok || appErr.Code != errors.CodeValidationFailed {
		t.Errorf("Expected validation error with CodeValidationFailed, got: %v", err)
	}
}

func TestUser_UpdateProfileData_EmailChangeRequiresVerification(t *testing.T) {
	user := createValidUser()
	user.Status = UserStatusActive // Make sure user is active

	encryptedEmail := createEncryptedData("new@example.com")
	newHashedEmail := "newHashedEmail123"
	err := user.UpdateProfileData(nil, nil, encryptedEmail, newHashedEmail)

	if err != nil {
		t.Errorf("Expected successful update, got error: %v", err)
	}

	if user.Status != UserStatusPendingVerification {
		t.Errorf("Expected status to change to %s for email change, got %s", UserStatusPendingVerification, user.Status)
	}
}

// Metadata and State Management Tests (7 tests)

func TestUser_Clone_DeepCopy(t *testing.T) {
	user := createValidUser()
	user.FirstName = createEncryptedData("John")
	user.LastName = createEncryptedData("Doe")
	user.Email = createEncryptedData("john.doe@example.com")

	clone := user.Clone()

	// Verify it's a deep copy
	if clone == user {
		t.Error("Expected different instance, got same reference")
	}

	// Verify all fields are copied
	if clone.ID != user.ID {
		t.Errorf("Expected ID %s, got %s", user.ID, clone.ID)
	}

	if clone.HashedEmail != user.HashedEmail {
		t.Errorf("Expected HashedEmail %s, got %s", user.HashedEmail, clone.HashedEmail)
	}

	if clone.Status != user.Status {
		t.Errorf("Expected Status %s, got %s", user.Status, clone.Status)
	}

	// Verify byte slices are deep copied
	if string(clone.FirstName) != string(user.FirstName) {
		t.Errorf("Expected FirstName to be copied")
	}

	if &clone.FirstName[0] == &user.FirstName[0] {
		t.Error("Expected FirstName to be deep copied, got same memory reference")
	}
}

func TestUser_Clone_IndependentUpdates(t *testing.T) {
	user := createValidUser()
	user.FirstName = createEncryptedData("John")

	clone := user.Clone()

	// Modify original
	user.FirstName[0] = 'X'

	// Verify clone is unaffected
	if clone.FirstName[0] == 'X' {
		t.Error("Expected clone to be independent of original modifications")
	}
}

func TestUser_UpdateMetadata_VersionIncrement(t *testing.T) {
	user := createValidUser()
	initialVersion := user.Version

	// Use any method that calls updateMetadata
	err := user.ActivateAccount()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if user.Version != initialVersion+1 {
		t.Errorf("Expected version to increment to %d, got %d", initialVersion+1, user.Version)
	}
}

func TestUser_UpdateMetadata_TimestampUpdate(t *testing.T) {
	user := createValidUser()
	initialTime := user.UpdatedAt

	// Wait a small amount to ensure timestamp difference
	time.Sleep(1 * time.Millisecond)

	// Use any method that calls updateMetadata
	err := user.ActivateAccount()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if !user.UpdatedAt.After(initialTime) {
		t.Errorf("Expected UpdatedAt to be updated, got %v (was %v)", user.UpdatedAt, initialTime)
	}
}

func TestUser_IsActive_StatusCheck(t *testing.T) {
	user := createValidUser()

	// Test active status
	user.Status = UserStatusActive
	if !user.IsActive() {
		t.Error("Expected IsActive to return true for active user")
	}

	// Test non-active statuses
	nonActiveStatuses := []UserStatus{
		UserStatusPendingVerification,
		UserStatusSuspended,
		UserStatusLocked,
		UserStatusDeactivated,
	}

	for _, status := range nonActiveStatuses {
		user.Status = status
		if user.IsActive() {
			t.Errorf("Expected IsActive to return false for status %s", status)
		}
	}
}

func TestUser_CanAuthenticate_StatusCheck(t *testing.T) {
	user := createValidUser()

	// Test active status
	user.Status = UserStatusActive
	if !user.CanAuthenticate() {
		t.Error("Expected CanAuthenticate to return true for active user")
	}

	// Test non-authenticatable statuses
	nonAuthStatuses := []UserStatus{
		UserStatusPendingVerification,
		UserStatusSuspended,
		UserStatusLocked,
		UserStatusDeactivated,
	}

	for _, status := range nonAuthStatuses {
		user.Status = status
		if user.CanAuthenticate() {
			t.Errorf("Expected CanAuthenticate to return false for status %s", status)
		}
	}
}

func TestUser_GetDisplayName_WithEncrypter(t *testing.T) {
	user := createValidUser()
	user.FirstName = createEncryptedData("John")

	mockEncrypter := &MockEncrypter{shouldFail: false}
	mockLogger := &MockLogger{}

	displayName := user.GetDisplayName(mockEncrypter, mockLogger)

	expectedName := "John"
	if displayName != expectedName {
		t.Errorf("Expected display name %s, got %s", expectedName, displayName)
	}

	// Verify logger was not called for successful decryption
	if mockLogger.warnCalled {
		t.Error("Expected logger not to be called for successful decryption")
	}
}

func TestUser_GetDisplayName_WithFailedDecryption(t *testing.T) {
	user := createValidUser()
	user.FirstName = createEncryptedData("John")

	mockEncrypter := &MockEncrypter{shouldFail: true}
	mockLogger := &MockLogger{}

	displayName := user.GetDisplayName(mockEncrypter, mockLogger)

	// Should return fallback based on user ID
	expectedPrefix := "User " + user.ID[:8]
	if displayName != expectedPrefix {
		t.Errorf("Expected display name %s, got %s", expectedPrefix, displayName)
	}

	// Verify logger was called for failed decryption
	if !mockLogger.warnCalled {
		t.Error("Expected logger to be called for failed decryption")
	}
}

func TestUser_GetDisplayName_WithoutEncrypter(t *testing.T) {
	user := createValidUser()
	user.FirstName = createEncryptedData("John")

	displayName := user.GetDisplayName(nil, nil)

	// Should return fallback based on user ID
	expectedPrefix := "User " + user.ID[:8]
	if displayName != expectedPrefix {
		t.Errorf("Expected display name %s, got %s", expectedPrefix, displayName)
	}
}

// Additional tests for UnlockAccount method

func TestUser_UnlockAccount_Success(t *testing.T) {
	user := createValidUser()
	user.Status = UserStatusLocked
	initialVersion := user.Version

	user.UnlockAccount()

	if user.Status != UserStatusActive {
		t.Errorf("Expected status %s, got %s", UserStatusActive, user.Status)
	}

	if user.Version != initialVersion+1 {
		t.Errorf("Expected version to increment to %d, got %d", initialVersion+1, user.Version)
	}
}

func TestUser_UnlockAccount_NotLocked(t *testing.T) {
	user := createValidUser()
	user.Status = UserStatusActive
	initialVersion := user.Version

	user.UnlockAccount()

	// Should be no-op if not locked
	if user.Status != UserStatusActive {
		t.Errorf("Expected status to remain %s, got %s", UserStatusActive, user.Status)
	}

	if user.Version != initialVersion {
		t.Errorf("Expected version to remain %d, got %d", initialVersion, user.Version)
	}
}

// Test GetID method for completeness

func TestUser_GetID(t *testing.T) {
	user := createValidUser()

	if user.GetID() != user.ID {
		t.Errorf("Expected GetID to return %s, got %s", user.ID, user.GetID())
	}
}
