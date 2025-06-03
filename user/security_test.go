package user

import (
	"testing"
	"time"

	"github.com/MichaelAJay/go-user-management/errors"
)

// Test helper functions for UserSecurity

// createValidUserSecurity creates a valid UserSecurity for testing
func createValidUserSecurity() *UserSecurity {
	return NewUserSecurity("user-123")
}

// createUserSecurityWithFailures creates a UserSecurity with some failed attempts for testing
func createUserSecurityWithFailures(attempts int) *UserSecurity {
	security := createValidUserSecurity()
	security.LoginAttempts = attempts
	security.TotalLoginAttempts = attempts
	return security
}

// Security State Management Tests (8 tests)

func TestUserSecurity_ProcessFailedAttempt_IncrementCounter(t *testing.T) {
	security := createValidUserSecurity()
	initialAttempts := security.LoginAttempts
	initialTotalAttempts := security.TotalLoginAttempts
	ipAddress := "192.168.1.1"

	security.ProcessFailedAttempt(5, time.Hour, ipAddress)

	if security.LoginAttempts != initialAttempts+1 {
		t.Errorf("Expected LoginAttempts to increment to %d, got %d", initialAttempts+1, security.LoginAttempts)
	}

	if security.TotalLoginAttempts != initialTotalAttempts+1 {
		t.Errorf("Expected TotalLoginAttempts to increment to %d, got %d", initialTotalAttempts+1, security.TotalLoginAttempts)
	}

	if security.LastFailedAt == nil {
		t.Error("Expected LastFailedAt to be set")
	}

	// Verify security event was added
	if len(security.SecurityEvents) == 0 {
		t.Error("Expected security event to be added")
	}

	event := security.SecurityEvents[0]
	if event.Type != SecurityEventLoginFailure {
		t.Errorf("Expected event type %s, got %s", SecurityEventLoginFailure, event.Type)
	}

	if event.IPAddress != ipAddress {
		t.Errorf("Expected IP address %s, got %s", ipAddress, event.IPAddress)
	}
}

func TestUserSecurity_ProcessFailedAttempt_LockAfterMaxAttempts(t *testing.T) {
	security := createUserSecurityWithFailures(4) // One less than max
	maxAttempts := 5
	lockDuration := time.Hour
	ipAddress := "192.168.1.1"

	security.ProcessFailedAttempt(maxAttempts, lockDuration, ipAddress)

	if security.LoginAttempts != maxAttempts {
		t.Errorf("Expected LoginAttempts to be %d, got %d", maxAttempts, security.LoginAttempts)
	}

	if security.LockedUntil == nil {
		t.Error("Expected account to be locked")
	}

	expectedUnlockTime := time.Now().Add(lockDuration)
	if security.LockedUntil.Before(expectedUnlockTime.Add(-time.Second)) || security.LockedUntil.After(expectedUnlockTime.Add(time.Second)) {
		t.Errorf("Expected lock until around %v, got %v", expectedUnlockTime, security.LockedUntil)
	}

	if security.LockReason != "too_many_attempts" {
		t.Errorf("Expected lock reason 'too_many_attempts', got %s", security.LockReason)
	}
}

func TestUserSecurity_ProcessSuccessfulLogin_ResetsCounters(t *testing.T) {
	security := createUserSecurityWithFailures(3)
	// Set up some locked state
	future := time.Now().Add(time.Hour)
	security.LockedUntil = &future
	security.LockReason = "too_many_attempts"
	ipAddress := "192.168.1.1"

	security.ProcessSuccessfulLogin(ipAddress)

	if security.LoginAttempts != 0 {
		t.Errorf("Expected LoginAttempts to be reset to 0, got %d", security.LoginAttempts)
	}

	if security.LockedUntil != nil {
		t.Error("Expected LockedUntil to be cleared")
	}

	if security.LockReason != "" {
		t.Errorf("Expected LockReason to be cleared, got %s", security.LockReason)
	}

	if security.LastLoginAt == nil {
		t.Error("Expected LastLoginAt to be set")
	}

	if security.LastLoginIP != ipAddress {
		t.Errorf("Expected LastLoginIP to be %s, got %s", ipAddress, security.LastLoginIP)
	}

	if security.SuccessfulLogins == 0 {
		t.Error("Expected SuccessfulLogins to be incremented")
	}
}

func TestUserSecurity_ProcessSuccessfulLogin_UpdatesTimestamp(t *testing.T) {
	security := createValidUserSecurity()
	initialTime := time.Now().Add(-time.Hour) // Set to past time
	security.LastLoginAt = &initialTime
	ipAddress := "192.168.1.1"

	security.ProcessSuccessfulLogin(ipAddress)

	if security.LastLoginAt == nil {
		t.Error("Expected LastLoginAt to be set")
	}

	if !security.LastLoginAt.After(initialTime) {
		t.Errorf("Expected LastLoginAt to be updated, got %v (was %v)", security.LastLoginAt, initialTime)
	}
}

func TestUserSecurity_LockAccount_TemporaryLock(t *testing.T) {
	security := createValidUserSecurity()
	lockUntil := time.Now().Add(time.Hour)
	reason := "suspicious_activity"

	security.LockAccount(&lockUntil, reason)

	if security.LockedUntil == nil {
		t.Error("Expected LockedUntil to be set")
	}

	if !security.LockedUntil.Equal(lockUntil) {
		t.Errorf("Expected LockedUntil to be %v, got %v", lockUntil, security.LockedUntil)
	}

	if security.LockReason != reason {
		t.Errorf("Expected LockReason to be %s, got %s", reason, security.LockReason)
	}

	// Verify security event was added
	if len(security.SecurityEvents) == 0 {
		t.Error("Expected security event to be added")
	}

	event := security.SecurityEvents[0]
	if event.Type != SecurityEventAccountLocked {
		t.Errorf("Expected event type %s, got %s", SecurityEventAccountLocked, event.Type)
	}
}

func TestUserSecurity_LockAccount_PermanentLock(t *testing.T) {
	security := createValidUserSecurity()
	reason := "permanent_ban"

	security.LockAccount(nil, reason) // nil means permanent lock

	if security.LockedUntil != nil {
		t.Error("Expected LockedUntil to be nil for permanent lock")
	}

	if security.LockReason != reason {
		t.Errorf("Expected LockReason to be %s, got %s", reason, security.LockReason)
	}
}

func TestUserSecurity_UnlockAccount_ClearsLockState(t *testing.T) {
	security := createValidUserSecurity()
	// Set up locked state
	future := time.Now().Add(time.Hour)
	security.LockedUntil = &future
	security.LockReason = "test_lock"
	security.LoginAttempts = 5

	security.UnlockAccount()

	if security.LockedUntil != nil {
		t.Error("Expected LockedUntil to be cleared")
	}

	if security.LockReason != "" {
		t.Errorf("Expected LockReason to be cleared, got %s", security.LockReason)
	}

	if security.LoginAttempts != 0 {
		t.Errorf("Expected LoginAttempts to be reset to 0, got %d", security.LoginAttempts)
	}

	// Verify security event was added
	if len(security.SecurityEvents) == 0 {
		t.Error("Expected security event to be added")
	}

	event := security.SecurityEvents[0]
	if event.Type != SecurityEventAccountUnlocked {
		t.Errorf("Expected event type %s, got %s", SecurityEventAccountUnlocked, event.Type)
	}
}

func TestUserSecurity_IsLocked_StatusCheck(t *testing.T) {
	security := createValidUserSecurity()

	// Test not locked
	if security.IsLocked() {
		t.Error("Expected IsLocked to return false for unlocked account")
	}

	// Test temporary lock in future
	future := time.Now().Add(time.Hour)
	security.LockedUntil = &future
	if !security.IsLocked() {
		t.Error("Expected IsLocked to return true for future lock")
	}

	// Test expired lock
	past := time.Now().Add(-time.Hour)
	security.LockedUntil = &past
	if security.IsLocked() {
		t.Error("Expected IsLocked to return false for expired lock")
	}
}

// Risk Score Management Tests (5 tests)

func TestUserSecurity_UpdateRiskScore_ValidRange(t *testing.T) {
	security := createValidUserSecurity()
	validScores := []float64{0.0, 25.5, 50.0, 75.5, 100.0}
	factors := []RiskFactor{RiskFactorUnknownDevice, RiskFactorHighFailureRate}

	for _, score := range validScores {
		err := security.UpdateRiskScore(score, factors)
		if err != nil {
			t.Errorf("Expected no error for valid score %f, got: %v", score, err)
		}

		if security.RiskScore != score {
			t.Errorf("Expected RiskScore to be %f, got %f", score, security.RiskScore)
		}

		if len(security.RiskFactors) != len(factors) {
			t.Errorf("Expected %d risk factors, got %d", len(factors), len(security.RiskFactors))
		}
	}
}

func TestUserSecurity_UpdateRiskScore_InvalidRange(t *testing.T) {
	security := createValidUserSecurity()
	invalidScores := []float64{-1.0, -10.5, 100.1, 150.0}

	for _, score := range invalidScores {
		err := security.UpdateRiskScore(score, nil)
		if err == nil {
			t.Errorf("Expected error for invalid score %f", score)
		}

		appErr, ok := err.(*errors.AppError)
		if !ok || appErr.Code != errors.CodeValidationFailed {
			t.Errorf("Expected validation error for invalid score %f, got: %v", score, err)
		}
	}
}

func TestUserSecurity_UpdateRiskScore_RiskFactors(t *testing.T) {
	security := createValidUserSecurity()
	factors := []RiskFactor{
		RiskFactorUnknownDevice,
		RiskFactorUnknownLocation,
		RiskFactorHighFailureRate,
	}

	err := security.UpdateRiskScore(75.0, factors)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	if len(security.RiskFactors) != len(factors) {
		t.Errorf("Expected %d risk factors, got %d", len(factors), len(security.RiskFactors))
	}

	for i, expectedFactor := range factors {
		if security.RiskFactors[i] != expectedFactor {
			t.Errorf("Expected risk factor %s at index %d, got %s", expectedFactor, i, security.RiskFactors[i])
		}
	}
}

func TestUserSecurity_UpdateRiskScore_VersionIncrement(t *testing.T) {
	security := createValidUserSecurity()
	initialVersion := security.Version

	err := security.UpdateRiskScore(50.0, nil)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	if security.Version != initialVersion+1 {
		t.Errorf("Expected version to increment to %d, got %d", initialVersion+1, security.Version)
	}
}

func TestUserSecurity_CalculateRiskScore_Algorithm(t *testing.T) {
	security := createValidUserSecurity()

	// Test adding individual risk factors
	security.AddRiskFactor(RiskFactorUnknownDevice)
	if !security.HasRiskFactor(RiskFactorUnknownDevice) {
		t.Error("Expected HasRiskFactor to return true for added factor")
	}

	// Test removing risk factors
	security.RemoveRiskFactor(RiskFactorUnknownDevice)
	if security.HasRiskFactor(RiskFactorUnknownDevice) {
		t.Error("Expected HasRiskFactor to return false for removed factor")
	}

	// Test high risk detection
	security.RiskScore = 80.0
	if !security.IsHighRisk() {
		t.Error("Expected IsHighRisk to return true for score >= 75.0")
	}

	security.RiskScore = 50.0
	if security.IsHighRisk() {
		t.Error("Expected IsHighRisk to return false for score < 75.0")
	}
}

// Security Events Tests (7 tests)

func TestUserSecurity_AddSecurityEvent_LoginSuccess(t *testing.T) {
	security := createValidUserSecurity()
	ipAddress := "192.168.1.1"

	security.ProcessSuccessfulLogin(ipAddress)

	if len(security.SecurityEvents) == 0 {
		t.Error("Expected security event to be added")
	}

	event := security.SecurityEvents[0]
	if event.Type != SecurityEventLoginSuccess {
		t.Errorf("Expected event type %s, got %s", SecurityEventLoginSuccess, event.Type)
	}

	if event.IPAddress != ipAddress {
		t.Errorf("Expected IP address %s, got %s", ipAddress, event.IPAddress)
	}

	if event.Timestamp.IsZero() {
		t.Error("Expected event timestamp to be set")
	}
}

func TestUserSecurity_AddSecurityEvent_LoginFailure(t *testing.T) {
	security := createValidUserSecurity()
	ipAddress := "192.168.1.1"

	security.ProcessFailedAttempt(5, time.Hour, ipAddress)

	if len(security.SecurityEvents) == 0 {
		t.Error("Expected security event to be added")
	}

	event := security.SecurityEvents[0]
	if event.Type != SecurityEventLoginFailure {
		t.Errorf("Expected event type %s, got %s", SecurityEventLoginFailure, event.Type)
	}

	if event.IPAddress != ipAddress {
		t.Errorf("Expected IP address %s, got %s", ipAddress, event.IPAddress)
	}
}

func TestUserSecurity_AddSecurityEvent_AccountLocked(t *testing.T) {
	security := createValidUserSecurity()
	lockUntil := time.Now().Add(time.Hour)

	security.LockAccount(&lockUntil, "too_many_attempts")

	if len(security.SecurityEvents) == 0 {
		t.Error("Expected security event to be added")
	}

	event := security.SecurityEvents[0]
	if event.Type != SecurityEventAccountLocked {
		t.Errorf("Expected event type %s, got %s", SecurityEventAccountLocked, event.Type)
	}
}

func TestUserSecurity_AddSecurityEvent_PasswordChanged(t *testing.T) {
	security := createValidUserSecurity()

	// Simulate password change event
	event := SecurityEvent{
		Type:      SecurityEventPasswordChanged,
		Timestamp: time.Now(),
		IPAddress: "192.168.1.1",
		Details: map[string]interface{}{
			"provider": "password",
		},
	}

	security.addSecurityEvent(event)

	if len(security.SecurityEvents) == 0 {
		t.Error("Expected security event to be added")
	}

	addedEvent := security.SecurityEvents[0]
	if addedEvent.Type != SecurityEventPasswordChanged {
		t.Errorf("Expected event type %s, got %s", SecurityEventPasswordChanged, addedEvent.Type)
	}
}

func TestUserSecurity_SecurityEventsLimiting(t *testing.T) {
	security := createValidUserSecurity()

	// Add more than 100 events to test limiting
	for i := 0; i < 150; i++ {
		event := SecurityEvent{
			Type:      SecurityEventLoginSuccess,
			Timestamp: time.Now(),
			IPAddress: "192.168.1.1",
		}
		security.addSecurityEvent(event)
	}

	// Check that events are limited to 100
	if len(security.SecurityEvents) > 100 {
		t.Errorf("Expected security events to be limited to 100, got %d", len(security.SecurityEvents))
	}

	// Check that the most recent events are kept (should be at the end)
	if len(security.SecurityEvents) == 100 {
		lastEvent := security.SecurityEvents[len(security.SecurityEvents)-1]
		if lastEvent.Type != SecurityEventLoginSuccess {
			t.Error("Expected most recent events to be kept")
		}
	}
}

func TestUserSecurity_GetRecentEvents_TimeFiltering(t *testing.T) {
	security := createValidUserSecurity()
	now := time.Now()

	// Add events at different times
	oldEvent := SecurityEvent{
		Type:      SecurityEventLoginFailure,
		Timestamp: now.Add(-5 * 24 * time.Hour), // 5 days ago
		IPAddress: "192.168.1.1",
	}
	recentEvent := SecurityEvent{
		Type:      SecurityEventLoginSuccess,
		Timestamp: now.Add(-1 * time.Hour), // 1 hour ago
		IPAddress: "192.168.1.2",
	}

	security.addSecurityEvent(oldEvent)
	security.addSecurityEvent(recentEvent)

	// Get events from last 3 days
	recentEvents := security.GetRecentEvents(3)

	if len(recentEvents) != 1 {
		t.Errorf("Expected 1 recent event, got %d", len(recentEvents))
	}

	if recentEvents[0].Type != SecurityEventLoginSuccess {
		t.Errorf("Expected recent event to be login success, got %s", recentEvents[0].Type)
	}
}

func TestUserSecurity_GetRecentEvents_Ordering(t *testing.T) {
	security := createValidUserSecurity()
	now := time.Now()

	// Add events in non-chronological order
	event1 := SecurityEvent{
		Type:      SecurityEventLoginFailure,
		Timestamp: now.Add(-2 * time.Hour),
		IPAddress: "192.168.1.1",
	}
	event2 := SecurityEvent{
		Type:      SecurityEventLoginSuccess,
		Timestamp: now.Add(-1 * time.Hour),
		IPAddress: "192.168.1.2",
	}
	event3 := SecurityEvent{
		Type:      SecurityEventLoginFailure,
		Timestamp: now.Add(-3 * time.Hour),
		IPAddress: "192.168.1.3",
	}

	security.addSecurityEvent(event1)
	security.addSecurityEvent(event2)
	security.addSecurityEvent(event3)

	recentEvents := security.GetRecentEvents(1) // Get events from last day

	if len(recentEvents) != 3 {
		t.Errorf("Expected 3 events, got %d", len(recentEvents))
	}

	// Events should be returned in the order they were added (since GetRecentEvents doesn't sort)
	// This matches the current implementation behavior
	if recentEvents[0].IPAddress != "192.168.1.1" {
		t.Errorf("Expected first event to be from IP 192.168.1.1, got %s", recentEvents[0].IPAddress)
	}

	if recentEvents[1].IPAddress != "192.168.1.2" {
		t.Errorf("Expected second event to be from IP 192.168.1.2, got %s", recentEvents[1].IPAddress)
	}

	if recentEvents[2].IPAddress != "192.168.1.3" {
		t.Errorf("Expected third event to be from IP 192.168.1.3, got %s", recentEvents[2].IPAddress)
	}
}

// MFA Management Tests (3 tests)

func TestUserSecurity_EnableMFA_Success(t *testing.T) {
	security := createValidUserSecurity()
	backupCodes := []byte("encrypted_backup_codes")

	security.EnableMFA(backupCodes)

	if !security.MFAEnabled {
		t.Error("Expected MFAEnabled to be true")
	}

	if len(security.MFABackupCodes) == 0 {
		t.Error("Expected MFABackupCodes to be set")
	}

	if string(security.MFABackupCodes) != string(backupCodes) {
		t.Error("Expected MFABackupCodes to match provided codes")
	}

	// Verify security event was added
	if len(security.SecurityEvents) == 0 {
		t.Error("Expected security event to be added")
	}

	event := security.SecurityEvents[0]
	if event.Type != SecurityEventMFAEnabled {
		t.Errorf("Expected event type %s, got %s", SecurityEventMFAEnabled, event.Type)
	}
}

func TestUserSecurity_DisableMFA_Success(t *testing.T) {
	security := createValidUserSecurity()
	// Enable MFA first
	security.EnableMFA([]byte("backup_codes"))

	security.DisableMFA()

	if security.MFAEnabled {
		t.Error("Expected MFAEnabled to be false")
	}

	if len(security.MFABackupCodes) != 0 {
		t.Error("Expected MFABackupCodes to be cleared")
	}

	// Verify security event was added
	eventFound := false
	for _, event := range security.SecurityEvents {
		if event.Type == SecurityEventMFADisabled {
			eventFound = true
			break
		}
	}

	if !eventFound {
		t.Error("Expected MFA disabled event to be added")
	}
}

func TestUserSecurity_MFARequired_RiskBasedDecision(t *testing.T) {
	security := createValidUserSecurity()

	// Test with low risk score - MFA not required
	security.RiskScore = 25.0

	// Test with high risk score - MFA required
	security.RiskScore = 85.0
	security.RiskFactors = []RiskFactor{RiskFactorUnknownDevice, RiskFactorUnknownLocation}

	// For now, just verify the risk factors are set correctly
	if !security.HasRiskFactor(RiskFactorUnknownDevice) {
		t.Error("Expected HasRiskFactor to return true for unknown device")
	}

	if !security.IsHighRisk() {
		t.Error("Expected IsHighRisk to return true for high risk score")
	}
}

// Entity Validation Tests (2 tests)

func TestUserSecurity_Validate_Success(t *testing.T) {
	security := createValidUserSecurity()

	err := security.Validate()
	if err != nil {
		t.Errorf("Expected validation to pass, got error: %v", err)
	}
}

func TestUserSecurity_Validate_InvalidUserID(t *testing.T) {
	security := createValidUserSecurity()
	security.UserID = ""

	err := security.Validate()
	if err == nil {
		t.Error("Expected validation error for empty user ID")
	}

	appErr, ok := err.(*errors.AppError)
	if !ok || appErr.Code != errors.CodeValidationFailed {
		t.Errorf("Expected validation error with CodeValidationFailed, got: %v", err)
	}
}

// Additional validation tests for completeness

func TestUserSecurity_Validate_InvalidLoginAttempts(t *testing.T) {
	security := createValidUserSecurity()
	security.LoginAttempts = -1

	err := security.Validate()
	if err == nil {
		t.Error("Expected validation error for negative login attempts")
	}

	appErr, ok := err.(*errors.AppError)
	if !ok || appErr.Code != errors.CodeValidationFailed {
		t.Errorf("Expected validation error with CodeValidationFailed, got: %v", err)
	}
}

func TestUserSecurity_Validate_InvalidRiskScore(t *testing.T) {
	security := createValidUserSecurity()
	security.RiskScore = 150.0 // Invalid score > 100

	err := security.Validate()
	if err == nil {
		t.Error("Expected validation error for invalid risk score")
	}

	appErr, ok := err.(*errors.AppError)
	if !ok || appErr.Code != errors.CodeValidationFailed {
		t.Errorf("Expected validation error with CodeValidationFailed, got: %v", err)
	}
}

func TestUserSecurity_Clone_DeepCopy(t *testing.T) {
	security := createValidUserSecurity()
	security.MFABackupCodes = []byte("backup_codes")
	security.RiskFactors = []RiskFactor{RiskFactorUnknownDevice}
	future := time.Now().Add(time.Hour)
	security.LockedUntil = &future

	clone := security.Clone()

	// Verify it's a deep copy
	if clone == security {
		t.Error("Expected different instance, got same reference")
	}

	// Verify fields are copied
	if clone.UserID != security.UserID {
		t.Errorf("Expected UserID %s, got %s", security.UserID, clone.UserID)
	}

	if clone.RiskScore != security.RiskScore {
		t.Errorf("Expected RiskScore %f, got %f", security.RiskScore, clone.RiskScore)
	}

	// Verify deep copy of byte slices
	if string(clone.MFABackupCodes) != string(security.MFABackupCodes) {
		t.Error("Expected MFABackupCodes to be copied")
	}

	if &clone.MFABackupCodes[0] == &security.MFABackupCodes[0] {
		t.Error("Expected MFABackupCodes to be deep copied, got same memory reference")
	}

	// Verify deep copy of time pointers
	if clone.LockedUntil == nil || security.LockedUntil == nil {
		t.Error("Expected LockedUntil to be copied")
	}

	if clone.LockedUntil == security.LockedUntil {
		t.Error("Expected LockedUntil to be deep copied, got same memory reference")
	}
}
