package user

import (
	"encoding/json"
	"time"

	"github.com/MichaelAJay/go-user-management/errors"
)

// SecurityEventType represents different types of security events
type SecurityEventType string

const (
	SecurityEventLoginFailure       SecurityEventType = "login_failure"
	SecurityEventLoginSuccess       SecurityEventType = "login_success"
	SecurityEventAccountLocked      SecurityEventType = "account_locked"
	SecurityEventAccountUnlocked    SecurityEventType = "account_unlocked"
	SecurityEventPasswordChanged    SecurityEventType = "password_changed"
	SecurityEventSuspiciousActivity SecurityEventType = "suspicious_activity"
	SecurityEventMFAEnabled         SecurityEventType = "mfa_enabled"
	SecurityEventMFADisabled        SecurityEventType = "mfa_disabled"
)

// SecurityEvent represents a security-related event for auditing
type SecurityEvent struct {
	Type        SecurityEventType      `json:"type"`
	Timestamp   time.Time              `json:"timestamp"`
	IPAddress   string                 `json:"ip_address,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
	RiskScore   float64                `json:"risk_score,omitempty"`
	Geolocation string                 `json:"geolocation,omitempty"`
}

// RiskFactor represents different risk factors for security assessment
type RiskFactor string

const (
	RiskFactorUnknownDevice    RiskFactor = "unknown_device"
	RiskFactorUnknownLocation  RiskFactor = "unknown_location"
	RiskFactorHighFailureRate  RiskFactor = "high_failure_rate"
	RiskFactorOfficeHours      RiskFactor = "outside_office_hours"
	RiskFactorVPNConnection    RiskFactor = "vpn_connection"
	RiskFactorTorConnection    RiskFactor = "tor_connection"
	RiskFactorMultipleAttempts RiskFactor = "multiple_attempts"
	RiskFactorPasswordAge      RiskFactor = "password_age"
	RiskFactorNoMFA            RiskFactor = "no_mfa"
)

// UserSecurity represents security-related state and tracking for a user.
// This entity is separated from the User entity to focus on security concerns
// and enable different access patterns and caching strategies.
//
// Primary Key: UserID (one-to-one relationship with User)
type UserSecurity struct {
	// UserID is the foreign key reference to the User entity
	// This establishes a 1:1 relationship: User -> UserSecurity
	UserID string `json:"user_id" db:"user_id"`

	// LoginAttempts tracks consecutive failed login attempts across all authentication methods
	// Used for progressive lockout policies and security monitoring
	LoginAttempts int `json:"login_attempts" db:"login_attempts"`

	// LastFailedAt tracks when the most recent failed login attempt occurred
	// Used for time-based lockout policies and security analysis
	LastFailedAt *time.Time `json:"last_failed_at,omitempty" db:"last_failed_at"`

	// LockedUntil defines when a temporary account lock expires
	// Nil means account is not temporarily locked
	// Used for automatic unlock after time-based penalties
	LockedUntil *time.Time `json:"locked_until,omitempty" db:"locked_until"`

	// LockReason provides context for why the account was locked
	// Examples: "too_many_attempts", "suspicious_activity", "admin_action"
	LockReason string `json:"lock_reason,omitempty" db:"lock_reason"`

	// LastLoginAt tracks the most recent successful authentication
	// Used for inactive account detection and security monitoring
	LastLoginAt *time.Time `json:"last_login_at,omitempty" db:"last_login_at"`

	// LastLoginIP stores the IP address of the most recent successful login
	// Used for geolocation-based risk assessment and suspicious activity detection
	LastLoginIP string `json:"last_login_ip,omitempty" db:"last_login_ip"`

	// TotalLoginAttempts tracks lifetime failed login attempts (never reset)
	// Used for long-term security analysis and threat detection
	TotalLoginAttempts int `json:"total_login_attempts" db:"total_login_attempts"`

	// SuccessfulLogins tracks lifetime successful authentications
	// Used for user behavior analysis and security metrics
	SuccessfulLogins int `json:"successful_logins" db:"successful_logins"`

	// RiskScore represents the current calculated risk level (0.0 - 100.0)
	// Higher scores indicate higher risk, used for adaptive security measures
	RiskScore float64 `json:"risk_score" db:"risk_score"`

	// RiskFactors contains active risk factors affecting the risk score
	// Stored as JSON array for flexible risk assessment
	RiskFactors []RiskFactor `json:"risk_factors,omitempty" db:"risk_factors"`

	// SecurityEvents contains recent security events for audit trail
	// Limited to recent events to prevent unbounded growth
	SecurityEvents []SecurityEvent `json:"security_events,omitempty" db:"security_events"`

	// MFAEnabled indicates if multi-factor authentication is enabled
	// Used for risk assessment and conditional security policies
	MFAEnabled bool `json:"mfa_enabled" db:"mfa_enabled"`

	// MFABackupCodes stores encrypted backup codes for MFA recovery
	// Encrypted separately from other auth data for additional security
	MFABackupCodes []byte `json:"-" db:"mfa_backup_codes"`

	// CreatedAt tracks when this security record was created
	CreatedAt time.Time `json:"created_at" db:"created_at"`

	// UpdatedAt tracks when this security record was last modified
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`

	// Version enables optimistic locking for concurrent security updates
	Version int64 `json:"version" db:"version"`
}

// NewUserSecurity creates a new UserSecurity instance with default values
func NewUserSecurity(userID string) *UserSecurity {
	now := time.Now()
	return &UserSecurity{
		UserID:             userID,
		LoginAttempts:      0,
		TotalLoginAttempts: 0,
		SuccessfulLogins:   0,
		RiskScore:          0.0,
		RiskFactors:        make([]RiskFactor, 0),
		SecurityEvents:     make([]SecurityEvent, 0),
		MFAEnabled:         false,
		CreatedAt:          now,
		UpdatedAt:          now,
		Version:            1,
	}
}

// IsLocked returns true if the account is currently locked (temporary or permanent)
func (us *UserSecurity) IsLocked() bool {
	// Check temporary lock
	return us.LockedUntil != nil && time.Now().Before(*us.LockedUntil)
}

// ProcessFailedAttempt increments failure counters and applies lockout logic
func (us *UserSecurity) ProcessFailedAttempt(maxAttempts int, lockDuration time.Duration, ipAddress string) {
	us.LoginAttempts++
	us.TotalLoginAttempts++

	now := time.Now()
	us.LastFailedAt = &now

	// Apply lockout if max attempts reached
	if us.LoginAttempts >= maxAttempts {
		lockUntil := now.Add(lockDuration)
		us.LockedUntil = &lockUntil
		us.LockReason = "too_many_attempts"
	}

	// Add security event
	event := SecurityEvent{
		Type:      SecurityEventLoginFailure,
		Timestamp: now,
		IPAddress: ipAddress,
		Details: map[string]interface{}{
			"attempt_count":  us.LoginAttempts,
			"total_attempts": us.TotalLoginAttempts,
		},
	}
	us.addSecurityEvent(event)
	us.updateMetadata()
}

// ProcessSuccessfulLogin resets failure counters and updates login tracking
func (us *UserSecurity) ProcessSuccessfulLogin(ipAddress string) {
	us.LoginAttempts = 0
	us.SuccessfulLogins++
	us.LockedUntil = nil
	us.LockReason = ""

	now := time.Now()
	us.LastLoginAt = &now
	us.LastLoginIP = ipAddress

	// Add security event
	event := SecurityEvent{
		Type:      SecurityEventLoginSuccess,
		Timestamp: now,
		IPAddress: ipAddress,
		Details: map[string]interface{}{
			"successful_login_count": us.SuccessfulLogins,
		},
	}
	us.addSecurityEvent(event)
	us.updateMetadata()
}

// LockAccount manually locks the account with a reason
func (us *UserSecurity) LockAccount(until *time.Time, reason string) {
	us.LockedUntil = until
	us.LockReason = reason

	event := SecurityEvent{
		Type:      SecurityEventAccountLocked,
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"reason": reason,
			"until":  until,
		},
	}
	us.addSecurityEvent(event)
	us.updateMetadata()
}

// UnlockAccount removes any account locks
func (us *UserSecurity) UnlockAccount() {
	us.LockedUntil = nil
	us.LockReason = ""
	us.LoginAttempts = 0

	event := SecurityEvent{
		Type:      SecurityEventAccountUnlocked,
		Timestamp: time.Now(),
	}
	us.addSecurityEvent(event)
	us.updateMetadata()
}

// UpdateRiskScore updates the risk score and associated factors
func (us *UserSecurity) UpdateRiskScore(score float64, factors []RiskFactor) error {
	if score < 0.0 || score > 100.0 {
		return errors.NewValidationError("risk_score", "risk score must be between 0.0 and 100.0")
	}

	us.RiskScore = score
	us.RiskFactors = factors
	us.updateMetadata()
	return nil
}

// AddRiskFactor adds a risk factor if not already present
func (us *UserSecurity) AddRiskFactor(factor RiskFactor) {
	for _, existing := range us.RiskFactors {
		if existing == factor {
			return // Already exists
		}
	}
	us.RiskFactors = append(us.RiskFactors, factor)
	us.updateMetadata()
}

// RemoveRiskFactor removes a specific risk factor
func (us *UserSecurity) RemoveRiskFactor(factor RiskFactor) {
	for i, existing := range us.RiskFactors {
		if existing == factor {
			us.RiskFactors = append(us.RiskFactors[:i], us.RiskFactors[i+1:]...)
			break
		}
	}
	us.updateMetadata()
}

// EnableMFA enables multi-factor authentication
func (us *UserSecurity) EnableMFA(encryptedBackupCodes []byte) {
	us.MFAEnabled = true
	us.MFABackupCodes = encryptedBackupCodes

	event := SecurityEvent{
		Type:      SecurityEventMFAEnabled,
		Timestamp: time.Now(),
	}
	us.addSecurityEvent(event)
	us.updateMetadata()
}

// DisableMFA disables multi-factor authentication
func (us *UserSecurity) DisableMFA() {
	us.MFAEnabled = false
	us.MFABackupCodes = nil

	event := SecurityEvent{
		Type:      SecurityEventMFADisabled,
		Timestamp: time.Now(),
	}
	us.addSecurityEvent(event)
	us.updateMetadata()
}

// IsHighRisk returns true if the user is considered high risk
func (us *UserSecurity) IsHighRisk() bool {
	return us.RiskScore >= 75.0
}

// HasRiskFactor checks if a specific risk factor is present
func (us *UserSecurity) HasRiskFactor(factor RiskFactor) bool {
	for _, existing := range us.RiskFactors {
		if existing == factor {
			return true
		}
	}
	return false
}

// GetRecentEvents returns security events from the last N days
func (us *UserSecurity) GetRecentEvents(days int) []SecurityEvent {
	cutoff := time.Now().AddDate(0, 0, -days)
	var recent []SecurityEvent

	for _, event := range us.SecurityEvents {
		if event.Timestamp.After(cutoff) {
			recent = append(recent, event)
		}
	}
	return recent
}

// addSecurityEvent adds a security event and maintains a reasonable limit
func (us *UserSecurity) addSecurityEvent(event SecurityEvent) {
	us.SecurityEvents = append(us.SecurityEvents, event)

	// Keep only last 100 events to prevent unbounded growth
	const maxEvents = 100
	if len(us.SecurityEvents) > maxEvents {
		us.SecurityEvents = us.SecurityEvents[len(us.SecurityEvents)-maxEvents:]
	}
}

// Validate performs comprehensive validation on the UserSecurity entity
func (us *UserSecurity) Validate() error {
	if us.UserID == "" {
		return errors.NewValidationError("user_id", "user ID is required")
	}

	if us.LoginAttempts < 0 {
		return errors.NewValidationError("login_attempts", "login attempts cannot be negative")
	}

	if us.TotalLoginAttempts < 0 {
		return errors.NewValidationError("total_login_attempts", "total login attempts cannot be negative")
	}

	if us.SuccessfulLogins < 0 {
		return errors.NewValidationError("successful_logins", "successful logins cannot be negative")
	}

	if us.RiskScore < 0.0 || us.RiskScore > 100.0 {
		return errors.NewValidationError("risk_score", "risk score must be between 0.0 and 100.0")
	}

	if us.Version <= 0 {
		return errors.NewValidationError("version", "version must be positive")
	}

	return nil
}

// Clone creates a deep copy of the UserSecurity for safe concurrent operations
func (us *UserSecurity) Clone() *UserSecurity {
	clone := *us

	// Deep copy time pointers
	if us.LastFailedAt != nil {
		lastFailedAt := *us.LastFailedAt
		clone.LastFailedAt = &lastFailedAt
	}

	if us.LockedUntil != nil {
		lockedUntil := *us.LockedUntil
		clone.LockedUntil = &lockedUntil
	}

	if us.LastLoginAt != nil {
		lastLoginAt := *us.LastLoginAt
		clone.LastLoginAt = &lastLoginAt
	}

	// Deep copy slices
	if us.RiskFactors != nil {
		clone.RiskFactors = make([]RiskFactor, len(us.RiskFactors))
		copy(clone.RiskFactors, us.RiskFactors)
	}

	if us.SecurityEvents != nil {
		clone.SecurityEvents = make([]SecurityEvent, len(us.SecurityEvents))
		copy(clone.SecurityEvents, us.SecurityEvents)
	}

	if us.MFABackupCodes != nil {
		clone.MFABackupCodes = make([]byte, len(us.MFABackupCodes))
		copy(clone.MFABackupCodes, us.MFABackupCodes)
	}

	return &clone
}

// ToJSON converts risk factors to JSON for storage
// TODO: Use go-serializer
func (us *UserSecurity) RiskFactorsJSON() ([]byte, error) {
	return json.Marshal(us.RiskFactors)
}

// FromJSON loads risk factors from JSON
// TODO: Use go-serializer
func (us *UserSecurity) LoadRiskFactorsFromJSON(data []byte) error {
	return json.Unmarshal(data, &us.RiskFactors)
}

// SecurityEventsJSON converts security events to JSON for storage
// TODO: Use go-serializer
func (us *UserSecurity) SecurityEventsJSON() ([]byte, error) {
	return json.Marshal(us.SecurityEvents)
}

// LoadSecurityEventsFromJSON loads security events from JSON
// TODO: Use go-serializer
func (us *UserSecurity) LoadSecurityEventsFromJSON(data []byte) error {
	return json.Unmarshal(data, &us.SecurityEvents)
}

// updateMetadata ensures consistent metadata updates for all state changes
// This private helper centralizes version increment and timestamp updates
func (us *UserSecurity) updateMetadata() {
	us.UpdatedAt = time.Now()
	us.Version++
}
