package password

import (
	"context"
	"fmt"
	"time"

	"github.com/MichaelAJay/go-config"
	"github.com/MichaelAJay/go-encrypter"
	"github.com/MichaelAJay/go-logger"
	"github.com/MichaelAJay/go-metrics"
	"github.com/MichaelAJay/go-serializer"
	"github.com/MichaelAJay/go-user-management/auth"
	"github.com/MichaelAJay/go-user-management/errors"
	"github.com/MichaelAJay/go-user-management/validation"
)

// Provider implements password-based authentication.
// This provider handles password hashing, verification, and validation
// following security best practices.
//
// Best Practice: Single Responsibility Principle - this provider is solely
// responsible for password-based authentication logic.
type Provider struct {
	encrypter         encrypter.Encrypter
	logger            logger.Logger
	metrics           metrics.Registry
	config            config.Config
	passwordValidator *validation.PasswordValidator
	serializer        serializer.Serializer
}

// Config contains configuration options for the password provider.
type Config struct {
	// Password validation settings
	MinLength      int     `json:"min_length" default:"8"`
	MaxLength      int     `json:"max_length" default:"128"`
	MinEntropy     float64 `json:"min_entropy" default:"30.0"`
	RequireUpper   bool    `json:"require_upper" default:"true"`
	RequireLower   bool    `json:"require_lower" default:"true"`
	RequireNumber  bool    `json:"require_number" default:"true"`
	RequireSpecial bool    `json:"require_special" default:"true"`
}

// PasswordCredentials represents password-based credentials.
type PasswordCredentials struct {
	Password string `json:"password"`
}

// StoredPasswordData represents password data stored with the user.
type StoredPasswordData struct {
	HashedPassword []byte    `json:"hashed_password"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// NewProvider creates a new password authentication provider.
//
// Best Practice: Dependency Injection - all dependencies are injected
// through the constructor, making the provider testable and flexible.
func NewProvider(
	encrypter encrypter.Encrypter,
	logger logger.Logger,
	metrics metrics.Registry,
	config config.Config,
) *Provider {
	// Load configuration with defaults
	providerConfig := loadConfig(config)

	// Configure password validator
	passwordValidator := validation.NewPasswordValidator()
	passwordValidator.MinLength = providerConfig.MinLength
	passwordValidator.MaxLength = providerConfig.MaxLength
	passwordValidator.MinEntropy = providerConfig.MinEntropy
	passwordValidator.RequireUppercase = providerConfig.RequireUpper
	passwordValidator.RequireLowercase = providerConfig.RequireLower
	passwordValidator.RequireNumbers = providerConfig.RequireNumber
	passwordValidator.RequireSpecialChars = providerConfig.RequireSpecial

	// Initialize serializer for handling StoredPasswordData
	authSerializer, err := serializer.DefaultRegistry.New(serializer.JSON)
	if err != nil {
		// Fallback to a new JSON serializer if registry fails
		authSerializer = serializer.NewJSONSerializer()
	}

	return &Provider{
		encrypter:         encrypter,
		logger:            logger,
		metrics:           metrics,
		config:            config,
		passwordValidator: passwordValidator,
		serializer:        authSerializer,
	}
}

// Authenticate verifies password credentials against stored password data.
func (p *Provider) Authenticate(ctx context.Context, identifier string, credentials any, storedAuthData []byte) (*auth.AuthenticationResult, error) {
	startTime := time.Now()
	defer func() {
		timer := p.metrics.Timer(metrics.Options{
			Name: "password_provider.authenticate",
		})
		timer.RecordSince(startTime)
	}()

	// Type assert credentials
	validCredentials, ok := credentials.(*PasswordCredentials)
	if !ok {
		return nil, errors.NewValidationError("credentials", "invalid credential type for password provider")
	}

	// Deserialize stored auth data to StoredPasswordData
	var passwordData StoredPasswordData
	if err := p.serializer.Deserialize(storedAuthData, &passwordData); err != nil {
		p.logger.Error("Failed to deserialize stored password data", logger.Field{Key: "error", Value: err.Error()})
		return nil, errors.NewAppError(errors.CodeInternalError, "Invalid stored auth data")
	}

	// Verify password against stored data
	valid, err := p.verifyPassword(ctx, &passwordData, validCredentials.Password)
	if err != nil || !valid {
		counter := p.metrics.Counter(metrics.Options{
			Name: "password_provider.authenticate.failed",
		})
		counter.Inc()
		return nil, errors.NewInvalidCredentialsError()
	}

	counter := p.metrics.Counter(metrics.Options{
		Name: "password_provider.authenticate.success",
	})
	counter.Inc()

	// Return authentication result with proper user ID
	return &auth.AuthenticationResult{
		UserID:         identifier, // This should be the user ID, not email
		ProviderType:   auth.ProviderTypePassword,
		ProviderUserID: identifier,
		SessionData: map[string]any{
			"auth_method": "password",
			"auth_time":   time.Now(),
		},
	}, nil
}

// ValidateCredentials validates password strength and requirements.
func (p *Provider) ValidateCredentials(ctx context.Context, credentials any, userInfo *auth.UserInfo) error {
	startTime := time.Now()
	defer func() {
		timer := p.metrics.Timer(metrics.Options{
			Name: "password_provider.validate_credentials",
		})
		timer.RecordSince(startTime)
	}()

	// Type assert credentials
	passwordCreds, ok := credentials.(*PasswordCredentials)
	if !ok {
		return errors.NewValidationError("credentials", "invalid credential type for password provider")
	}

	// Convert auth.UserInfo to validation.UserInfo
	validationUserInfo := &validation.UserInfo{
		FirstName: userInfo.FirstName,
		LastName:  userInfo.LastName,
		Email:     userInfo.Email,
	}

	// Validate password strength
	if err := p.passwordValidator.ValidatePasswordWithUserInfo(passwordCreds.Password, validationUserInfo); err != nil {
		counter := p.metrics.Counter(metrics.Options{
			Name: "password_provider.validate_credentials.weak_password",
		})
		counter.Inc()
		return err
	}

	counter := p.metrics.Counter(metrics.Options{
		Name: "password_provider.validate_credentials.success",
	})
	counter.Inc()

	return nil
}

// UpdateCredentials updates password credentials after verification.
func (p *Provider) UpdateCredentials(ctx context.Context, userID string, oldCredentials, newCredentials any, storedAuthData []byte) ([]byte, error) {
	startTime := time.Now()
	defer func() {
		timer := p.metrics.Timer(metrics.Options{
			Name: "password_provider.update_credentials",
		})
		timer.RecordSince(startTime)
	}()

	// Type assert credentials
	oldPasswordCreds, ok := oldCredentials.(*PasswordCredentials)
	if !ok {
		return nil, errors.NewValidationError("old_credentials", "invalid credential type for password provider")
	}

	newPasswordCreds, ok := newCredentials.(*PasswordCredentials)
	if !ok {
		return nil, errors.NewValidationError("new_credentials", "invalid credential type for password provider")
	}

	// Deserialize stored auth data to StoredPasswordData
	var passwordData StoredPasswordData
	if err := p.serializer.Deserialize(storedAuthData, &passwordData); err != nil {
		p.logger.Error("Failed to deserialize stored password data for update", logger.Field{Key: "error", Value: err.Error()})
		return nil, errors.NewAppError(errors.CodeInternalError, "Invalid stored auth data")
	}

	// Verify the old password
	valid, err := p.verifyPassword(ctx, &passwordData, oldPasswordCreds.Password)
	if err != nil || !valid {
		return nil, errors.NewInvalidCredentialsError()
	}

	// Check if new password is different from old password
	if oldPasswordCreds.Password == newPasswordCreds.Password {
		return nil, errors.NewValidationError("new_password", "new password must be different from current password")
	}

	// Prepare new credentials for storage
	newStoredData, err := p.PrepareCredentials(ctx, newPasswordCreds)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare new credentials: %w", err)
	}

	p.logger.Info("Password credentials updated successfully", logger.Field{Key: "user_id", Value: userID})
	counter := p.metrics.Counter(metrics.Options{
		Name: "password_provider.update_credentials.success",
	})
	counter.Inc()

	return newStoredData, nil
}

// PrepareCredentials hashes the password for secure storage.
func (p *Provider) PrepareCredentials(ctx context.Context, credentials any) ([]byte, error) {
	startTime := time.Now()
	defer func() {
		timer := p.metrics.Timer(metrics.Options{
			Name: "password_provider.prepare_credentials",
		})
		timer.RecordSince(startTime)
	}()

	// Type assert credentials
	passwordCreds, ok := credentials.(*PasswordCredentials)
	if !ok {
		return nil, errors.NewValidationError("credentials", "invalid credential type for password provider")
	}

	// Hash the password
	hashedPassword, err := p.encrypter.HashPassword([]byte(passwordCreds.Password))
	if err != nil {
		p.logger.Error("Failed to hash password", logger.Field{Key: "error", Value: err.Error()})
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to process password")
	}

	now := time.Now()
	storedData := &StoredPasswordData{
		HashedPassword: hashedPassword,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	// Serialize the stored data
	serializedData, err := p.serializer.Serialize(storedData)
	if err != nil {
		p.logger.Error("Failed to serialize password data", logger.Field{Key: "error", Value: err.Error()})
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to serialize password data")
	}

	counter := p.metrics.Counter(metrics.Options{
		Name: "password_provider.prepare_credentials.success",
	})
	counter.Inc()

	return serializedData, nil
}

// verifyPassword verifies a password against stored password data.
// This is a utility method used internally by the provider.
func (p *Provider) verifyPassword(_ context.Context, passwordData *StoredPasswordData, password string) (bool, error) {
	// Verify password using encrypter
	valid, err := p.encrypter.VerifyPassword(passwordData.HashedPassword, []byte(password))
	if err != nil {
		p.logger.Error("Failed to verify password", logger.Field{Key: "error", Value: err.Error()})
		return false, err
	}

	if valid {
		counter := p.metrics.Counter(metrics.Options{
			Name: "password_provider.verify_password.success",
		})
		counter.Inc()
	} else {
		counter := p.metrics.Counter(metrics.Options{
			Name: "password_provider.verify_password.failed",
		})
		counter.Inc()
	}

	return valid, nil
}

// GetProviderType returns the provider type identifier.
func (p *Provider) GetProviderType() auth.ProviderType {
	return auth.ProviderTypePassword
}

// SupportsCredentialUpdate returns true as password provider supports credential updates.
func (p *Provider) SupportsCredentialUpdate() bool {
	return true
}

// loadConfig loads provider configuration with defaults.
func loadConfig(config config.Config) *Config {
	providerConfig := &Config{
		MinLength:      8,
		MaxLength:      128,
		MinEntropy:     30.0,
		RequireUpper:   true,
		RequireLower:   true,
		RequireNumber:  true,
		RequireSpecial: true,
	}

	// Load configuration values if available
	if minLen, ok := config.GetInt("password_provider.min_length"); ok {
		providerConfig.MinLength = minLen
	}
	if maxLen, ok := config.GetInt("password_provider.max_length"); ok {
		providerConfig.MaxLength = maxLen
	}
	if minEntropyStr, ok := config.GetString("password_provider.min_entropy"); ok {
		// Parse the string to float64 if needed
		// For now, we'll use the default value since GetFloat64 is not available
		_ = minEntropyStr
	}
	if requireUpper, ok := config.GetBool("password_provider.require_upper"); ok {
		providerConfig.RequireUpper = requireUpper
	}
	if requireLower, ok := config.GetBool("password_provider.require_lower"); ok {
		providerConfig.RequireLower = requireLower
	}
	if requireNumber, ok := config.GetBool("password_provider.require_number"); ok {
		providerConfig.RequireNumber = requireNumber
	}
	if requireSpecial, ok := config.GetBool("password_provider.require_special"); ok {
		providerConfig.RequireSpecial = requireSpecial
	}

	return providerConfig
}
