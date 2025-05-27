package user

import (
	"context"
	"fmt"
	"time"

	"github.com/MichaelAJay/go-cache"
	"github.com/MichaelAJay/go-config"
	"github.com/MichaelAJay/go-encrypter"
	"github.com/MichaelAJay/go-logger"
	"github.com/MichaelAJay/go-metrics"
	"github.com/MichaelAJay/go-user-management/errors"
	"github.com/MichaelAJay/go-user-management/validation"
)

// UserService provides the business logic for user management operations.
// It orchestrates validation, encryption, repository operations, and caching.
type UserService interface {
	// CreateUser creates a new user account
	CreateUser(ctx context.Context, req *CreateUserRequest) (*UserResponse, error)

	// AuthenticateUser authenticates a user with email and password
	AuthenticateUser(ctx context.Context, req *AuthenticateRequest) (*AuthenticationResponse, error)

	// GetUserByID retrieves a user by their ID
	GetUserByID(ctx context.Context, userID string) (*UserResponse, error)

	// GetUserByEmail retrieves a user by their email address
	GetUserByEmail(ctx context.Context, email string) (*UserResponse, error)

	// UpdateProfile updates user profile information
	UpdateProfile(ctx context.Context, userID string, req *UpdateProfileRequest) (*UserResponse, error)

	// UpdatePassword updates a user's password
	UpdatePassword(ctx context.Context, userID string, req *UpdatePasswordRequest) error

	// ActivateUser activates a user account (typically after email verification)
	ActivateUser(ctx context.Context, userID string) (*UserResponse, error)

	// SuspendUser suspends a user account
	SuspendUser(ctx context.Context, userID string, reason string) (*UserResponse, error)

	// DeactivateUser deactivates a user account
	DeactivateUser(ctx context.Context, userID string, reason string) (*UserResponse, error)

	// LockUser locks a user account
	LockUser(ctx context.Context, userID string, until *time.Time, reason string) (*UserResponse, error)

	// UnlockUser unlocks a user account
	UnlockUser(ctx context.Context, userID string) (*UserResponse, error)

	// ListUsers retrieves users with pagination and filtering
	ListUsers(ctx context.Context, req *ListUsersRequest) (*ListUsersResponse, error)

	// GetUserStats retrieves user statistics
	GetUserStats(ctx context.Context) (*UserStatsResponse, error)

	// DeleteUser deletes a user account
	DeleteUser(ctx context.Context, userID string) error
}

// userService implements the UserService interface.
type userService struct {
	repository        UserRepository
	encrypter         encrypter.Encrypter
	logger            logger.Logger
	cache             cache.Cache
	config            config.Config
	metrics           metrics.Registry
	emailValidator    *validation.EmailValidator
	passwordValidator *validation.PasswordValidator
}

// ServiceConfig contains configuration for the UserService.
type ServiceConfig struct {
	// Cache settings
	CacheUserTTL   time.Duration `json:"cache_user_ttl" default:"15m"`
	CacheStatseTTL time.Duration `json:"cache_stats_ttl" default:"5m"`

	// Account lockout settings
	MaxLoginAttempts int           `json:"max_login_attempts" default:"5"`
	LockoutDuration  time.Duration `json:"lockout_duration" default:"30m"`

	// Rate limiting
	EnableRateLimit      bool          `json:"enable_rate_limit" default:"true"`
	RateLimitWindow      time.Duration `json:"rate_limit_window" default:"1h"`
	RateLimitMaxAttempts int           `json:"rate_limit_max_attempts" default:"10"`

	// Email validation settings
	AllowDisposableEmails bool     `json:"allow_disposable_emails" default:"false"`
	AllowedEmailDomains   []string `json:"allowed_email_domains"`
	BlockedEmailDomains   []string `json:"blocked_email_domains"`

	// Password validation settings
	PasswordMinLength      int     `json:"password_min_length" default:"8"`
	PasswordMaxLength      int     `json:"password_max_length" default:"128"`
	PasswordMinEntropy     float64 `json:"password_min_entropy" default:"30.0"`
	RequirePasswordUpper   bool    `json:"require_password_upper" default:"true"`
	RequirePasswordLower   bool    `json:"require_password_lower" default:"true"`
	RequirePasswordNumber  bool    `json:"require_password_number" default:"true"`
	RequirePasswordSpecial bool    `json:"require_password_special" default:"true"`
}

// NewUserService creates a new UserService instance with the provided dependencies.
func NewUserService(
	repository UserRepository,
	encrypter encrypter.Encrypter,
	logger logger.Logger,
	cache cache.Cache,
	config config.Config,
	metrics metrics.Registry,
) UserService {
	// Load service configuration
	serviceConfig := &ServiceConfig{}
	// Note: Using Get methods since config.Config doesn't have Unmarshal
	if ttl, ok := config.GetString("user_service.cache_user_ttl"); ok {
		if parsed, err := time.ParseDuration(ttl); err == nil {
			serviceConfig.CacheUserTTL = parsed
		}
	}
	if serviceConfig.CacheUserTTL == 0 {
		serviceConfig.CacheUserTTL = 15 * time.Minute
	}

	// Configure email validator
	emailValidator := validation.NewEmailValidator()
	emailValidator.AllowDisposableEmails = serviceConfig.AllowDisposableEmails
	emailValidator.AllowedDomains = serviceConfig.AllowedEmailDomains
	emailValidator.BlockedDomains = serviceConfig.BlockedEmailDomains

	// Configure password validator
	passwordValidator := validation.NewPasswordValidator()
	passwordValidator.MinLength = serviceConfig.PasswordMinLength
	passwordValidator.MaxLength = serviceConfig.PasswordMaxLength
	passwordValidator.MinEntropy = serviceConfig.PasswordMinEntropy
	passwordValidator.RequireUppercase = serviceConfig.RequirePasswordUpper
	passwordValidator.RequireLowercase = serviceConfig.RequirePasswordLower
	passwordValidator.RequireNumbers = serviceConfig.RequirePasswordNumber
	passwordValidator.RequireSpecialChars = serviceConfig.RequirePasswordSpecial

	return &userService{
		repository:        repository,
		encrypter:         encrypter,
		logger:            logger,
		cache:             cache,
		config:            config,
		metrics:           metrics,
		emailValidator:    emailValidator,
		passwordValidator: passwordValidator,
	}
}

// CreateUser creates a new user account with validation and encryption.
func (s *userService) CreateUser(ctx context.Context, req *CreateUserRequest) (*UserResponse, error) {
	startTime := time.Now()
	defer func() {
		timer := s.metrics.Timer(metrics.Options{
			Name: "user_service.create_user",
		})
		timer.RecordSince(startTime)
	}()

	s.logger.Info("Creating new user", logger.Field{Key: "email", Value: req.Email})

	// Validate request
	if err := s.validateCreateUserRequest(req); err != nil {
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.create_user.validation_error",
		})
		counter.Inc()
		return nil, err
	}

	// Normalize and validate email
	normalizedEmail := s.emailValidator.NormalizeEmail(req.Email)
	if err := s.emailValidator.ValidateEmail(normalizedEmail); err != nil {
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.create_user.email_validation_error",
		})
		counter.Inc()
		return nil, err
	}

	// Validate password
	userInfo := &validation.UserInfo{
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Email:     normalizedEmail,
	}
	if err := s.passwordValidator.ValidatePasswordWithUserInfo(req.Password, userInfo); err != nil {
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.create_user.password_validation_error",
		})
		counter.Inc()
		return nil, err
	}

	// Hash email for lookup
	hashedEmail := s.encrypter.HashLookupData([]byte(normalizedEmail))

	// Check if user already exists
	if _, err := s.repository.GetByHashedEmail(ctx, string(hashedEmail)); err == nil {
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.create_user.duplicate_email",
		})
		counter.Inc()
		return nil, errors.NewDuplicateEmailError(req.Email)
	} else if !errors.IsErrorType(err, errors.ErrUserNotFound) {
		s.logger.Error("Failed to check existing user", logger.Field{Key: "error", Value: err.Error()})
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to check existing user")
	}

	// Encrypt PII fields
	encryptedFirstName, err := s.encrypter.Encrypt([]byte(req.FirstName))
	if err != nil {
		s.logger.Error("Failed to encrypt first name", logger.Field{Key: "error", Value: err.Error()})
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to process user data")
	}

	encryptedLastName, err := s.encrypter.Encrypt([]byte(req.LastName))
	if err != nil {
		s.logger.Error("Failed to encrypt last name", logger.Field{Key: "error", Value: err.Error()})
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to process user data")
	}

	encryptedEmail, err := s.encrypter.Encrypt([]byte(normalizedEmail))
	if err != nil {
		s.logger.Error("Failed to encrypt email", logger.Field{Key: "error", Value: err.Error()})
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to process user data")
	}

	// Hash password
	hashedPassword, err := s.encrypter.HashPassword([]byte(req.Password))
	if err != nil {
		s.logger.Error("Failed to hash password", logger.Field{Key: "error", Value: err.Error()})
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to process password")
	}

	// Create user entity
	user := NewUser(req.FirstName, req.LastName, normalizedEmail, string(hashedEmail), hashedPassword)
	user.FirstName = encryptedFirstName
	user.LastName = encryptedLastName
	user.Email = encryptedEmail

	// Store user in repository
	if err := s.repository.Create(ctx, user); err != nil {
		s.logger.Error("Failed to create user in repository",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: user.ID})
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.create_user.repository_error",
		})
		counter.Inc()
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to create user")
	}

	// Cache user data
	s.cacheUser(ctx, user)

	s.logger.Info("User created successfully",
		logger.Field{Key: "user_id", Value: user.ID},
		logger.Field{Key: "email", Value: normalizedEmail})
	counter := s.metrics.Counter(metrics.Options{
		Name: "user_service.create_user.success",
	})
	counter.Inc()

	return user.ToUserResponse(), nil
}

// AuthenticateUser authenticates a user with email and password.
func (s *userService) AuthenticateUser(ctx context.Context, req *AuthenticateRequest) (*AuthenticationResponse, error) {
	startTime := time.Now()
	defer func() {
		timer := s.metrics.Timer(metrics.Options{
			Name: "user_service.authenticate_user",
		})
		timer.RecordSince(startTime)
	}()

	// Normalize email
	normalizedEmail := s.emailValidator.NormalizeEmail(req.Email)

	// Hash email for lookup
	hashedEmail := s.encrypter.HashLookupData([]byte(normalizedEmail))

	// Check rate limiting
	if err := s.checkRateLimit(ctx, string(hashedEmail)); err != nil {
		return nil, err
	}

	// Get user by hashed email
	user, err := s.repository.GetByHashedEmail(ctx, string(hashedEmail))
	if err != nil {
		if errors.IsErrorType(err, errors.ErrUserNotFound) {
			counter := s.metrics.Counter(metrics.Options{
				Name: "user_service.authenticate_user.user_not_found",
			})
			counter.Inc()
			return nil, errors.NewInvalidCredentialsError()
		}
		s.logger.Error("Failed to retrieve user for authentication", logger.Field{Key: "error", Value: err.Error()})
		return nil, errors.NewAppError(errors.CodeInternalError, "Authentication failed")
	}

	// Check if user can authenticate
	if !user.CanAuthenticate() {
		s.logger.Warn("Authentication attempt for non-authenticatable user",
			logger.Field{Key: "user_id", Value: user.ID},
			logger.Field{Key: "status", Value: user.Status.String()},
			logger.Field{Key: "is_locked", Value: user.IsLocked()})
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.authenticate_user.account_locked",
		})
		counter.Inc()

		if user.IsLocked() {
			var lockMessage string
			if user.LockedUntil != nil {
				lockMessage = user.LockedUntil.Format(time.RFC3339)
			}
			return nil, errors.NewAccountLockedError(lockMessage)
		}

		return nil, errors.NewAppError(errors.CodeAccountNotActivated, "Account is not active")
	}

	// Verify password - note the parameter order: password first, then hash
	if valid, err := s.encrypter.VerifyPassword(user.Password, []byte(req.Password)); err != nil || !valid {
		// Increment login attempts
		user.IncrementLoginAttempts()

		// Check if account should be locked
		config := &ServiceConfig{}
		// Load config values with defaults
		if maxAttempts, ok := s.config.GetInt("user_service.max_login_attempts"); ok {
			config.MaxLoginAttempts = maxAttempts
		} else {
			config.MaxLoginAttempts = 5
		}
		if lockoutStr, ok := s.config.GetString("user_service.lockout_duration"); ok {
			if parsed, parseErr := time.ParseDuration(lockoutStr); parseErr == nil {
				config.LockoutDuration = parsed
			} else {
				config.LockoutDuration = 30 * time.Minute
			}
		} else {
			config.LockoutDuration = 30 * time.Minute
		}

		if user.LoginAttempts >= config.MaxLoginAttempts {
			lockUntil := time.Now().Add(config.LockoutDuration)
			user.LockAccount(&lockUntil)

			s.logger.Warn("Account locked due to excessive failed login attempts",
				logger.Field{Key: "user_id", Value: user.ID},
				logger.Field{Key: "attempts", Value: user.LoginAttempts},
				logger.Field{Key: "locked_until", Value: lockUntil})
		}

		// Update user in repository
		s.repository.Update(ctx, user)

		s.logger.Warn("Invalid password for user authentication",
			logger.Field{Key: "user_id", Value: user.ID},
			logger.Field{Key: "attempts", Value: user.LoginAttempts})
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.authenticate_user.invalid_password",
		})
		counter.Inc()

		return nil, errors.NewInvalidCredentialsError()
	}

	// Reset login attempts on successful authentication
	// Clone the user to avoid race conditions when multiple goroutines authenticate the same user
	userCopy := user.Clone()
	userCopy.ResetLoginAttempts()
	userCopy.UpdateLastLogin()

	// Update user in repository
	if err := s.repository.Update(ctx, userCopy); err != nil {
		s.logger.Error("Failed to update user after successful authentication",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: userCopy.ID})
		// Continue despite error as authentication was successful
	}

	// Update cache with the modified copy
	s.cacheUser(ctx, userCopy)

	s.logger.Info("User authenticated successfully", logger.Field{Key: "user_id", Value: userCopy.ID})
	counter := s.metrics.Counter(metrics.Options{
		Name: "user_service.authenticate_user.success",
	})
	counter.Inc()

	return &AuthenticationResponse{
		User:    userCopy.ToUserResponse(),
		Message: "Authentication successful",
	}, nil
}

// GetUserByID retrieves a user by their ID.
func (s *userService) GetUserByID(ctx context.Context, userID string) (*UserResponse, error) {
	startTime := time.Now()
	defer func() {
		timer := s.metrics.Timer(metrics.Options{
			Name: "user_service.get_user_by_id",
		})
		timer.RecordSince(startTime)
	}()

	// Validate user ID
	if err := validation.ValidateID(userID, "user_id"); err != nil {
		return nil, err
	}

	// Try cache first
	if user := s.getCachedUser(ctx, userID); user != nil {
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.get_user_by_id.cache_hit",
		})
		counter.Inc()
		return user.ToUserResponse(), nil
	}

	// Get from repository
	user, err := s.repository.GetByID(ctx, userID)
	if err != nil {
		if errors.IsErrorType(err, errors.ErrUserNotFound) {
			counter := s.metrics.Counter(metrics.Options{
				Name: "user_service.get_user_by_id.not_found",
			})
			counter.Inc()
			return nil, errors.NewUserNotFoundError(userID)
		}
		s.logger.Error("Failed to retrieve user by ID",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: userID})
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to retrieve user")
	}

	// Cache user
	s.cacheUser(ctx, user)
	counter := s.metrics.Counter(metrics.Options{
		Name: "user_service.get_user_by_id.success",
	})
	counter.Inc()

	return user.ToUserResponse(), nil
}

// validateCreateUserRequest validates the create user request.
func (s *userService) validateCreateUserRequest(req *CreateUserRequest) error {
	if req == nil {
		return errors.NewValidationError("request", "request is required")
	}

	// Validate first name
	if err := validation.ValidateName(req.FirstName, "first_name"); err != nil {
		return err
	}

	// Validate last name
	if err := validation.ValidateName(req.LastName, "last_name"); err != nil {
		return err
	}

	// Basic email validation (detailed validation happens later)
	if req.Email == "" {
		return errors.NewValidationError("email", "email is required")
	}

	// Basic password validation (detailed validation happens later)
	if req.Password == "" {
		return errors.NewValidationError("password", "password is required")
	}

	return nil
}

// checkRateLimit checks if the request should be rate limited.
func (s *userService) checkRateLimit(ctx context.Context, identifier string) error {
	config := &ServiceConfig{}
	// Load config with defaults
	if enabled, ok := s.config.GetBool("user_service.enable_rate_limit"); ok {
		config.EnableRateLimit = enabled
	} else {
		config.EnableRateLimit = true
	}

	if !config.EnableRateLimit {
		return nil
	}

	// Load other rate limit config
	if windowStr, ok := s.config.GetString("user_service.rate_limit_window"); ok {
		if parsed, err := time.ParseDuration(windowStr); err == nil {
			config.RateLimitWindow = parsed
		} else {
			config.RateLimitWindow = time.Hour
		}
	} else {
		config.RateLimitWindow = time.Hour
	}

	if maxAttempts, ok := s.config.GetInt("user_service.rate_limit_max_attempts"); ok {
		config.RateLimitMaxAttempts = maxAttempts
	} else {
		config.RateLimitMaxAttempts = 10
	}

	key := fmt.Sprintf("rate_limit:auth:%s", identifier)
	attempts, _, err := s.cache.Get(ctx, key)
	if err != nil && !errors.IsErrorType(err, errors.ErrCacheMiss) {
		// Cache error, continue without rate limiting
		return nil
	}

	var attemptCount int
	if attempts != nil {
		if count, ok := attempts.(int); ok {
			attemptCount = count
		}
	}

	if attemptCount >= config.RateLimitMaxAttempts {
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.rate_limit_exceeded",
		})
		counter.Inc()
		return errors.NewAppError(errors.CodeRateLimitExceeded, "Too many authentication attempts")
	}

	// Increment counter
	s.cache.Set(ctx, key, attemptCount+1, config.RateLimitWindow)
	return nil
}

// cacheUser stores user data in cache.
func (s *userService) cacheUser(ctx context.Context, user *User) {
	config := &ServiceConfig{}
	// Load cache TTL with default
	if ttlStr, ok := s.config.GetString("user_service.cache_user_ttl"); ok {
		if parsed, err := time.ParseDuration(ttlStr); err == nil {
			config.CacheUserTTL = parsed
		} else {
			config.CacheUserTTL = 15 * time.Minute
		}
	} else {
		config.CacheUserTTL = 15 * time.Minute
	}

	key := fmt.Sprintf("user:%s", user.ID)
	if err := s.cache.Set(ctx, key, user, config.CacheUserTTL); err != nil {
		s.logger.Warn("Failed to cache user",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: user.ID})
	}
}

// getCachedUser retrieves user data from cache.
func (s *userService) getCachedUser(ctx context.Context, userID string) *User {
	key := fmt.Sprintf("user:%s", userID)
	cached, _, err := s.cache.Get(ctx, key)
	if err != nil {
		return nil
	}

	if user, ok := cached.(*User); ok {
		return user
	}
	return nil
}

// GetUserByEmail retrieves a user by their email address.
func (s *userService) GetUserByEmail(ctx context.Context, email string) (*UserResponse, error) {
	startTime := time.Now()
	defer func() {
		timer := s.metrics.Timer(metrics.Options{
			Name: "user_service.get_user_by_email",
		})
		timer.RecordSince(startTime)
	}()

	// Validate email
	if email == "" {
		return nil, errors.NewValidationError("email", "email is required")
	}

	// Normalize email
	normalizedEmail := s.emailValidator.NormalizeEmail(email)

	// Hash email for lookup
	hashedEmail := s.encrypter.HashLookupData([]byte(normalizedEmail))

	// Get from repository
	user, err := s.repository.GetByHashedEmail(ctx, string(hashedEmail))
	if err != nil {
		if errors.IsErrorType(err, errors.ErrUserNotFound) {
			counter := s.metrics.Counter(metrics.Options{
				Name: "user_service.get_user_by_email.not_found",
			})
			counter.Inc()
			return nil, errors.NewUserNotFoundError(normalizedEmail)
		}
		s.logger.Error("Failed to retrieve user by email",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "email", Value: normalizedEmail})
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to retrieve user")
	}

	// Cache user
	s.cacheUser(ctx, user)
	counter := s.metrics.Counter(metrics.Options{
		Name: "user_service.get_user_by_email.success",
	})
	counter.Inc()

	return user.ToUserResponse(), nil
}

// UpdateProfile updates user profile information.
func (s *userService) UpdateProfile(ctx context.Context, userID string, req *UpdateProfileRequest) (*UserResponse, error) {
	startTime := time.Now()
	defer func() {
		timer := s.metrics.Timer(metrics.Options{
			Name: "user_service.update_profile",
		})
		timer.RecordSince(startTime)
	}()

	s.logger.Info("Updating user profile", logger.Field{Key: "user_id", Value: userID})

	// Validate user ID
	if err := validation.ValidateID(userID, "user_id"); err != nil {
		return nil, err
	}

	// Validate request
	if req == nil || req.IsEmpty() {
		return nil, errors.NewValidationError("request", "no fields to update")
	}

	// Get current user
	user, err := s.repository.GetByID(ctx, userID)
	if err != nil {
		if errors.IsErrorType(err, errors.ErrUserNotFound) {
			return nil, errors.NewUserNotFoundError(userID)
		}
		s.logger.Error("Failed to retrieve user for profile update",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: userID})
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to retrieve user")
	}

	// Check if user can be updated
	if user.Status == UserStatusDeactivated {
		return nil, errors.NewAppError(errors.CodeUserDeactivated, "Cannot update deactivated user")
	}

	// Clone the user to avoid race conditions when multiple goroutines update the same user
	userCopy := user.Clone()

	// Track if email is being changed for additional validation
	emailChanged := false

	// Update first name if provided
	if req.FirstName != nil {
		if err := validation.ValidateName(*req.FirstName, "first_name"); err != nil {
			return nil, err
		}
		encryptedFirstName, err := s.encrypter.Encrypt([]byte(*req.FirstName))
		if err != nil {
			s.logger.Error("Failed to encrypt first name", logger.Field{Key: "error", Value: err.Error()})
			return nil, errors.NewAppError(errors.CodeInternalError, "Failed to process user data")
		}
		userCopy.FirstName = encryptedFirstName
	}

	// Update last name if provided
	if req.LastName != nil {
		if err := validation.ValidateName(*req.LastName, "last_name"); err != nil {
			return nil, err
		}
		encryptedLastName, err := s.encrypter.Encrypt([]byte(*req.LastName))
		if err != nil {
			s.logger.Error("Failed to encrypt last name", logger.Field{Key: "error", Value: err.Error()})
			return nil, errors.NewAppError(errors.CodeInternalError, "Failed to process user data")
		}
		userCopy.LastName = encryptedLastName
	}

	// Update email if provided
	if req.Email != nil {
		emailChanged = true
		normalizedEmail := s.emailValidator.NormalizeEmail(*req.Email)

		// Validate email
		if err := s.emailValidator.ValidateEmail(normalizedEmail); err != nil {
			return nil, err
		}

		// Hash email for lookup
		newHashedEmail := s.encrypter.HashLookupData([]byte(normalizedEmail))

		// Check if new email already exists (but not for the same user)
		if existingUser, err := s.repository.GetByHashedEmail(ctx, string(newHashedEmail)); err == nil {
			if existingUser.ID != userID {
				counter := s.metrics.Counter(metrics.Options{
					Name: "user_service.update_profile.duplicate_email",
				})
				counter.Inc()
				return nil, errors.NewDuplicateEmailError(*req.Email)
			}
		} else if !errors.IsErrorType(err, errors.ErrUserNotFound) {
			s.logger.Error("Failed to check existing email", logger.Field{Key: "error", Value: err.Error()})
			return nil, errors.NewAppError(errors.CodeInternalError, "Failed to validate email")
		}

		// Encrypt new email
		encryptedEmail, err := s.encrypter.Encrypt([]byte(normalizedEmail))
		if err != nil {
			s.logger.Error("Failed to encrypt email", logger.Field{Key: "error", Value: err.Error()})
			return nil, errors.NewAppError(errors.CodeInternalError, "Failed to process email")
		}

		userCopy.Email = encryptedEmail
		userCopy.HashedEmail = string(newHashedEmail)

		// If email changed, user needs to verify new email
		if userCopy.Status == UserStatusActive {
			userCopy.Status = UserStatusPendingVerification
		}
	}

	// Update timestamps
	userCopy.UpdatedAt = time.Now()

	// Save updated user
	if err := s.repository.Update(ctx, userCopy); err != nil {
		if errors.IsErrorType(err, errors.ErrVersionMismatch) {
			return nil, errors.NewVersionMismatchError(userCopy.Version, userCopy.Version)
		}
		s.logger.Error("Failed to update user profile",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: userID})
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.update_profile.repository_error",
		})
		counter.Inc()
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to update user")
	}

	// Update cache
	s.cacheUser(ctx, userCopy)

	s.logger.Info("User profile updated successfully",
		logger.Field{Key: "user_id", Value: userID},
		logger.Field{Key: "email_changed", Value: emailChanged})
	counter := s.metrics.Counter(metrics.Options{
		Name: "user_service.update_profile.success",
	})
	counter.Inc()

	return userCopy.ToUserResponse(), nil
}

// UpdatePassword updates a user's password.
func (s *userService) UpdatePassword(ctx context.Context, userID string, req *UpdatePasswordRequest) error {
	startTime := time.Now()
	defer func() {
		timer := s.metrics.Timer(metrics.Options{
			Name: "user_service.update_password",
		})
		timer.RecordSince(startTime)
	}()

	s.logger.Info("Updating user password", logger.Field{Key: "user_id", Value: userID})

	// Validate user ID
	if err := validation.ValidateID(userID, "user_id"); err != nil {
		return err
	}

	// Validate request
	if req == nil {
		return errors.NewValidationError("request", "request is required")
	}
	if req.CurrentPassword == "" {
		return errors.NewValidationError("current_password", "current password is required")
	}
	if req.NewPassword == "" {
		return errors.NewValidationError("new_password", "new password is required")
	}

	// Get current user
	user, err := s.repository.GetByID(ctx, userID)
	if err != nil {
		if errors.IsErrorType(err, errors.ErrUserNotFound) {
			return errors.NewUserNotFoundError(userID)
		}
		s.logger.Error("Failed to retrieve user for password update",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: userID})
		return errors.NewAppError(errors.CodeInternalError, "Failed to retrieve user")
	}

	// Check if user can update password
	if user.Status == UserStatusDeactivated {
		return errors.NewAppError(errors.CodeUserDeactivated, "Cannot update password for deactivated user")
	}

	// Verify current password
	if valid, err := s.encrypter.VerifyPassword(user.Password, []byte(req.CurrentPassword)); err != nil || !valid {
		s.logger.Warn("Invalid current password for password update",
			logger.Field{Key: "user_id", Value: userID})
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.update_password.invalid_current_password",
		})
		counter.Inc()
		return errors.NewAppError(errors.CodeInvalidCredentials, "Current password is incorrect")
	}

	// Validate new password strength
	// Get decrypted user info for password validation
	decryptedFirstName, err := s.encrypter.Decrypt(user.FirstName)
	if err != nil {
		s.logger.Error("Failed to decrypt first name for password validation", logger.Field{Key: "error", Value: err.Error()})
		// Continue without user info validation
		decryptedFirstName = []byte("")
	}

	decryptedLastName, err := s.encrypter.Decrypt(user.LastName)
	if err != nil {
		s.logger.Error("Failed to decrypt last name for password validation", logger.Field{Key: "error", Value: err.Error()})
		// Continue without user info validation
		decryptedLastName = []byte("")
	}

	decryptedEmail, err := s.encrypter.Decrypt(user.Email)
	if err != nil {
		s.logger.Error("Failed to decrypt email for password validation", logger.Field{Key: "error", Value: err.Error()})
		// Continue without user info validation
		decryptedEmail = []byte("")
	}

	userInfo := &validation.UserInfo{
		FirstName: string(decryptedFirstName),
		LastName:  string(decryptedLastName),
		Email:     string(decryptedEmail),
	}

	if err := s.passwordValidator.ValidatePasswordWithUserInfo(req.NewPassword, userInfo); err != nil {
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.update_password.weak_password",
		})
		counter.Inc()
		return err
	}

	// Check if new password is different from current
	if valid, err := s.encrypter.VerifyPassword(user.Password, []byte(req.NewPassword)); err == nil && valid {
		return errors.NewValidationError("new_password", "new password must be different from current password")
	}

	// Hash new password
	hashedPassword, err := s.encrypter.HashPassword([]byte(req.NewPassword))
	if err != nil {
		s.logger.Error("Failed to hash new password", logger.Field{Key: "error", Value: err.Error()})
		return errors.NewAppError(errors.CodeInternalError, "Failed to process new password")
	}

	// Clone the user to avoid race conditions when multiple goroutines update the same user
	userCopy := user.Clone()

	// Update user password and reset login attempts
	userCopy.Password = hashedPassword
	userCopy.LoginAttempts = 0
	userCopy.LockedUntil = nil
	userCopy.UpdatedAt = time.Now()

	// Save updated user
	if err := s.repository.Update(ctx, userCopy); err != nil {
		if errors.IsErrorType(err, errors.ErrVersionMismatch) {
			return errors.NewVersionMismatchError(userCopy.Version, userCopy.Version)
		}
		s.logger.Error("Failed to update user password",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: userID})
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.update_password.repository_error",
		})
		counter.Inc()
		return errors.NewAppError(errors.CodeInternalError, "Failed to update password")
	}

	// Update cache
	s.cacheUser(ctx, userCopy)

	s.logger.Info("User password updated successfully", logger.Field{Key: "user_id", Value: userID})
	counter := s.metrics.Counter(metrics.Options{
		Name: "user_service.update_password.success",
	})
	counter.Inc()

	return nil
}

// ActivateUser activates a user account (typically after email verification).
func (s *userService) ActivateUser(ctx context.Context, userID string) (*UserResponse, error) {
	startTime := time.Now()
	defer func() {
		timer := s.metrics.Timer(metrics.Options{
			Name: "user_service.activate_user",
		})
		timer.RecordSince(startTime)
	}()

	s.logger.Info("Activating user", logger.Field{Key: "user_id", Value: userID})

	// Validate user ID
	if err := validation.ValidateID(userID, "user_id"); err != nil {
		return nil, err
	}

	// Get current user
	user, err := s.repository.GetByID(ctx, userID)
	if err != nil {
		if errors.IsErrorType(err, errors.ErrUserNotFound) {
			return nil, errors.NewUserNotFoundError(userID)
		}
		s.logger.Error("Failed to retrieve user for activation",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: userID})
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to retrieve user")
	}

	// Check current status
	if user.Status == UserStatusActive {
		s.logger.Info("User is already active", logger.Field{Key: "user_id", Value: userID})
		return user.ToUserResponse(), nil
	}

	if user.Status == UserStatusDeactivated {
		return nil, errors.NewAppError(errors.CodeUserDeactivated, "Cannot activate deactivated user")
	}

	if user.Status == UserStatusSuspended {
		return nil, errors.NewAppError(errors.CodeUserSuspended, "Cannot activate suspended user")
	}

	// Activate user
	user.Status = UserStatusActive
	user.UpdatedAt = time.Now()

	// Save updated user
	if err := s.repository.Update(ctx, user); err != nil {
		if errors.IsErrorType(err, errors.ErrVersionMismatch) {
			return nil, errors.NewVersionMismatchError(user.Version, user.Version)
		}
		s.logger.Error("Failed to activate user",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: userID})
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.activate_user.repository_error",
		})
		counter.Inc()
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to activate user")
	}

	// Update cache
	s.cacheUser(ctx, user)

	s.logger.Info("User activated successfully", logger.Field{Key: "user_id", Value: userID})
	counter := s.metrics.Counter(metrics.Options{
		Name: "user_service.activate_user.success",
	})
	counter.Inc()

	return user.ToUserResponse(), nil
}

// SuspendUser suspends a user account
func (s *userService) SuspendUser(ctx context.Context, userID string, reason string) (*UserResponse, error) {
	startTime := time.Now()
	defer func() {
		timer := s.metrics.Timer(metrics.Options{
			Name: "user_service.suspend_user",
		})
		timer.RecordSince(startTime)
	}()

	s.logger.Info("Suspending user",
		logger.Field{Key: "user_id", Value: userID},
		logger.Field{Key: "reason", Value: reason})

	// Validate user ID
	if err := validation.ValidateID(userID, "user_id"); err != nil {
		return nil, err
	}

	// Get current user
	user, err := s.repository.GetByID(ctx, userID)
	if err != nil {
		if errors.IsErrorType(err, errors.ErrUserNotFound) {
			return nil, errors.NewUserNotFoundError(userID)
		}
		s.logger.Error("Failed to retrieve user for suspension",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: userID})
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to retrieve user")
	}

	// Check if user can be suspended
	if user.Status == UserStatusDeactivated {
		return nil, errors.NewAppError(errors.CodeUserDeactivated, "Cannot suspend deactivated user")
	}

	if user.Status == UserStatusSuspended {
		s.logger.Info("User is already suspended", logger.Field{Key: "user_id", Value: userID})
		return user.ToUserResponse(), nil
	}

	// Suspend user
	user.Status = UserStatusSuspended
	user.UpdatedAt = time.Now()

	// Save updated user
	if err := s.repository.Update(ctx, user); err != nil {
		if errors.IsErrorType(err, errors.ErrVersionMismatch) {
			return nil, errors.NewVersionMismatchError(user.Version, user.Version)
		}
		s.logger.Error("Failed to suspend user",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: userID})
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.suspend_user.repository_error",
		})
		counter.Inc()
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to suspend user")
	}

	// Update cache
	s.cacheUser(ctx, user)

	s.logger.Info("User suspended successfully",
		logger.Field{Key: "user_id", Value: userID},
		logger.Field{Key: "reason", Value: reason})
	counter := s.metrics.Counter(metrics.Options{
		Name: "user_service.suspend_user.success",
	})
	counter.Inc()

	return user.ToUserResponse(), nil
}

// DeactivateUser deactivates a user account
func (s *userService) DeactivateUser(ctx context.Context, userID string, reason string) (*UserResponse, error) {
	startTime := time.Now()
	defer func() {
		timer := s.metrics.Timer(metrics.Options{
			Name: "user_service.deactivate_user",
		})
		timer.RecordSince(startTime)
	}()

	s.logger.Info("Deactivating user",
		logger.Field{Key: "user_id", Value: userID},
		logger.Field{Key: "reason", Value: reason})

	// Validate user ID
	if err := validation.ValidateID(userID, "user_id"); err != nil {
		return nil, err
	}

	// Get current user
	user, err := s.repository.GetByID(ctx, userID)
	if err != nil {
		if errors.IsErrorType(err, errors.ErrUserNotFound) {
			return nil, errors.NewUserNotFoundError(userID)
		}
		s.logger.Error("Failed to retrieve user for deactivation",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: userID})
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to retrieve user")
	}

	// Check if user is already deactivated
	if user.Status == UserStatusDeactivated {
		s.logger.Info("User is already deactivated", logger.Field{Key: "user_id", Value: userID})
		return user.ToUserResponse(), nil
	}

	// Deactivate user
	user.Status = UserStatusDeactivated
	user.UpdatedAt = time.Now()

	// Save updated user
	if err := s.repository.Update(ctx, user); err != nil {
		if errors.IsErrorType(err, errors.ErrVersionMismatch) {
			return nil, errors.NewVersionMismatchError(user.Version, user.Version)
		}
		s.logger.Error("Failed to deactivate user",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: userID})
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.deactivate_user.repository_error",
		})
		counter.Inc()
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to deactivate user")
	}

	// Update cache
	s.cacheUser(ctx, user)

	s.logger.Info("User deactivated successfully",
		logger.Field{Key: "user_id", Value: userID},
		logger.Field{Key: "reason", Value: reason})
	counter := s.metrics.Counter(metrics.Options{
		Name: "user_service.deactivate_user.success",
	})
	counter.Inc()

	return user.ToUserResponse(), nil
}

// LockUser locks a user account
func (s *userService) LockUser(ctx context.Context, userID string, until *time.Time, reason string) (*UserResponse, error) {
	startTime := time.Now()
	defer func() {
		timer := s.metrics.Timer(metrics.Options{
			Name: "user_service.lock_user",
		})
		timer.RecordSince(startTime)
	}()

	s.logger.Info("Locking user",
		logger.Field{Key: "user_id", Value: userID},
		logger.Field{Key: "reason", Value: reason})

	// Validate user ID
	if err := validation.ValidateID(userID, "user_id"); err != nil {
		return nil, err
	}

	// Get current user
	user, err := s.repository.GetByID(ctx, userID)
	if err != nil {
		if errors.IsErrorType(err, errors.ErrUserNotFound) {
			return nil, errors.NewUserNotFoundError(userID)
		}
		s.logger.Error("Failed to retrieve user for locking",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: userID})
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to retrieve user")
	}

	// Check if user can be locked
	if user.Status == UserStatusDeactivated {
		return nil, errors.NewAppError(errors.CodeUserDeactivated, "Cannot lock deactivated user")
	}

	// Lock user account
	user.LockAccount(until)
	user.UpdatedAt = time.Now()

	// Save updated user
	if err := s.repository.Update(ctx, user); err != nil {
		if errors.IsErrorType(err, errors.ErrVersionMismatch) {
			return nil, errors.NewVersionMismatchError(user.Version, user.Version)
		}
		s.logger.Error("Failed to lock user",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: userID})
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.lock_user.repository_error",
		})
		counter.Inc()
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to lock user")
	}

	// Update cache
	s.cacheUser(ctx, user)

	s.logger.Info("User locked successfully",
		logger.Field{Key: "user_id", Value: userID},
		logger.Field{Key: "reason", Value: reason})
	counter := s.metrics.Counter(metrics.Options{
		Name: "user_service.lock_user.success",
	})
	counter.Inc()

	return user.ToUserResponse(), nil
}

// UnlockUser unlocks a user account
func (s *userService) UnlockUser(ctx context.Context, userID string) (*UserResponse, error) {
	startTime := time.Now()
	defer func() {
		timer := s.metrics.Timer(metrics.Options{
			Name: "user_service.unlock_user",
		})
		timer.RecordSince(startTime)
	}()

	s.logger.Info("Unlocking user", logger.Field{Key: "user_id", Value: userID})

	// Validate user ID
	if err := validation.ValidateID(userID, "user_id"); err != nil {
		return nil, err
	}

	// Get current user
	user, err := s.repository.GetByID(ctx, userID)
	if err != nil {
		if errors.IsErrorType(err, errors.ErrUserNotFound) {
			return nil, errors.NewUserNotFoundError(userID)
		}
		s.logger.Error("Failed to retrieve user for unlocking",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: userID})
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to retrieve user")
	}

	// Check if user can be unlocked
	if user.Status == UserStatusDeactivated {
		return nil, errors.NewAppError(errors.CodeUserDeactivated, "Cannot unlock deactivated user")
	}

	// Check if user is actually locked
	if !user.IsLocked() {
		s.logger.Info("User is not locked", logger.Field{Key: "user_id", Value: userID})
		return user.ToUserResponse(), nil
	}

	// Unlock user account
	user.UnlockAccount()
	user.UpdatedAt = time.Now()

	// Save updated user
	if err := s.repository.Update(ctx, user); err != nil {
		if errors.IsErrorType(err, errors.ErrVersionMismatch) {
			return nil, errors.NewVersionMismatchError(user.Version, user.Version)
		}
		s.logger.Error("Failed to unlock user",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: userID})
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.unlock_user.repository_error",
		})
		counter.Inc()
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to unlock user")
	}

	// Update cache
	s.cacheUser(ctx, user)

	s.logger.Info("User unlocked successfully", logger.Field{Key: "user_id", Value: userID})
	counter := s.metrics.Counter(metrics.Options{
		Name: "user_service.unlock_user.success",
	})
	counter.Inc()

	return user.ToUserResponse(), nil
}

// ListUsers retrieves users with pagination and filtering
func (s *userService) ListUsers(ctx context.Context, req *ListUsersRequest) (*ListUsersResponse, error) {
	startTime := time.Now()
	defer func() {
		timer := s.metrics.Timer(metrics.Options{
			Name: "user_service.list_users",
		})
		timer.RecordSince(startTime)
	}()

	// Validate request
	if req == nil {
		return nil, errors.NewValidationError("request", "request is required")
	}

	// Set defaults
	if req.Limit <= 0 {
		req.Limit = 50
	}
	if req.Limit > 1000 {
		req.Limit = 1000
	}
	if req.Offset < 0 {
		req.Offset = 0
	}

	// Get users from repository
	users, totalCount, err := s.repository.ListUsers(ctx, req.Offset, req.Limit)
	if err != nil {
		s.logger.Error("Failed to list users",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "offset", Value: req.Offset},
			logger.Field{Key: "limit", Value: req.Limit})
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to retrieve users")
	}

	// Convert to response DTOs
	userResponses := make([]*UserResponse, len(users))
	for i, user := range users {
		userResponses[i] = user.ToUserResponse()
	}

	// Calculate if there are more results
	hasMore := int64(req.Offset+req.Limit) < totalCount

	counter := s.metrics.Counter(metrics.Options{
		Name: "user_service.list_users.success",
	})
	counter.Inc()

	return &ListUsersResponse{
		Users:      userResponses,
		TotalCount: totalCount,
		Offset:     req.Offset,
		Limit:      req.Limit,
		HasMore:    hasMore,
	}, nil
}

// GetUserStats retrieves user statistics
func (s *userService) GetUserStats(ctx context.Context) (*UserStatsResponse, error) {
	startTime := time.Now()
	defer func() {
		timer := s.metrics.Timer(metrics.Options{
			Name: "user_service.get_user_stats",
		})
		timer.RecordSince(startTime)
	}()

	// Try cache first
	cacheKey := "user_stats"
	if cached, _, err := s.cache.Get(ctx, cacheKey); err == nil {
		if stats, ok := cached.(*UserStatsResponse); ok {
			counter := s.metrics.Counter(metrics.Options{
				Name: "user_service.get_user_stats.cache_hit",
			})
			counter.Inc()
			return stats, nil
		}
	}

	// Get stats from repository
	stats, err := s.repository.GetUserStats(ctx)
	if err != nil {
		s.logger.Error("Failed to get user stats", logger.Field{Key: "error", Value: err.Error()})
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to retrieve user statistics")
	}

	response := &UserStatsResponse{
		Stats:     stats,
		UpdatedAt: time.Now(),
	}

	// Cache the response
	config := &ServiceConfig{}
	if ttlStr, ok := s.config.GetString("user_service.cache_stats_ttl"); ok {
		if parsed, parseErr := time.ParseDuration(ttlStr); parseErr == nil {
			config.CacheStatseTTL = parsed
		} else {
			config.CacheStatseTTL = 5 * time.Minute
		}
	} else {
		config.CacheStatseTTL = 5 * time.Minute
	}

	if err := s.cache.Set(ctx, cacheKey, response, config.CacheStatseTTL); err != nil {
		s.logger.Warn("Failed to cache user stats", logger.Field{Key: "error", Value: err.Error()})
	}

	counter := s.metrics.Counter(metrics.Options{
		Name: "user_service.get_user_stats.success",
	})
	counter.Inc()

	return response, nil
}

// DeleteUser deletes a user account
func (s *userService) DeleteUser(ctx context.Context, userID string) error {
	startTime := time.Now()
	defer func() {
		timer := s.metrics.Timer(metrics.Options{
			Name: "user_service.delete_user",
		})
		timer.RecordSince(startTime)
	}()

	s.logger.Info("Deleting user", logger.Field{Key: "user_id", Value: userID})

	// Validate user ID
	if err := validation.ValidateID(userID, "user_id"); err != nil {
		return err
	}

	// Check if user exists first
	user, err := s.repository.GetByID(ctx, userID)
	if err != nil {
		if errors.IsErrorType(err, errors.ErrUserNotFound) {
			return errors.NewUserNotFoundError(userID)
		}
		s.logger.Error("Failed to retrieve user for deletion",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: userID})
		return errors.NewAppError(errors.CodeInternalError, "Failed to retrieve user")
	}

	// Delete user from repository
	if err := s.repository.Delete(ctx, userID); err != nil {
		s.logger.Error("Failed to delete user",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: userID})
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.delete_user.repository_error",
		})
		counter.Inc()
		return errors.NewAppError(errors.CodeInternalError, "Failed to delete user")
	}

	// Remove from cache
	cacheKey := fmt.Sprintf("user:%s", userID)
	if err := s.cache.Delete(ctx, cacheKey); err != nil {
		s.logger.Warn("Failed to remove user from cache",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: userID})
	}

	s.logger.Info("User deleted successfully",
		logger.Field{Key: "user_id", Value: userID},
		logger.Field{Key: "previous_status", Value: user.Status.String()})
	counter := s.metrics.Counter(metrics.Options{
		Name: "user_service.delete_user.success",
	})
	counter.Inc()

	return nil
}
