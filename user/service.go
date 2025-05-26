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
	user.ResetLoginAttempts()
	user.UpdateLastLogin()

	// Update user in repository
	if err := s.repository.Update(ctx, user); err != nil {
		s.logger.Error("Failed to update user after successful authentication",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: user.ID})
		// Continue despite error as authentication was successful
	}

	// Update cache
	s.cacheUser(ctx, user)

	s.logger.Info("User authenticated successfully", logger.Field{Key: "user_id", Value: user.ID})
	counter := s.metrics.Counter(metrics.Options{
		Name: "user_service.authenticate_user.success",
	})
	counter.Inc()

	return &AuthenticationResponse{
		User:    user.ToUserResponse(),
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

// Stub implementations for the remaining interface methods
// These would be implemented following the same patterns as above

func (s *userService) GetUserByEmail(ctx context.Context, email string) (*UserResponse, error) {
	// TODO: Implement
	return nil, errors.NewAppError(errors.CodeNotImplemented, "GetUserByEmail not implemented")
}

func (s *userService) UpdateProfile(ctx context.Context, userID string, req *UpdateProfileRequest) (*UserResponse, error) {
	// TODO: Implement
	return nil, errors.NewAppError(errors.CodeNotImplemented, "UpdateProfile not implemented")
}

func (s *userService) UpdatePassword(ctx context.Context, userID string, req *UpdatePasswordRequest) error {
	// TODO: Implement
	return errors.NewAppError(errors.CodeNotImplemented, "UpdatePassword not implemented")
}

func (s *userService) ActivateUser(ctx context.Context, userID string) (*UserResponse, error) {
	// TODO: Implement
	return nil, errors.NewAppError(errors.CodeNotImplemented, "ActivateUser not implemented")
}

func (s *userService) SuspendUser(ctx context.Context, userID string, reason string) (*UserResponse, error) {
	// TODO: Implement
	return nil, errors.NewAppError(errors.CodeNotImplemented, "SuspendUser not implemented")
}

func (s *userService) DeactivateUser(ctx context.Context, userID string, reason string) (*UserResponse, error) {
	// TODO: Implement
	return nil, errors.NewAppError(errors.CodeNotImplemented, "DeactivateUser not implemented")
}

func (s *userService) LockUser(ctx context.Context, userID string, until *time.Time, reason string) (*UserResponse, error) {
	// TODO: Implement
	return nil, errors.NewAppError(errors.CodeNotImplemented, "LockUser not implemented")
}

func (s *userService) UnlockUser(ctx context.Context, userID string) (*UserResponse, error) {
	// TODO: Implement
	return nil, errors.NewAppError(errors.CodeNotImplemented, "UnlockUser not implemented")
}

func (s *userService) ListUsers(ctx context.Context, req *ListUsersRequest) (*ListUsersResponse, error) {
	// TODO: Implement
	return nil, errors.NewAppError(errors.CodeNotImplemented, "ListUsers not implemented")
}

func (s *userService) GetUserStats(ctx context.Context) (*UserStatsResponse, error) {
	// TODO: Implement
	return nil, errors.NewAppError(errors.CodeNotImplemented, "GetUserStats not implemented")
}

func (s *userService) DeleteUser(ctx context.Context, userID string) error {
	// TODO: Implement
	return errors.NewAppError(errors.CodeNotImplemented, "DeleteUser not implemented")
}
