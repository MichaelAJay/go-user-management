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
	"github.com/MichaelAJay/go-user-management/auth"
	"github.com/MichaelAJay/go-user-management/auth/providers/password"
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

	// UpdateCredentials updates a user's authentication credentials
	UpdateCredentials(ctx context.Context, userID string, req *UpdateCredentialsRequest) error

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
}

// userService implements the UserService interface.
type userService struct {
	// Repository dependencies - each focused on specific domain
	userRepository     UserRepository
	authRepository     AuthenticationRepository // NEW - handles credentials
	securityRepository UserSecurityRepository   // NEW - handles security state

	// Existing dependencies
	encrypter      encrypter.Encrypter
	logger         logger.Logger
	cache          cache.Cache
	config         config.Config
	metrics        metrics.Registry
	emailValidator *validation.EmailValidator
	authManager    auth.Manager
	serviceConfig  *ServiceConfig // Store loaded configuration
}

// NewUserService creates a new UserService instance with the provided dependencies.
func NewUserService(
	userRepository UserRepository,
	authRepository AuthenticationRepository, // NEW parameter
	securityRepository UserSecurityRepository, // NEW parameter
	encrypter encrypter.Encrypter,
	logger logger.Logger,
	cache cache.Cache,
	config config.Config,
	metrics metrics.Registry,
	authManager auth.Manager,
) UserService {
	// Load service configuration
	serviceConfig := &ServiceConfig{}

	// Cache settings
	if ttl, ok := config.GetString("user_service.cache_user_ttl"); ok {
		if parsed, err := time.ParseDuration(ttl); err == nil {
			serviceConfig.CacheUserTTL = parsed
		}
	}
	if serviceConfig.CacheUserTTL == 0 {
		serviceConfig.CacheUserTTL = 15 * time.Minute
	}

	if ttl, ok := config.GetString("user_service.cache_stats_ttl"); ok {
		if parsed, err := time.ParseDuration(ttl); err == nil {
			serviceConfig.CacheStatseTTL = parsed
		}
	}
	if serviceConfig.CacheStatseTTL == 0 {
		serviceConfig.CacheStatseTTL = 5 * time.Minute
	}

	// Account lockout settings
	if maxAttempts, ok := config.GetInt("user_service.max_login_attempts"); ok {
		serviceConfig.MaxLoginAttempts = maxAttempts
	}
	if serviceConfig.MaxLoginAttempts == 0 {
		serviceConfig.MaxLoginAttempts = 5
	}

	if lockoutStr, ok := config.GetString("user_service.lockout_duration"); ok {
		if parsed, err := time.ParseDuration(lockoutStr); err == nil {
			serviceConfig.LockoutDuration = parsed
		}
	}
	if serviceConfig.LockoutDuration == 0 {
		serviceConfig.LockoutDuration = 30 * time.Minute
	}

	// Rate limiting settings
	if enabled, ok := config.GetBool("user_service.enable_rate_limit"); ok {
		serviceConfig.EnableRateLimit = enabled
	} else {
		serviceConfig.EnableRateLimit = true
	}

	if windowStr, ok := config.GetString("user_service.rate_limit_window"); ok {
		if parsed, err := time.ParseDuration(windowStr); err == nil {
			serviceConfig.RateLimitWindow = parsed
		}
	}
	if serviceConfig.RateLimitWindow == 0 {
		serviceConfig.RateLimitWindow = time.Hour
	}

	if maxAttempts, ok := config.GetInt("user_service.rate_limit_max_attempts"); ok {
		serviceConfig.RateLimitMaxAttempts = maxAttempts
	}
	if serviceConfig.RateLimitMaxAttempts == 0 {
		serviceConfig.RateLimitMaxAttempts = 10
	}

	// Email validation settings
	if allowDisposable, ok := config.GetBool("user_service.allow_disposable_emails"); ok {
		serviceConfig.AllowDisposableEmails = allowDisposable
	}

	// Configure email validator
	emailValidator := validation.NewEmailValidator()
	emailValidator.AllowDisposableEmails = serviceConfig.AllowDisposableEmails
	emailValidator.AllowedDomains = serviceConfig.AllowedEmailDomains
	emailValidator.BlockedDomains = serviceConfig.BlockedEmailDomains

	return &userService{
		userRepository:     userRepository,
		authRepository:     authRepository,     // NEW
		securityRepository: securityRepository, // NEW
		encrypter:          encrypter,
		logger:             logger,
		cache:              cache,
		config:             config,
		metrics:            metrics,
		emailValidator:     emailValidator,
		authManager:        authManager,
		serviceConfig:      serviceConfig,
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

	// Convert credentials to proper type for the provider
	convertedCredentials, err := s.convertCredentials(req.AuthenticationProvider, req.Credentials)
	if err != nil {
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.create_user.credential_conversion_error",
		})
		counter.Inc()
		return nil, err
	}

	// Validate credentials using authentication manager
	userInfo := &auth.UserInfo{
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Email:     normalizedEmail,
	}
	if err := s.authManager.ValidateCredentials(ctx, req.AuthenticationProvider, convertedCredentials, userInfo); err != nil {
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.create_user.credential_validation_error",
		})
		counter.Inc()
		return nil, err
	}

	// Hash email for lookup
	hashedEmail := s.encrypter.HashLookupData([]byte(normalizedEmail))

	// Check if user already exists
	if _, err := s.userRepository.GetByHashedEmail(ctx, string(hashedEmail)); err == nil {
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

	// Prepare credentials for storage using authentication manager
	authData, err := s.authManager.PrepareCredentials(ctx, req.AuthenticationProvider, convertedCredentials)
	if err != nil {
		s.logger.Error("Failed to prepare credentials", logger.Field{Key: "error", Value: err.Error()})
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to process credentials")
	}

	// Store user in repository
	params := &CreateUserParams{
		FirstName:           encryptedFirstName,
		LastName:            encryptedLastName,
		Email:               encryptedEmail,
		HashedEmail:         string(hashedEmail),
		PrimaryAuthProvider: req.AuthenticationProvider,
	}
	createdUser, err := s.userRepository.Create(ctx, params)
	if err != nil {
		s.logger.Error("Failed to create user in repository",
			logger.Field{Key: "error", Value: err.Error()})
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.create_user.repository_error",
		})
		counter.Inc()
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to create user")
	}

	// Create credentials using the new credential architecture
	// Encrypt the serialized auth data (authData is already []byte from provider)
	encryptedAuthData, err := s.encrypter.Encrypt(authData)
	if err != nil {
		s.logger.Error("Failed to encrypt auth data", logger.Field{Key: "error", Value: err.Error()})
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to encrypt auth data")
	}

	credentials := NewUserCredentials(createdUser.ID, req.AuthenticationProvider, encryptedAuthData)
	if err := s.authRepository.CreateCredentials(ctx, credentials); err != nil {
		s.logger.Error("Failed to create user credentials",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: createdUser.ID})
		// TODO: Rollback user creation
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to create credentials")
	}

	// Create security state
	security := NewUserSecurity(createdUser.ID)
	if err := s.securityRepository.CreateSecurity(ctx, security); err != nil {
		s.logger.Error("Failed to create user security state",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: createdUser.ID})
		// TODO: Rollback user and credentials creation
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to create security state")
	}

	// Cache user data
	s.cacheUser(ctx, createdUser)

	// Cache email mapping for faster email lookups
	s.cacheEmailMapping(ctx, createdUser.HashedEmail, createdUser.ID)

	s.logger.Info("User created successfully",
		logger.Field{Key: "user_id", Value: createdUser.ID},
		logger.Field{Key: "email", Value: normalizedEmail})
	counter := s.metrics.Counter(metrics.Options{
		Name: "user_service.create_user.success",
	})
	counter.Inc()

	// Use orchestrator method to build comprehensive response
	return s.buildUserResponse(ctx, createdUser)
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
	user, err := s.userRepository.GetByHashedEmail(ctx, string(hashedEmail))
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

	// Get security state FIRST to check for locks - this handles both temporary and permanent locks
	security, err := s.securityRepository.GetSecurity(ctx, user.ID)
	if err != nil {
		s.logger.Error("Failed to get user security state",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: user.ID})
		return nil, errors.NewAppError(errors.CodeInternalError, "Authentication failed")
	}

	// Check for security locks (temporary locks via UserSecurity)
	if security.IsLocked() {
		s.logger.Warn("Authentication attempt for locked user",
			logger.Field{Key: "user_id", Value: user.ID},
			logger.Field{Key: "lock_reason", Value: security.LockReason},
			logger.Field{Key: "locked_until", Value: security.LockedUntil})
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.authenticate_user.account_locked",
		})
		counter.Inc()

		var lockMessage string
		if security.LockedUntil != nil {
			lockMessage = security.LockedUntil.Format(time.RFC3339)
		}
		return nil, errors.NewAccountLockedError(lockMessage)
	}

	// Now check if user can authenticate (User status checks)
	if !user.CanAuthenticate() {
		s.logger.Warn("Authentication attempt for non-authenticatable user",
			logger.Field{Key: "user_id", Value: user.ID},
			logger.Field{Key: "status", Value: user.Status.String()})
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.authenticate_user.account_not_active",
		})
		counter.Inc()

		return nil, errors.NewAppError(errors.CodeAccountNotActivated, "Account is not active")
	}

	// Get the authentication provider to verify credentials
	provider, err := s.authManager.GetProvider(req.AuthenticationProvider)
	if err != nil {
		s.logger.Error("Authentication provider not found", logger.Field{Key: "provider", Value: string(req.AuthenticationProvider)})
		return nil, errors.NewInvalidCredentialsError()
	}

	// Get stored authentication data for this provider
	credentials, err := s.authRepository.GetCredentials(ctx, user.ID, req.AuthenticationProvider)
	if err != nil {
		if errors.IsErrorType(err, errors.ErrUserNotFound) {
			s.logger.Warn("User does not have authentication data for provider",
				logger.Field{Key: "user_id", Value: user.ID},
				logger.Field{Key: "provider", Value: string(req.AuthenticationProvider)})
			return nil, errors.NewInvalidCredentialsError()
		}
		s.logger.Error("Failed to get user credentials", logger.Field{Key: "error", Value: err.Error()})
		return nil, errors.NewAppError(errors.CodeInternalError, "Authentication failed")
	}

	// Convert credentials to proper type for the provider
	convertedCredentials, err := s.convertCredentials(req.AuthenticationProvider, req.Credentials)
	if err != nil {
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.authenticate_user.credential_conversion_error",
		})
		counter.Inc()
		return nil, err
	}

	// Use the provider to authenticate with stored data
	// First decrypt the stored auth data to get raw serialized bytes
	decryptedAuthData, err := s.encrypter.Decrypt(credentials.EncryptedAuthData)
	if err != nil {
		s.logger.Error("Failed to decrypt auth data", logger.Field{Key: "error", Value: err.Error()})
		return nil, errors.NewAppError(errors.CodeInternalError, "Authentication failed")
	}

	// Pass raw bytes to provider - provider handles its own deserialization
	authResult, err := provider.Authenticate(ctx, user.ID, convertedCredentials, decryptedAuthData)
	if err != nil {
		// Clone security state to avoid race conditions (we already have it from above)
		securityCopy := security.Clone()

		// Process failed authentication using business logic with pre-loaded config
		securityCopy.ProcessFailedAttempt(s.serviceConfig.MaxLoginAttempts, s.serviceConfig.LockoutDuration, "")

		// Update security state in repository using the clone
		if err := s.securityRepository.UpdateSecurity(ctx, securityCopy); err != nil {
			s.logger.Error("Failed to update security state after failed authentication",
				logger.Field{Key: "error", Value: err.Error()},
				logger.Field{Key: "user_id", Value: user.ID})
			// Continue with authentication failure response despite repository error
		}

		s.logger.Warn("Authentication failed for user",
			logger.Field{Key: "user_id", Value: user.ID},
			logger.Field{Key: "attempts", Value: securityCopy.LoginAttempts})
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.authenticate_user.failed",
		})
		counter.Inc()

		return nil, errors.NewInvalidCredentialsError()
	}

	// Clone security state to avoid race conditions (we already have it from above)
	securityCopy := security.Clone()

	// Process successful authentication using business logic
	securityCopy.ProcessSuccessfulLogin("")

	// Update security state in repository using the clone
	if err := s.securityRepository.UpdateSecurity(ctx, securityCopy); err != nil {
		s.logger.Error("Failed to update security state after successful authentication",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: user.ID})
		// Continue despite error as authentication was successful
	}

	// Update cache with user data
	s.cacheUser(ctx, user)

	s.logger.Info("User authenticated successfully", logger.Field{Key: "user_id", Value: user.ID})
	counter := s.metrics.Counter(metrics.Options{
		Name: "user_service.authenticate_user.success",
	})
	counter.Inc()

	// Build comprehensive user response using orchestrator
	userResponse, err := s.buildUserResponse(ctx, user)
	if err != nil {
		s.logger.Error("Failed to build user response after authentication",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: user.ID})
		// Continue with basic response rather than failing authentication
		userResponse = user.ToUserResponse(s.encrypter)
	}

	return &AuthenticationResponse{
		User:       userResponse,
		AuthResult: authResult,
		Message:    "Authentication successful",
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
		// Use orchestrator method to build comprehensive response
		return s.buildUserResponse(ctx, user)
	}

	// Get from repository
	user, err := s.userRepository.GetByID(ctx, userID)
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

	// Use orchestrator method to build comprehensive response
	return s.buildUserResponse(ctx, user)
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

	// Basic credentials validation (detailed validation happens later)
	if req.Credentials == nil {
		return errors.NewValidationError("credentials", "credentials are required")
	}

	// Validate authentication provider
	if req.AuthenticationProvider == "" {
		return errors.NewValidationError("authentication_provider", "authentication provider is required")
	}

	return nil
}

// checkRateLimit checks if the request should be rate limited.
func (s *userService) checkRateLimit(ctx context.Context, identifier string) error {
	if !s.serviceConfig.EnableRateLimit {
		return nil
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

	if attemptCount >= s.serviceConfig.RateLimitMaxAttempts {
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.rate_limit_exceeded",
		})
		counter.Inc()
		return errors.NewAppError(errors.CodeRateLimitExceeded, "Too many authentication attempts")
	}

	// Increment counter
	s.cache.Set(ctx, key, attemptCount+1, s.serviceConfig.RateLimitWindow)
	return nil
}

// cacheUser stores user data in cache.
func (s *userService) cacheUser(ctx context.Context, user *User) {
	key := fmt.Sprintf("user:%s", user.ID)
	if err := s.cache.Set(ctx, key, user, s.serviceConfig.CacheUserTTL); err != nil {
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

// cacheEmailMapping stores email->userID mapping in cache for faster email lookups.
func (s *userService) cacheEmailMapping(ctx context.Context, hashedEmail, userID string) {
	key := fmt.Sprintf("user:email:%s", hashedEmail)
	if err := s.cache.Set(ctx, key, userID, s.serviceConfig.CacheUserTTL); err != nil {
		s.logger.Warn("Failed to cache email mapping",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "hashed_email", Value: hashedEmail})
	}
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

	// Try cache first using hashed email as secondary key
	emailCacheKey := fmt.Sprintf("user:email:%s", string(hashedEmail))
	if cached, _, err := s.cache.Get(ctx, emailCacheKey); err == nil {
		if userID, ok := cached.(string); ok {
			// Now get the full user from cache using the user ID
			if user := s.getCachedUser(ctx, userID); user != nil {
				counter := s.metrics.Counter(metrics.Options{
					Name: "user_service.get_user_by_email.cache_hit",
				})
				counter.Inc()
				// Use orchestrator method to build comprehensive response
				return s.buildUserResponse(ctx, user)
			}
		}
	}

	// Get from repository
	user, err := s.userRepository.GetByHashedEmail(ctx, string(hashedEmail))
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

	// Cache both the user and the email->userID mapping
	s.cacheUser(ctx, user)
	s.cacheEmailMapping(ctx, string(hashedEmail), user.ID)

	counter := s.metrics.Counter(metrics.Options{
		Name: "user_service.get_user_by_email.success",
	})
	counter.Inc()

	// Use orchestrator method to build comprehensive response
	return s.buildUserResponse(ctx, user)
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
	user, err := s.userRepository.GetByID(ctx, userID)
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

	// Prepare encrypted data for profile update
	var encryptedFirstName, encryptedLastName, encryptedEmail []byte
	var newHashedEmail string

	// Update first name if provided
	if req.FirstName != nil {
		if err := validation.ValidateName(*req.FirstName, "first_name"); err != nil {
			return nil, err
		}
		var err error
		encryptedFirstName, err = s.encrypter.Encrypt([]byte(*req.FirstName))
		if err != nil {
			s.logger.Error("Failed to encrypt first name", logger.Field{Key: "error", Value: err.Error()})
			return nil, errors.NewAppError(errors.CodeInternalError, "Failed to process user data")
		}
	}

	// Update last name if provided
	if req.LastName != nil {
		if err := validation.ValidateName(*req.LastName, "last_name"); err != nil {
			return nil, err
		}
		var err error
		encryptedLastName, err = s.encrypter.Encrypt([]byte(*req.LastName))
		if err != nil {
			s.logger.Error("Failed to encrypt last name", logger.Field{Key: "error", Value: err.Error()})
			return nil, errors.NewAppError(errors.CodeInternalError, "Failed to process user data")
		}
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
		newHashedEmailBytes := s.encrypter.HashLookupData([]byte(normalizedEmail))
		newHashedEmail = string(newHashedEmailBytes)

		// Check if new email already exists (but not for the same user)
		if existingUser, err := s.userRepository.GetByHashedEmail(ctx, newHashedEmail); err == nil {
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
		var err error
		encryptedEmail, err = s.encrypter.Encrypt([]byte(normalizedEmail))
		if err != nil {
			s.logger.Error("Failed to encrypt email", logger.Field{Key: "error", Value: err.Error()})
			return nil, errors.NewAppError(errors.CodeInternalError, "Failed to process email")
		}
	}

	// Update profile data using the new business logic method
	if err := userCopy.UpdateProfileData(encryptedFirstName, encryptedLastName, encryptedEmail, newHashedEmail); err != nil {
		s.logger.Error("Failed to update profile data", logger.Field{Key: "error", Value: err.Error()})
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to update profile")
	}

	// Save updated user
	if err := s.userRepository.Update(ctx, userCopy); err != nil {
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

	// If email changed, invalidate old email mapping and cache new one
	if emailChanged {
		// Invalidate old email mapping
		oldEmailKey := fmt.Sprintf("user:email:%s", user.HashedEmail)
		if err := s.cache.Delete(ctx, oldEmailKey); err != nil {
			s.logger.Warn("Failed to invalidate old email mapping",
				logger.Field{Key: "error", Value: err.Error()},
				logger.Field{Key: "user_id", Value: userID})
		}

		// Cache new email mapping
		s.cacheEmailMapping(ctx, userCopy.HashedEmail, userCopy.ID)
	}

	s.logger.Info("User profile updated successfully",
		logger.Field{Key: "user_id", Value: userID},
		logger.Field{Key: "email_changed", Value: emailChanged})
	counter := s.metrics.Counter(metrics.Options{
		Name: "user_service.update_profile.success",
	})
	counter.Inc()

	// Use orchestrator method to build comprehensive response
	return s.buildUserResponse(ctx, userCopy)
}

// UpdateCredentials updates a user's authentication credentials.
func (s *userService) UpdateCredentials(ctx context.Context, userID string, req *UpdateCredentialsRequest) error {
	startTime := time.Now()
	defer func() {
		timer := s.metrics.Timer(metrics.Options{
			Name: "user_service.update_credentials",
		})
		timer.RecordSince(startTime)
	}()

	s.logger.Info("Updating user credentials", logger.Field{Key: "user_id", Value: userID})

	// Validate user ID
	if err := validation.ValidateID(userID, "user_id"); err != nil {
		return err
	}

	// Validate request
	if req == nil {
		return errors.NewValidationError("request", "request is required")
	}
	if req.CurrentCredentials == nil {
		return errors.NewValidationError("current_credentials", "current credentials are required")
	}
	if req.NewCredentials == nil {
		return errors.NewValidationError("new_credentials", "new credentials are required")
	}

	// Get current user
	user, err := s.userRepository.GetByID(ctx, userID)
	if err != nil {
		if errors.IsErrorType(err, errors.ErrUserNotFound) {
			return errors.NewUserNotFoundError(userID)
		}
		s.logger.Error("Failed to retrieve user for credential update",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: userID})
		return errors.NewAppError(errors.CodeInternalError, "Failed to retrieve user")
	}

	// Check if user can update credentials
	if user.Status == UserStatusDeactivated {
		return errors.NewAppError(errors.CodeUserDeactivated, "Cannot update credentials for deactivated user")
	}

	// Clone user to avoid race conditions
	userCopy := user.Clone()

	// Convert credentials to proper types for the provider
	convertedNewCredentials, err := s.convertCredentials(req.AuthenticationProvider, req.NewCredentials)
	if err != nil {
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.update_credentials.credential_conversion_error",
		})
		counter.Inc()
		return err
	}

	// Validate new credentials using authentication manager
	// Get decrypted user info for validation
	decryptedFirstName, err := s.encrypter.Decrypt(userCopy.FirstName)
	if err != nil {
		s.logger.Error("Failed to decrypt first name for credential validation", logger.Field{Key: "error", Value: err.Error()})
		decryptedFirstName = []byte("")
	}

	decryptedLastName, err := s.encrypter.Decrypt(userCopy.LastName)
	if err != nil {
		s.logger.Error("Failed to decrypt last name for credential validation", logger.Field{Key: "error", Value: err.Error()})
		decryptedLastName = []byte("")
	}

	decryptedEmail, err := s.encrypter.Decrypt(userCopy.Email)
	if err != nil {
		s.logger.Error("Failed to decrypt email for credential validation", logger.Field{Key: "error", Value: err.Error()})
		decryptedEmail = []byte("")
	}

	userInfo := &auth.UserInfo{
		UserID:    userID,
		FirstName: string(decryptedFirstName),
		LastName:  string(decryptedLastName),
		Email:     string(decryptedEmail),
		CreatedAt: userCopy.CreatedAt,
	}

	if err := s.authManager.ValidateCredentials(ctx, req.AuthenticationProvider, convertedNewCredentials, userInfo); err != nil {
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.update_credentials.weak_credentials",
		})
		counter.Inc()
		return err
	}

	// Update user authentication data using the new credential architecture
	// Get current credentials
	currentCredentials, err := s.authRepository.GetCredentials(ctx, userID, req.AuthenticationProvider)
	if err != nil {
		s.logger.Error("Failed to get current credentials", logger.Field{Key: "error", Value: err.Error()})
		return errors.NewAppError(errors.CodeInternalError, "Failed to get current credentials")
	}

	// Decrypt current auth data to get raw serialized bytes
	decryptedCurrentAuthData, err := s.encrypter.Decrypt(currentCredentials.EncryptedAuthData)
	if err != nil {
		s.logger.Error("Failed to decrypt current auth data", logger.Field{Key: "error", Value: err.Error()})
		return errors.NewAppError(errors.CodeInternalError, "Failed to process current credentials")
	}

	// Convert current and new credentials to proper types
	convertedCurrentCredentials, err := s.convertCredentials(req.AuthenticationProvider, req.CurrentCredentials)
	if err != nil {
		return err
	}

	// Use the provider to update credentials
	provider, err := s.authManager.GetProvider(req.AuthenticationProvider)
	if err != nil {
		s.logger.Error("Authentication provider not found", logger.Field{Key: "provider", Value: string(req.AuthenticationProvider)})
		return errors.NewAppError(errors.CodeInternalError, "Failed to get authentication provider")
	}

	// Update credentials using the provider - provider handles its own serialization
	newAuthData, err := provider.UpdateCredentials(ctx, userID, convertedCurrentCredentials, convertedNewCredentials, decryptedCurrentAuthData)
	if err != nil {
		s.logger.Error("Failed to update credentials via provider", logger.Field{Key: "error", Value: err.Error()})
		return err
	}

	// Encrypt the new auth data (newAuthData is already []byte from provider)
	encryptedNewAuthData, err := s.encrypter.Encrypt(newAuthData)
	if err != nil {
		s.logger.Error("Failed to encrypt new auth data", logger.Field{Key: "error", Value: err.Error()})
		return errors.NewAppError(errors.CodeInternalError, "Failed to encrypt new auth data")
	}

	// Clone credentials to avoid race conditions
	currentCredentialsCopy := currentCredentials.Clone()

	// Update credentials with new encrypted data
	if err := currentCredentialsCopy.UpdateAuthData(encryptedNewAuthData); err != nil {
		s.logger.Error("Failed to update credential data", logger.Field{Key: "error", Value: err.Error()})
		return errors.NewAppError(errors.CodeInternalError, "Failed to update credentials")
	}

	// Save updated credentials using the clone
	if err := s.authRepository.UpdateCredentials(ctx, currentCredentialsCopy); err != nil {
		s.logger.Error("Failed to save updated credentials",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: userID})
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.update_credentials.repository_error",
		})
		counter.Inc()
		return errors.NewAppError(errors.CodeInternalError, "Failed to update credentials")
	}

	// Update cache
	s.cacheUser(ctx, userCopy)

	s.logger.Info("User credentials updated successfully", logger.Field{Key: "user_id", Value: userID})
	counter := s.metrics.Counter(metrics.Options{
		Name: "user_service.update_credentials.success",
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
	user, err := s.userRepository.GetByID(ctx, userID)
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
		return s.buildUserResponse(ctx, user)
	}

	if user.Status == UserStatusDeactivated {
		return nil, errors.NewAppError(errors.CodeUserDeactivated, "Cannot activate deactivated user")
	}

	if user.Status == UserStatusSuspended {
		return nil, errors.NewAppError(errors.CodeUserSuspended, "Cannot activate suspended user")
	}

	// Clone user to avoid race conditions
	userCopy := user.Clone()

	// Activate user using business logic
	if err := userCopy.ActivateAccount(); err != nil {
		return nil, err
	}

	// Save updated user
	if err := s.userRepository.Update(ctx, userCopy); err != nil {
		if errors.IsErrorType(err, errors.ErrVersionMismatch) {
			return nil, errors.NewVersionMismatchError(userCopy.Version, userCopy.Version)
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
	s.cacheUser(ctx, userCopy)

	s.logger.Info("User activated successfully", logger.Field{Key: "user_id", Value: userID})
	counter := s.metrics.Counter(metrics.Options{
		Name: "user_service.activate_user.success",
	})
	counter.Inc()

	return s.buildUserResponse(ctx, userCopy)
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
	user, err := s.userRepository.GetByID(ctx, userID)
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
		return s.buildUserResponse(ctx, user)
	}

	// Clone user to avoid race conditions
	userCopy := user.Clone()

	// Suspend user using business logic
	if err := userCopy.SuspendAccount(reason); err != nil {
		return nil, err
	}

	// Save updated user
	if err := s.userRepository.Update(ctx, userCopy); err != nil {
		if errors.IsErrorType(err, errors.ErrVersionMismatch) {
			return nil, errors.NewVersionMismatchError(userCopy.Version, userCopy.Version)
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
	s.cacheUser(ctx, userCopy)

	s.logger.Info("User suspended successfully",
		logger.Field{Key: "user_id", Value: userID},
		logger.Field{Key: "reason", Value: reason})
	counter := s.metrics.Counter(metrics.Options{
		Name: "user_service.suspend_user.success",
	})
	counter.Inc()

	return s.buildUserResponse(ctx, userCopy)
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
	user, err := s.userRepository.GetByID(ctx, userID)
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
		return s.buildUserResponse(ctx, user)
	}

	// Clone user to avoid race conditions
	userCopy := user.Clone()

	// Deactivate user using business logic
	if err := userCopy.DeactivateAccount(reason); err != nil {
		return nil, err
	}

	// Save updated user
	if err := s.userRepository.Update(ctx, userCopy); err != nil {
		if errors.IsErrorType(err, errors.ErrVersionMismatch) {
			return nil, errors.NewVersionMismatchError(userCopy.Version, userCopy.Version)
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
	s.cacheUser(ctx, userCopy)

	s.logger.Info("User deactivated successfully",
		logger.Field{Key: "user_id", Value: userID},
		logger.Field{Key: "reason", Value: reason})
	counter := s.metrics.Counter(metrics.Options{
		Name: "user_service.deactivate_user.success",
	})
	counter.Inc()

	return s.buildUserResponse(ctx, userCopy)
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
	user, err := s.userRepository.GetByID(ctx, userID)
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

	// Get or create security state
	security, err := s.securityRepository.GetSecurity(ctx, userID)
	if err != nil {
		if errors.IsErrorType(err, errors.ErrUserNotFound) {
			// Create security state if it doesn't exist
			security = NewUserSecurity(userID)
		} else {
			s.logger.Error("Failed to get security state for locking",
				logger.Field{Key: "error", Value: err.Error()},
				logger.Field{Key: "user_id", Value: userID})
			return nil, errors.NewAppError(errors.CodeInternalError, "Failed to get security state")
		}
	}

	// Clone security state to avoid race conditions
	securityCopy := security.Clone()

	// Lock user account using simplified security business logic
	// Both temporary and permanent locks are handled by UserSecurity
	securityCopy.LockAccount(until, reason)

	// Save security state using the clone
	if err := s.securityRepository.UpdateSecurity(ctx, securityCopy); err != nil {
		s.logger.Error("Failed to update security state for lock",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: userID})
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.lock_user.repository_error",
		})
		counter.Inc()
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to lock user")
	}

	s.logger.Info("User locked successfully",
		logger.Field{Key: "user_id", Value: userID},
		logger.Field{Key: "reason", Value: reason})
	counter := s.metrics.Counter(metrics.Options{
		Name: "user_service.lock_user.success",
	})
	counter.Inc()

	return s.buildUserResponse(ctx, user)
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
	user, err := s.userRepository.GetByID(ctx, userID)
	if err != nil {
		if errors.IsErrorType(err, errors.ErrUserNotFound) {
			return nil, errors.NewUserNotFoundError(userID)
		}
		s.logger.Error("Failed to retrieve user for unlocking",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: userID})
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to retrieve user")
	}

	// Get security state to check if user is actually locked
	security, err := s.securityRepository.GetSecurity(ctx, userID)
	if err != nil {
		if errors.IsErrorType(err, errors.ErrUserNotFound) {
			// No security record means not locked
			s.logger.Info("User has no security record, treating as not locked", logger.Field{Key: "user_id", Value: userID})
			return s.buildUserResponse(ctx, user)
		}
		s.logger.Error("Failed to get security state for unlocking",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: userID})
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to get security state")
	}

	// Check if user is actually locked
	if !security.IsLocked() {
		s.logger.Info("User is not locked", logger.Field{Key: "user_id", Value: userID})
		return s.buildUserResponse(ctx, user)
	}

	// Clone security state to avoid race conditions
	securityCopy := security.Clone()

	// Unlock user account using security business logic
	securityCopy.UnlockAccount()

	// Save security state using the clone
	if err := s.securityRepository.UpdateSecurity(ctx, securityCopy); err != nil {
		s.logger.Error("Failed to update security state for unlock",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: userID})
		counter := s.metrics.Counter(metrics.Options{
			Name: "user_service.unlock_user.repository_error",
		})
		counter.Inc()
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to unlock user")
	}

	s.logger.Info("User unlocked successfully", logger.Field{Key: "user_id", Value: userID})
	counter := s.metrics.Counter(metrics.Options{
		Name: "user_service.unlock_user.success",
	})
	counter.Inc()

	return s.buildUserResponse(ctx, user)
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
	users, totalCount, err := s.userRepository.ListUsers(ctx, req.Offset, req.Limit)
	if err != nil {
		s.logger.Error("Failed to list users",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "offset", Value: req.Offset},
			logger.Field{Key: "limit", Value: req.Limit})
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to retrieve users")
	}

	// Convert to response DTOs using orchestrator pattern
	userResponses := make([]*UserResponse, len(users))
	for i, user := range users {
		if response, err := s.buildUserResponse(ctx, user); err != nil {
			// Log error but continue with basic response
			s.logger.Warn("Failed to build comprehensive response for user in list",
				logger.Field{Key: "error", Value: err.Error()},
				logger.Field{Key: "user_id", Value: user.ID})
			userResponses[i] = user.ToUserResponse(s.encrypter)
		} else {
			userResponses[i] = response
		}
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
	stats, err := s.userRepository.GetUserStats(ctx)
	if err != nil {
		s.logger.Error("Failed to get user stats", logger.Field{Key: "error", Value: err.Error()})
		return nil, errors.NewAppError(errors.CodeInternalError, "Failed to retrieve user statistics")
	}

	response := &UserStatsResponse{
		Stats:     stats,
		UpdatedAt: time.Now(),
	}

	// Cache the response
	if err := s.cache.Set(ctx, cacheKey, response, s.serviceConfig.CacheStatseTTL); err != nil {
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
	user, err := s.userRepository.GetByID(ctx, userID)
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
	if err := s.userRepository.Delete(ctx, userID); err != nil {
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

	// Remove email mapping from cache
	emailCacheKey := fmt.Sprintf("user:email:%s", user.HashedEmail)
	if err := s.cache.Delete(ctx, emailCacheKey); err != nil {
		s.logger.Warn("Failed to remove email mapping from cache",
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

// convertCredentials converts map-based credentials to provider-specific credential types.
// This follows the Adapter pattern to convert between different credential representations.
func (s *userService) convertCredentials(providerType auth.ProviderType, credentials any) (any, error) {
	// If credentials are already the correct type, return as-is
	if credentials == nil {
		return nil, errors.NewValidationError("credentials", "credentials cannot be nil")
	}

	// Handle map-based credentials (from API requests)
	credMap, ok := credentials.(map[string]any)
	if !ok {
		// If not a map, assume it's already the correct type
		return credentials, nil
	}

	switch providerType {
	case auth.ProviderTypePassword:
		passwordValue, exists := credMap["password"]
		if !exists {
			return nil, errors.NewValidationError("credentials", "password field is required for password provider")
		}
		passwordStr, ok := passwordValue.(string)
		if !ok {
			return nil, errors.NewValidationError("credentials", "password must be a string")
		}
		return &password.PasswordCredentials{
			Password: passwordStr,
		}, nil

	case auth.ProviderTypeOAuth:
		// Handle OAuth credentials conversion
		// This would be implemented when OAuth provider is added
		return nil, errors.NewValidationError("provider_type", "OAuth provider not yet implemented")

	case auth.ProviderTypeGoogle:
		// Handle Google OAuth credentials conversion
		// This would be implemented when Google provider is added
		return nil, errors.NewValidationError("provider_type", "Google provider not yet implemented")

	case auth.ProviderTypeAuth0:
		// Handle Auth0 credentials conversion
		// This would be implemented when Auth0 provider is added
		return nil, errors.NewValidationError("provider_type", "Auth0 provider not yet implemented")

	default:
		return nil, errors.NewValidationError("provider_type", fmt.Sprintf("unsupported provider type: %s", providerType))
	}
}

// buildUserResponse orchestrates data from multiple repositories to create a comprehensive UserResponse.
// This method demonstrates the service layer's role as an orchestrator, combining data from:
// - UserRepository: Profile data, status, basic metadata
// - UserSecurityRepository: Security state, login attempts, locks, last login
// - AuthenticationRepository: Available authentication providers
// This is a key Go best practice: keep business logic in the service layer.
func (s *userService) buildUserResponse(ctx context.Context, user *User) (*UserResponse, error) {
	// Start with base user response
	response := user.ToUserResponse(s.encrypter)

	// Enhance with security data from UserSecurityRepository
	if security, err := s.securityRepository.GetSecurity(ctx, user.ID); err == nil {
		response.LastLoginAt = security.LastLoginAt
		response.AccountLocked = security.IsLocked()

		// CRITICAL: Properly calculate CanAuthenticate considering both User status AND security locks
		// This is the key architectural fix - service layer orchestrates complete authentication logic
		response.CanAuthenticate = user.CanAuthenticate() && !security.IsLocked()
	} else if !errors.IsErrorType(err, errors.ErrUserNotFound) {
		// Log error but don't fail the entire request
		s.logger.Warn("Failed to get security data for user response",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: user.ID})
	}

	// Enhance with authentication provider data from AuthenticationRepository
	if providers, err := s.authRepository.GetActiveProviders(ctx, user.ID); err == nil {
		response.AvailableAuthProviders = providers
		if len(providers) > 0 {
			// Set primary provider (could be business logic to determine which is primary)
			response.PrimaryAuthProvider = providers[0]
		}
	} else if !errors.IsErrorType(err, errors.ErrUserNotFound) {
		// Log error but don't fail the entire request
		s.logger.Warn("Failed to get authentication providers for user response",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: user.ID})
	}

	// Set computed display name (requires logger for fallback)
	response.DisplayName = user.GetDisplayName(s.encrypter, s.logger)

	return response, nil
}

// buildDetailedUserResponse creates a comprehensive DetailedUserResponse with data from all repositories.
// This is used for administrative operations that need complete user information.
func (s *userService) buildDetailedUserResponse(ctx context.Context, user *User) (*DetailedUserResponse, error) {
	// Start with base detailed response
	baseResponse := user.ToDetailedUserResponse(s.encrypter)

	// Enhance with security data from UserSecurityRepository
	if security, err := s.securityRepository.GetSecurity(ctx, user.ID); err == nil {
		// Update UserResponse fields
		baseResponse.UserResponse.LastLoginAt = security.LastLoginAt
		baseResponse.UserResponse.AccountLocked = security.IsLocked()

		// CRITICAL: Properly calculate CanAuthenticate considering both User status AND security locks
		// This maintains consistency with buildUserResponse
		baseResponse.UserResponse.CanAuthenticate = user.CanAuthenticate() && !security.IsLocked()

		// Update DetailedUserResponse specific fields
		baseResponse.LoginAttempts = security.LoginAttempts
		baseResponse.LockedUntil = security.LockedUntil
	} else if !errors.IsErrorType(err, errors.ErrUserNotFound) {
		s.logger.Warn("Failed to get security data for detailed user response",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: user.ID})
	}

	// Enhance with authentication provider data
	if providers, err := s.authRepository.GetActiveProviders(ctx, user.ID); err == nil {
		baseResponse.UserResponse.AvailableAuthProviders = providers
		if len(providers) > 0 {
			baseResponse.UserResponse.PrimaryAuthProvider = providers[0]
		}
	} else if !errors.IsErrorType(err, errors.ErrUserNotFound) {
		s.logger.Warn("Failed to get authentication providers for detailed user response",
			logger.Field{Key: "error", Value: err.Error()},
			logger.Field{Key: "user_id", Value: user.ID})
	}

	// Set computed display name
	baseResponse.UserResponse.DisplayName = user.GetDisplayName(s.encrypter, s.logger)

	return baseResponse, nil
}
