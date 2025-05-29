package user

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/MichaelAJay/go-user-management/auth"
)

var (
	// emailRegex is a simple email validation regex
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
)

// Validate validates the CreateUserRequest
func (r *CreateUserRequest) Validate() error {
	if err := validateName(r.FirstName, "first name"); err != nil {
		return err
	}
	
	if err := validateName(r.LastName, "last name"); err != nil {
		return err
	}
	
	if err := validateEmail(r.Email); err != nil {
		return err
	}
	
	if r.Credentials == nil {
		return errors.New("credentials are required")
	}
	
	if err := validateAuthProvider(r.AuthenticationProvider); err != nil {
		return err
	}
	
	return nil
}

// Validate validates the UpdateProfileRequest
func (r *UpdateProfileRequest) Validate() error {
	if r.FirstName != nil {
		if err := validateName(*r.FirstName, "first name"); err != nil {
			return err
		}
	}
	
	if r.LastName != nil {
		if err := validateName(*r.LastName, "last name"); err != nil {
			return err
		}
	}
	
	if r.Email != nil {
		if err := validateEmail(*r.Email); err != nil {
			return err
		}
	}
	
	return nil
}

// Validate validates the UpdateCredentialsRequest
func (r *UpdateCredentialsRequest) Validate() error {
	if r.CurrentCredentials == nil {
		return errors.New("current credentials are required")
	}
	
	if r.NewCredentials == nil {
		return errors.New("new credentials are required")
	}
	
	if err := validateAuthProvider(r.AuthenticationProvider); err != nil {
		return err
	}
	
	return nil
}

// Validate validates the AuthenticateRequest
func (r *AuthenticateRequest) Validate() error {
	if err := validateEmail(r.Email); err != nil {
		return err
	}
	
	if r.Credentials == nil {
		return errors.New("credentials are required")
	}
	
	if err := validateAuthProvider(r.AuthenticationProvider); err != nil {
		return err
	}
	
	return nil
}

// Validate validates the ListUsersRequest
func (r *ListUsersRequest) Validate() error {
	if r.Offset < 0 {
		return errors.New("offset must be non-negative")
	}
	
	if r.Limit <= 0 {
		return errors.New("limit must be positive")
	}
	
	if r.Limit > 1000 {
		return errors.New("limit cannot exceed 1000")
	}
	
	if r.Status != "" {
		validStatuses := []string{"active", "suspended", "pending_verification", "locked", "deactivated"}
		if !contains(validStatuses, r.Status) {
			return fmt.Errorf("invalid status: %s. Valid statuses are: %s", r.Status, strings.Join(validStatuses, ", "))
		}
	}
	
	return nil
}

// Validate validates the PasswordResetRequest
func (r *PasswordResetRequest) Validate() error {
	return validateEmail(r.Email)
}

// Validate validates the CompletePasswordResetRequest
func (r *CompletePasswordResetRequest) Validate() error {
	if strings.TrimSpace(r.Token) == "" {
		return errors.New("token is required")
	}
	
	if err := validatePassword(r.NewPassword); err != nil {
		return err
	}
	
	return nil
}

// Validate validates the VerifyEmailRequest
func (r *VerifyEmailRequest) Validate() error {
	if strings.TrimSpace(r.Token) == "" {
		return errors.New("token is required")
	}
	
	return nil
}

// Validate validates the ResendVerificationRequest
func (r *ResendVerificationRequest) Validate() error {
	return validateEmail(r.Email)
}

// Helper validation functions

func validateName(name, fieldName string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return fmt.Errorf("%s is required", fieldName)
	}
	
	if len(trimmed) > 100 {
		return fmt.Errorf("%s must be 100 characters or less", fieldName)
	}
	
	return nil
}

func validateEmail(email string) error {
	trimmed := strings.TrimSpace(email)
	if trimmed == "" {
		return errors.New("email is required")
	}
	
	if len(trimmed) > 255 {
		return errors.New("email must be 255 characters or less")
	}
	
	if !emailRegex.MatchString(trimmed) {
		return errors.New("invalid email format")
	}
	
	return nil
}

func validatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}
	
	if len(password) > 128 {
		return errors.New("password must be 128 characters or less")
	}
	
	return nil
}

func validateAuthProvider(provider auth.ProviderType) error {
	if provider == "" {
		return errors.New("authentication provider is required")
	}
	
	// Add validation for known provider types if needed
	validProviders := []auth.ProviderType{
		auth.ProviderTypePassword,
		auth.ProviderTypeOAuth,
		// Add other valid providers as needed
	}
	
	for _, validProvider := range validProviders {
		if provider == validProvider {
			return nil
		}
	}
	
	return fmt.Errorf("invalid authentication provider: %s", provider)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}