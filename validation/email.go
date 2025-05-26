package validation

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/MichaelAJay/go-user-management/errors"
)

// EmailValidator provides email validation functionality.
// It includes format validation, domain validation, and normalization.
type EmailValidator struct {
	// AllowedDomains is a list of allowed email domains.
	// If empty, all domains are allowed.
	AllowedDomains []string

	// BlockedDomains is a list of blocked email domains.
	BlockedDomains []string

	// RequireTLD specifies whether a top-level domain is required.
	RequireTLD bool

	// MaxLength is the maximum allowed email length.
	MaxLength int

	// DisposableEmailDomains is a list of known disposable email domains.
	DisposableEmailDomains []string

	// AllowDisposableEmails determines whether disposable emails are allowed.
	AllowDisposableEmails bool
}

// NewEmailValidator creates a new EmailValidator with default settings.
func NewEmailValidator() *EmailValidator {
	return &EmailValidator{
		RequireTLD:             true,
		MaxLength:              255,
		AllowDisposableEmails:  false,
		DisposableEmailDomains: getDefaultDisposableEmailDomains(),
	}
}

// RFC 5322 compliant email regex (simplified version)
// This regex is more permissive than the full RFC 5322 specification for practical use
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

// Simple email regex for basic validation
var simpleEmailRegex = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

// ValidateEmail validates an email address according to the configured rules.
func (v *EmailValidator) ValidateEmail(email string) error {
	if email == "" {
		return errors.NewValidationError("email", "email is required")
	}

	// Normalize the email
	normalizedEmail := v.NormalizeEmail(email)

	// Check length
	if len(normalizedEmail) > v.MaxLength {
		return errors.NewValidationError("email", fmt.Sprintf("email exceeds maximum length of %d characters", v.MaxLength))
	}

	// Basic format validation
	if !v.isValidFormat(normalizedEmail) {
		return errors.NewValidationError("email", "invalid email format")
	}

	// Extract domain
	domain := v.extractDomain(normalizedEmail)
	if domain == "" {
		return errors.NewValidationError("email", "invalid email domain")
	}

	// Check if domain is allowed
	if err := v.validateDomain(domain); err != nil {
		return err
	}

	// Check for disposable emails
	if !v.AllowDisposableEmails && v.isDisposableEmail(domain) {
		return errors.NewValidationError("email", "disposable email addresses are not allowed")
	}

	return nil
}

// NormalizeEmail normalizes an email address by converting to lowercase and trimming whitespace.
func (v *EmailValidator) NormalizeEmail(email string) string {
	// Trim whitespace
	email = strings.TrimSpace(email)

	// Convert to lowercase
	email = strings.ToLower(email)

	return email
}

// isValidFormat checks if the email format is valid using regex.
func (v *EmailValidator) isValidFormat(email string) bool {
	// Use the more comprehensive regex for validation
	if !emailRegex.MatchString(email) {
		// Fallback to simple regex for edge cases
		return simpleEmailRegex.MatchString(email)
	}
	return true
}

// extractDomain extracts the domain part from an email address.
func (v *EmailValidator) extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

// validateDomain validates the domain according to the configured rules.
func (v *EmailValidator) validateDomain(domain string) error {
	// Check if domain is blocked
	for _, blocked := range v.BlockedDomains {
		if strings.EqualFold(domain, blocked) {
			return errors.NewValidationError("email", fmt.Sprintf("domain %s is not allowed", domain))
		}
	}

	// Check if domain is in allowed list (if configured)
	if len(v.AllowedDomains) > 0 {
		allowed := false
		for _, allowedDomain := range v.AllowedDomains {
			if strings.EqualFold(domain, allowedDomain) {
				allowed = true
				break
			}
		}
		if !allowed {
			return errors.NewValidationError("email", fmt.Sprintf("domain %s is not in the allowed domains list", domain))
		}
	}

	// Check TLD requirement
	if v.RequireTLD && !strings.Contains(domain, ".") {
		return errors.NewValidationError("email", "email domain must include a top-level domain")
	}

	return nil
}

// isDisposableEmail checks if the domain is a known disposable email provider.
func (v *EmailValidator) isDisposableEmail(domain string) bool {
	for _, disposable := range v.DisposableEmailDomains {
		if strings.EqualFold(domain, disposable) {
			return true
		}
	}
	return false
}

// getDefaultDisposableEmailDomains returns a list of common disposable email domains.
// This list can be expanded based on requirements.
func getDefaultDisposableEmailDomains() []string {
	return []string{
		"10minutemail.com",
		"mailinator.com",
		"guerrillamail.com",
		"temp-mail.org",
		"throwaway.email",
		"yopmail.com",
		"maildrop.cc",
		"fakeinbox.com",
		"mailcatch.com",
		"tempail.com",
		"dispostable.com",
		"trashmail.com",
		"sharklasers.com",
		"guerrillamailblock.com",
		"pokemail.net",
		"spam4.me",
		"trbvm.com",
		"klzlk.com",
		"beerolympics.se",
		"chammy.info",
	}
}

// IsValidEmailDomain checks if a domain is valid for email addresses.
// This is a utility function for domain validation without full email validation.
func IsValidEmailDomain(domain string) bool {
	if domain == "" {
		return false
	}

	// Basic domain format check
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return domainRegex.MatchString(domain)
}

// SanitizeEmail removes potentially harmful characters from email input.
// This is useful for preventing injection attacks in email-related operations.
func SanitizeEmail(email string) string {
	// Remove null bytes and control characters
	email = strings.ReplaceAll(email, "\x00", "")

	// Remove carriage returns and line feeds to prevent header injection
	email = strings.ReplaceAll(email, "\r", "")
	email = strings.ReplaceAll(email, "\n", "")

	// Remove tabs
	email = strings.ReplaceAll(email, "\t", "")

	return strings.TrimSpace(email)
}
