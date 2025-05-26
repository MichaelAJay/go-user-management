package validation

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode"

	"github.com/MichaelAJay/go-user-management/errors"
)

// PasswordValidator provides password validation functionality.
// It includes strength checking, entropy calculation, and common password detection.
type PasswordValidator struct {
	// MinLength is the minimum required password length.
	MinLength int

	// MaxLength is the maximum allowed password length.
	MaxLength int

	// RequireUppercase specifies whether uppercase letters are required.
	RequireUppercase bool

	// RequireLowercase specifies whether lowercase letters are required.
	RequireLowercase bool

	// RequireNumbers specifies whether numbers are required.
	RequireNumbers bool

	// RequireSpecialChars specifies whether special characters are required.
	RequireSpecialChars bool

	// MinEntropy is the minimum entropy score required (bits).
	MinEntropy float64

	// ForbiddenPasswords is a list of forbidden common passwords.
	ForbiddenPasswords []string

	// ForbidUserInfo specifies whether passwords containing user info are forbidden.
	ForbidUserInfo bool

	// AllowedSpecialChars defines which special characters are allowed.
	// If empty, all special characters are allowed.
	AllowedSpecialChars string

	// MinUniqueChars is the minimum number of unique characters required.
	MinUniqueChars int

	// MaxRepeatingChars is the maximum number of consecutive repeating characters.
	MaxRepeatingChars int
}

// NewPasswordValidator creates a new PasswordValidator with secure default settings.
func NewPasswordValidator() *PasswordValidator {
	return &PasswordValidator{
		MinLength:           8,
		MaxLength:           128,
		RequireUppercase:    true,
		RequireLowercase:    true,
		RequireNumbers:      true,
		RequireSpecialChars: true,
		MinEntropy:          30.0, // Reasonable entropy requirement
		ForbiddenPasswords:  getDefaultForbiddenPasswords(),
		ForbidUserInfo:      true,
		AllowedSpecialChars: "!@#$%^&*()_+-=[]{}|;:,.<>?",
		MinUniqueChars:      6,
		MaxRepeatingChars:   3,
	}
}

// PasswordStrength represents the strength level of a password.
type PasswordStrength int

const (
	PasswordStrengthVeryWeak PasswordStrength = iota
	PasswordStrengthWeak
	PasswordStrengthFair
	PasswordStrengthGood
	PasswordStrengthStrong
	PasswordStrengthVeryStrong
)

// String returns the string representation of PasswordStrength.
func (s PasswordStrength) String() string {
	switch s {
	case PasswordStrengthVeryWeak:
		return "very_weak"
	case PasswordStrengthWeak:
		return "weak"
	case PasswordStrengthFair:
		return "fair"
	case PasswordStrengthGood:
		return "good"
	case PasswordStrengthStrong:
		return "strong"
	case PasswordStrengthVeryStrong:
		return "very_strong"
	default:
		return "unknown"
	}
}

// PasswordValidationResult contains the result of password validation.
type PasswordValidationResult struct {
	IsValid      bool             `json:"is_valid"`
	Strength     PasswordStrength `json:"strength"`
	Entropy      float64          `json:"entropy"`
	Errors       []string         `json:"errors,omitempty"`
	Suggestions  []string         `json:"suggestions,omitempty"`
	MeetsMinimum bool             `json:"meets_minimum"`
}

// ValidatePassword validates a password according to the configured rules.
func (v *PasswordValidator) ValidatePassword(password string) error {
	result := v.AnalyzePassword(password, nil)

	if !result.IsValid {
		return errors.NewWeakPasswordError(strings.Join(result.Errors, "; "))
	}

	return nil
}

// ValidatePasswordWithUserInfo validates a password with user information context.
func (v *PasswordValidator) ValidatePasswordWithUserInfo(password string, userInfo *UserInfo) error {
	result := v.AnalyzePassword(password, userInfo)

	if !result.IsValid {
		return errors.NewWeakPasswordError(strings.Join(result.Errors, "; "))
	}

	return nil
}

// AnalyzePassword performs comprehensive password analysis.
func (v *PasswordValidator) AnalyzePassword(password string, userInfo *UserInfo) *PasswordValidationResult {
	result := &PasswordValidationResult{
		IsValid:     true,
		Errors:      []string{},
		Suggestions: []string{},
	}

	// Check length requirements
	if len(password) < v.MinLength {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("password must be at least %d characters long", v.MinLength))
		result.Suggestions = append(result.Suggestions, "Use a longer password")
	}

	if len(password) > v.MaxLength {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("password must be no more than %d characters long", v.MaxLength))
	}

	// Check character requirements
	v.checkCharacterRequirements(password, result)

	// Check for forbidden passwords
	if v.isForbiddenPassword(password) {
		result.IsValid = false
		result.Errors = append(result.Errors, "password is too common and easily guessed")
		result.Suggestions = append(result.Suggestions, "Use a more unique password")
	}

	// Check user info requirements
	if v.ForbidUserInfo && userInfo != nil {
		if v.containsUserInfo(password, userInfo) {
			result.IsValid = false
			result.Errors = append(result.Errors, "password should not contain personal information")
			result.Suggestions = append(result.Suggestions, "Avoid using your name, email, or other personal information")
		}
	}

	// Check unique characters
	if v.countUniqueChars(password) < v.MinUniqueChars {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("password must contain at least %d unique characters", v.MinUniqueChars))
		result.Suggestions = append(result.Suggestions, "Use more varied characters")
	}

	// Check repeating characters
	if v.hasExcessiveRepeating(password) {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("password should not have more than %d consecutive repeating characters", v.MaxRepeatingChars))
		result.Suggestions = append(result.Suggestions, "Avoid repeating the same character consecutively")
	}

	// Calculate entropy
	result.Entropy = v.calculateEntropy(password)
	if result.Entropy < v.MinEntropy {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("password entropy is too low (%.1f bits, minimum %.1f required)", result.Entropy, v.MinEntropy))
		result.Suggestions = append(result.Suggestions, "Use a more complex password with varied characters")
	}

	// Determine strength
	result.Strength = v.determineStrength(password, result.Entropy)
	result.MeetsMinimum = result.IsValid

	return result
}

// checkCharacterRequirements checks if the password meets character type requirements.
func (v *PasswordValidator) checkCharacterRequirements(password string, result *PasswordValidationResult) {
	hasUpper := false
	hasLower := false
	hasNumber := false
	hasSpecial := false

	for _, char := range password {
		if unicode.IsUpper(char) {
			hasUpper = true
		} else if unicode.IsLower(char) {
			hasLower = true
		} else if unicode.IsNumber(char) {
			hasNumber = true
		} else if v.isAllowedSpecialChar(char) {
			hasSpecial = true
		}
	}

	if v.RequireUppercase && !hasUpper {
		result.IsValid = false
		result.Errors = append(result.Errors, "password must contain at least one uppercase letter")
		result.Suggestions = append(result.Suggestions, "Add uppercase letters")
	}

	if v.RequireLowercase && !hasLower {
		result.IsValid = false
		result.Errors = append(result.Errors, "password must contain at least one lowercase letter")
		result.Suggestions = append(result.Suggestions, "Add lowercase letters")
	}

	if v.RequireNumbers && !hasNumber {
		result.IsValid = false
		result.Errors = append(result.Errors, "password must contain at least one number")
		result.Suggestions = append(result.Suggestions, "Add numbers")
	}

	if v.RequireSpecialChars && !hasSpecial {
		result.IsValid = false
		result.Errors = append(result.Errors, "password must contain at least one special character")
		if v.AllowedSpecialChars != "" {
			result.Suggestions = append(result.Suggestions, fmt.Sprintf("Add special characters from: %s", v.AllowedSpecialChars))
		} else {
			result.Suggestions = append(result.Suggestions, "Add special characters")
		}
	}
}

// isAllowedSpecialChar checks if a character is an allowed special character.
func (v *PasswordValidator) isAllowedSpecialChar(char rune) bool {
	if v.AllowedSpecialChars == "" {
		// If no specific allowed chars, consider any non-alphanumeric as special
		return !unicode.IsLetter(char) && !unicode.IsNumber(char) && !unicode.IsSpace(char)
	}

	return strings.ContainsRune(v.AllowedSpecialChars, char)
}

// isForbiddenPassword checks if the password is in the forbidden list.
func (v *PasswordValidator) isForbiddenPassword(password string) bool {
	lowerPassword := strings.ToLower(password)
	for _, forbidden := range v.ForbiddenPasswords {
		if strings.ToLower(forbidden) == lowerPassword {
			return true
		}
	}
	return false
}

// containsUserInfo checks if the password contains user information.
func (v *PasswordValidator) containsUserInfo(password string, userInfo *UserInfo) bool {
	if userInfo == nil {
		return false
	}

	lowerPassword := strings.ToLower(password)

	// Check various user info fields
	userFields := []string{
		userInfo.FirstName,
		userInfo.LastName,
		userInfo.Email,
		userInfo.Username,
	}

	for _, field := range userFields {
		if field != "" && len(field) >= 3 {
			if strings.Contains(lowerPassword, strings.ToLower(field)) {
				return true
			}
		}
	}

	// Check email local part
	if userInfo.Email != "" {
		emailParts := strings.Split(userInfo.Email, "@")
		if len(emailParts) > 0 && len(emailParts[0]) >= 3 {
			if strings.Contains(lowerPassword, strings.ToLower(emailParts[0])) {
				return true
			}
		}
	}

	return false
}

// countUniqueChars counts the number of unique characters in the password.
func (v *PasswordValidator) countUniqueChars(password string) int {
	charSet := make(map[rune]bool)
	for _, char := range password {
		charSet[char] = true
	}
	return len(charSet)
}

// hasExcessiveRepeating checks for excessive consecutive repeating characters.
func (v *PasswordValidator) hasExcessiveRepeating(password string) bool {
	if len(password) <= v.MaxRepeatingChars {
		return false
	}

	count := 1
	for i := 1; i < len(password); i++ {
		if password[i] == password[i-1] {
			count++
			if count > v.MaxRepeatingChars {
				return true
			}
		} else {
			count = 1
		}
	}

	return false
}

// calculateEntropy calculates the entropy of a password in bits.
func (v *PasswordValidator) calculateEntropy(password string) float64 {
	if len(password) == 0 {
		return 0
	}

	// Determine character set size
	charSetSize := 0

	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[^a-zA-Z0-9]`).MatchString(password)

	if hasLower {
		charSetSize += 26
	}
	if hasUpper {
		charSetSize += 26
	}
	if hasNumber {
		charSetSize += 10
	}
	if hasSpecial {
		charSetSize += 32 // Approximate number of common special characters
	}

	if charSetSize == 0 {
		return 0
	}

	// Calculate entropy: log2(charSetSize) * length
	return math.Log2(float64(charSetSize)) * float64(len(password))
}

// determineStrength determines the overall strength of the password.
func (v *PasswordValidator) determineStrength(password string, entropy float64) PasswordStrength {
	// Base strength on entropy
	switch {
	case entropy >= 80:
		return PasswordStrengthVeryStrong
	case entropy >= 60:
		return PasswordStrengthStrong
	case entropy >= 40:
		return PasswordStrengthGood
	case entropy >= 25:
		return PasswordStrengthFair
	case entropy >= 15:
		return PasswordStrengthWeak
	default:
		return PasswordStrengthVeryWeak
	}
}

// UserInfo contains user information for password validation context.
type UserInfo struct {
	FirstName string
	LastName  string
	Email     string
	Username  string
}

// getDefaultForbiddenPasswords returns a list of commonly used weak passwords.
func getDefaultForbiddenPasswords() []string {
	return []string{
		"password", "123456", "12345678", "qwerty", "abc123",
		"password123", "admin", "letmein", "welcome", "monkey",
		"1234567890", "password1", "123456789", "welcome123",
		"admin123", "qwerty123", "iloveyou", "princess", "dragon",
		"123123", "654321", "superman", "qazwsx", "michael",
		"football", "baseball", "liverpool", "jordan", "shadow",
		"master", "jennifer", "111111", "2000", "jordan23",
	}
}
