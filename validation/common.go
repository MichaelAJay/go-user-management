package validation

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/MichaelAJay/go-user-management/errors"
)

// FieldValidator provides common field validation functionality.
type FieldValidator struct {
	// MaxStringLength is the default maximum length for string fields
	MaxStringLength int

	// AllowEmpty determines if empty values are allowed by default
	AllowEmpty bool
}

// NewFieldValidator creates a new FieldValidator with default settings.
func NewFieldValidator() *FieldValidator {
	return &FieldValidator{
		MaxStringLength: 255,
		AllowEmpty:      false,
	}
}

// ValidateStringField validates a string field with common rules.
func (v *FieldValidator) ValidateStringField(fieldName, value string, minLength, maxLength int, required bool) error {
	// Check if field is required
	if required && strings.TrimSpace(value) == "" {
		return errors.NewValidationError(fieldName, "field is required")
	}

	// If not required and empty, skip other validations
	if !required && strings.TrimSpace(value) == "" {
		return nil
	}

	// Check minimum length
	if len(value) < minLength {
		return errors.NewValidationError(fieldName, fmt.Sprintf("must be at least %d characters long", minLength))
	}

	// Check maximum length
	if maxLength > 0 && len(value) > maxLength {
		return errors.NewValidationError(fieldName, fmt.Sprintf("must be no more than %d characters long", maxLength))
	}

	// Check for null bytes and control characters
	if containsNullBytes(value) {
		return errors.NewValidationError(fieldName, "contains invalid characters")
	}

	return nil
}

// ValidateName validates a name field (first name, last name, etc.).
func ValidateName(name string, fieldName string) error {
	if strings.TrimSpace(name) == "" {
		return errors.NewValidationError(fieldName, "name is required")
	}

	// Check length
	if len(name) < 1 {
		return errors.NewValidationError(fieldName, "name must be at least 1 character long")
	}

	if len(name) > 100 {
		return errors.NewValidationError(fieldName, "name must be no more than 100 characters long")
	}

	// Check for valid name characters (letters, spaces, hyphens, apostrophes)
	nameRegex := regexp.MustCompile(`^[a-zA-ZÀ-ÿ\s\-'\.]+$`)
	if !nameRegex.MatchString(name) {
		return errors.NewValidationError(fieldName, "name contains invalid characters")
	}

	// Check for reasonable constraints
	if strings.Count(name, " ") > 5 {
		return errors.NewValidationError(fieldName, "name has too many spaces")
	}

	if strings.Count(name, "-") > 3 {
		return errors.NewValidationError(fieldName, "name has too many hyphens")
	}

	// Check for SQL injection patterns (basic protection)
	if containsSQLPatterns(name) {
		return errors.NewValidationError(fieldName, "name contains invalid patterns")
	}

	return nil
}

// ValidateID validates a UUID or similar ID field.
func ValidateID(id string, fieldName string) error {
	if strings.TrimSpace(id) == "" {
		return errors.NewValidationError(fieldName, "ID is required")
	}

	// Basic UUID format validation (36 characters with hyphens)
	uuidRegex := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	if !uuidRegex.MatchString(id) {
		return errors.NewValidationError(fieldName, "invalid ID format")
	}

	return nil
}

// SanitizeString removes potentially harmful characters from string input.
func SanitizeString(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")

	// Remove other control characters except newlines and tabs
	var result strings.Builder
	for _, char := range input {
		if unicode.IsPrint(char) || char == '\n' || char == '\t' {
			result.WriteRune(char)
		}
	}

	return strings.TrimSpace(result.String())
}

// SanitizeName sanitizes a name field by removing invalid characters.
func SanitizeName(name string) string {
	// Remove leading/trailing whitespace
	name = strings.TrimSpace(name)

	// Remove null bytes and control characters
	name = SanitizeString(name)

	// Remove multiple consecutive spaces
	spaceRegex := regexp.MustCompile(`\s+`)
	name = spaceRegex.ReplaceAllString(name, " ")

	// Remove invalid characters for names
	nameRegex := regexp.MustCompile(`[^a-zA-ZÀ-ÿ\s\-'\.]+`)
	name = nameRegex.ReplaceAllString(name, "")

	return name
}

// IsValidLength checks if a string meets length requirements.
func IsValidLength(value string, minLength, maxLength int) bool {
	length := len(value)
	return length >= minLength && (maxLength <= 0 || length <= maxLength)
}

// ContainsOnlyAlphanumeric checks if a string contains only alphanumeric characters.
func ContainsOnlyAlphanumeric(value string) bool {
	alphanumericRegex := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	return alphanumericRegex.MatchString(value)
}

// ContainsOnlyLetters checks if a string contains only letters.
func ContainsOnlyLetters(value string) bool {
	letterRegex := regexp.MustCompile(`^[a-zA-ZÀ-ÿ]+$`)
	return letterRegex.MatchString(value)
}

// ContainsOnlyNumbers checks if a string contains only numbers.
func ContainsOnlyNumbers(value string) bool {
	numberRegex := regexp.MustCompile(`^[0-9]+$`)
	return numberRegex.MatchString(value)
}

// HasValidCharacterDistribution checks if a string has a reasonable character distribution.
// This helps detect obvious invalid inputs like all the same character.
func HasValidCharacterDistribution(value string, maxSameChar float64) bool {
	if len(value) == 0 {
		return true
	}

	charCount := make(map[rune]int)
	for _, char := range value {
		charCount[char]++
	}

	totalLength := float64(len(value))
	for _, count := range charCount {
		if float64(count)/totalLength > maxSameChar {
			return false
		}
	}

	return true
}

// ValidateVersion validates an optimistic locking version number.
func ValidateVersion(version int64, fieldName string) error {
	if version <= 0 {
		return errors.NewValidationError(fieldName, "version must be positive")
	}
	return nil
}

// containsNullBytes checks if a string contains null bytes or other control characters.
func containsNullBytes(value string) bool {
	for _, char := range value {
		if char == 0 || (unicode.IsControl(char) && char != '\n' && char != '\t' && char != '\r') {
			return true
		}
	}
	return false
}

// containsSQLPatterns checks for basic SQL injection patterns.
func containsSQLPatterns(value string) bool {
	// Convert to lowercase for pattern matching
	lower := strings.ToLower(value)

	// Common SQL injection patterns
	patterns := []string{
		"'",
		"\"",
		";",
		"--",
		"/*",
		"*/",
		"union",
		"select",
		"insert",
		"update",
		"delete",
		"drop",
		"create",
		"alter",
		"exec",
		"execute",
		"script",
		"<script",
		"</script>",
		"javascript:",
		"vbscript:",
		"onload=",
		"onerror=",
	}

	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	return false
}

// ValidationResult represents the result of a validation operation.
type ValidationResult struct {
	IsValid   bool     `json:"is_valid"`
	Errors    []string `json:"errors,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
	Sanitized string   `json:"sanitized,omitempty"`
}

// ValidateAndSanitizeInput performs comprehensive validation and sanitization.
func ValidateAndSanitizeInput(input, fieldName string, minLength, maxLength int, required bool) *ValidationResult {
	result := &ValidationResult{
		IsValid:  true,
		Errors:   []string{},
		Warnings: []string{},
	}

	// Sanitize the input
	sanitized := SanitizeString(input)
	result.Sanitized = sanitized

	// Validate the sanitized input
	validator := NewFieldValidator()
	if err := validator.ValidateStringField(fieldName, sanitized, minLength, maxLength, required); err != nil {
		result.IsValid = false
		if appErr, ok := err.(*errors.AppError); ok {
			result.Errors = append(result.Errors, appErr.Message)
		} else {
			result.Errors = append(result.Errors, err.Error())
		}
	}

	// Add warnings if the input was modified during sanitization
	if input != sanitized {
		result.Warnings = append(result.Warnings, "Input was sanitized to remove invalid characters")
	}

	// Check character distribution
	if !HasValidCharacterDistribution(sanitized, 0.8) {
		result.Warnings = append(result.Warnings, "Input has unusual character distribution")
	}

	return result
}

// BatchValidationResult represents the result of validating multiple fields.
type BatchValidationResult struct {
	IsValid bool                         `json:"is_valid"`
	Fields  map[string]*ValidationResult `json:"fields"`
	Summary []string                     `json:"summary,omitempty"`
}

// NewBatchValidationResult creates a new BatchValidationResult.
func NewBatchValidationResult() *BatchValidationResult {
	return &BatchValidationResult{
		IsValid: true,
		Fields:  make(map[string]*ValidationResult),
		Summary: []string{},
	}
}

// AddFieldResult adds a field validation result to the batch.
func (b *BatchValidationResult) AddFieldResult(fieldName string, result *ValidationResult) {
	b.Fields[fieldName] = result
	if !result.IsValid {
		b.IsValid = false
	}
}

// GetSummary returns a summary of validation errors.
func (b *BatchValidationResult) GetSummary() []string {
	var summary []string
	for fieldName, result := range b.Fields {
		if !result.IsValid {
			for _, err := range result.Errors {
				summary = append(summary, fmt.Sprintf("%s: %s", fieldName, err))
			}
		}
	}
	return summary
}
