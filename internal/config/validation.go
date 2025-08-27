package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ValidateMainConfig checks if the main configuration is valid
func (c *Config) ValidateMainConfig() error {
	if c.ClientAddr == "" {
		return fmt.Errorf("agent address cannot be empty")
	}

	if c.ServerAddr == "" {
		return fmt.Errorf("server address cannot be empty")
	}

	if c.Delay <= 0 {
		return fmt.Errorf("delay must be positive")
	}

	if c.Jitter < 0 || c.Jitter > 100 {
		return fmt.Errorf("jitter must be between 0 and 100")
	}

	if c.TlsCert == "" {
		return fmt.Errorf("tls cert cannot be empty")
	}

	if c.TlsKey == "" {
		return fmt.Errorf("tls cert cannot be empty")
	}

	if c.PathToRequestYAML == "" {
		return fmt.Errorf("yaml request config cannot be empty")
	}

	if _, err := os.Stat(c.PathToRequestYAML); os.IsNotExist(err) {
		return fmt.Errorf("request YAML file does not exist: %s", c.PathToRequestYAML)
	}

	if c.PathToResponseYAML == "" {
		return fmt.Errorf("yaml response config cannot be empty")
	}

	if _, err := os.Stat(c.PathToResponseYAML); os.IsNotExist(err) {
		return fmt.Errorf("response YAML file does not exist: %s", c.PathToResponseYAML)
	}

	if c.Protocol != "https" && c.Protocol != "wss" && c.Protocol != "dns" {
		return fmt.Errorf("desired protocol not yet implemented, please select either: dns, htttps, wss")
	}

	return nil
}

// ValidationErrors is a custom error type that holds a slice of validation errors (allows for 1+)
type ValidationErrors []error

// Error implements the error interface for ValidationErrors.
// It joins all the underlying errors into a single string.
func (v ValidationErrors) Error() string {
	var b strings.Builder

	b.WriteString("validation failed with the following errors:\n")
	for _, err := range v {
		b.WriteString(fmt.Sprintf("- %s\n", err))
	}
	return b.String()
}

func ValidateRequest(dnsRequest *DNSRequest) error {

	var validateErrs ValidationErrors

	// HEADER SECTION VALIDATION

	// make sure Header.OpCode appears in our OpCodeMap
	if _, ok := OpCodeMap[dnsRequest.Header.OpCode]; !ok {
		validateErrs = append(validateErrs, fmt.Errorf("invalid opcode: %s", dnsRequest.Header.OpCode))
	}

	// make sure Header.Z is not >7 (note uint8 already ensure it's >=0)
	if dnsRequest.Header.Z > 7 {
		validateErrs = append(validateErrs, fmt.Errorf("Z flag must be between 0 and 7, but got %d", dnsRequest.Header.Z))
	}

	// make sure Header.RCode is not >15 (note uint8 already ensure it's >=0)
	if dnsRequest.Header.RCode > 15 {
		validateErrs = append(validateErrs, fmt.Errorf("RCode must be between 0 and 15, but got %d", dnsRequest.Header.RCode))
	}

	// QUESTION SECTION VALIDATION
	// make sure Question.Type appears in our QTypeMap
	if _, ok := QTypeMap[dnsRequest.Question.Type]; !ok {
		validateErrs = append(validateErrs, fmt.Errorf("invalid question type: %s", dnsRequest.Question.Type))
	}

	// make sure Question.Class appears in our QClassMap
	if dnsRequest.Question.StdClass {
		// Standard class mode - check if it's in our map
		if _, ok := QClassMap[dnsRequest.Question.Class]; !ok {
			validateErrs = append(validateErrs, fmt.Errorf("invalid standard question class: %s", dnsRequest.Question.Class))
		}
	}

	if len(validateErrs) > 0 {
		return validateErrs
	}

	return nil
}

func ValidateResponse(dnsResponse *DNSResponse) error {
	var validateErrs ValidationErrors

	// HEADER SECTION VALIDATION
	if _, ok := OpCodeMap[dnsResponse.Header.OpCode]; !ok {
		validateErrs = append(validateErrs, fmt.Errorf("invalid opcode: %s", dnsResponse.Header.OpCode))
	}

	if dnsResponse.Header.Z > 7 {
		validateErrs = append(validateErrs, fmt.Errorf("Z flag must be between 0 and 7, but got %d", dnsResponse.Header.Z))
	}

	if dnsResponse.Header.RCode > 15 {
		validateErrs = append(validateErrs, fmt.Errorf("RCode must be between 0 and 15, but got %d", dnsResponse.Header.RCode))
	}

	// QUESTION SECTION VALIDATION
	if _, ok := QTypeMap[dnsResponse.Question.Type]; !ok {
		validateErrs = append(validateErrs, fmt.Errorf("invalid question type: %s", dnsResponse.Question.Type))
	}

	// make sure Question.Class appears in our QClassMap
	if dnsResponse.Question.StdClass {
		// Standard class mode - check if it's in our map
		if _, ok := QClassMap[dnsResponse.Question.Class]; !ok {
			validateErrs = append(validateErrs, fmt.Errorf("invalid standard question class: %s", dnsResponse.Question.Class))
		}
	}

	// ANSWER SECTION VALIDATION - handle multiple answers
	for i, answer := range dnsResponse.Answers {
		if err := validateAnswer(&answer, i); err != nil {
			validateErrs = append(validateErrs, err)
		}
	}

	if len(validateErrs) > 0 {
		return validateErrs
	}

	return nil
}

func validateAnswer(answer *Answer, index int) error {
	// Validate Type
	if _, ok := QTypeMap[answer.Type]; !ok {
		return fmt.Errorf("answer[%d]: invalid type: %s", index, answer.Type)
	}

	// Validate Class
	if _, ok := QClassMap[answer.Class]; !ok {
		return fmt.Errorf("answer[%d]: invalid class: %s", index, answer.Class)
	}

	// Validate TTL
	if answer.TTL > MaxTTL {
		return fmt.Errorf("answer[%d]: TTL %d exceeds maximum %d", index, answer.TTL, MaxTTL)
	}

	// Validate Name (domain name validation)
	if err := validateDomainName(answer.Name); err != nil {
		return fmt.Errorf("answer[%d]: invalid name: %w", index, err)
	}

	// Validate Data based on record type
	if err := validateAnswerData(answer.Type, answer.Data); err != nil {
		return fmt.Errorf("answer[%d]: invalid data for type %s: %w", index, answer.Type, err)
	}

	return nil
}

func validateDomainName(name string) error {
	if name == "" {
		return fmt.Errorf("domain name cannot be empty")
	}

	if len(name) > MaxDomainNameLength {
		return fmt.Errorf("domain name too long: %d characters (max %d)", len(name), MaxDomainNameLength)
	}

	// Split into labels and validate each
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for _, label := range labels {
		if len(label) == 0 {
			return fmt.Errorf("empty label in domain name")
		}
		if len(label) > MaxLabelLength {
			return fmt.Errorf("label '%s' too long: %d characters (max %d)", label, len(label), MaxLabelLength)
		}

		// Basic character validation for labels
		for i, char := range label {
			if !((char >= 'a' && char <= 'z') ||
				(char >= 'A' && char <= 'Z') ||
				(char >= '0' && char <= '9') ||
				(char == '-' && i != 0 && i != len(label)-1)) { // hyphens not at start/end
				return fmt.Errorf("invalid character '%c' in label '%s'", char, label)
			}
		}
	}

	return nil
}

func validateAnswerData(recordType, data string) error {
	if data == "" {
		return fmt.Errorf("data cannot be empty")
	}

	switch recordType {
	case "A":
		return validateIPv4(data)
	case "CNAME":
		return validateDomainName(data)
	case "TXT":
		return validateTXTData(data)
	default:
		// For other record types, just do basic non-empty validation
		return nil
	}
}

func validateIPv4(ip string) error {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return fmt.Errorf("invalid IPv4 format: must have 4 octets")
	}

	for i, part := range parts {
		if len(part) == 0 {
			return fmt.Errorf("empty octet at position %d", i+1)
		}

		// Check for leading zeros (except for "0" itself)
		if len(part) > 1 && part[0] == '0' {
			return fmt.Errorf("octet %d has leading zero: %s", i+1, part)
		}

		if num, err := strconv.Atoi(part); err != nil || num < 0 || num > 255 {
			return fmt.Errorf("invalid IPv4 octet %d: %s (must be 0-255)", i+1, part)
		}
	}
	return nil
}

func validateTXTData(data string) error {
	if len(data) > MaxTXTRecordLength {
		return fmt.Errorf("TXT data too long: %d characters (max %d)", len(data), MaxTXTRecordLength)
	}

	// TXT records should not contain null bytes
	if strings.Contains(data, "\x00") {
		return fmt.Errorf("TXT data contains null byte")
	}

	return nil
}
