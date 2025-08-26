package config

import (
	"fmt"
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
	if _, ok := QClassMap[dnsRequest.Question.Class]; !ok {
		validateErrs = append(validateErrs, fmt.Errorf("invalid question class: %s", dnsRequest.Question.Class))
	}

	if len(validateErrs) > 0 {
		return validateErrs
	}

	return nil
}
