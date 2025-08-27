package config

import (
	"strings"
	"time"
)

// =============================================================================
// UTILITY METHODS
// =============================================================================

// GetTimeouts returns server timeouts as time.Duration values
func (s *ServerConfig) GetTimeouts() (read, write time.Duration) {
	return time.Duration(s.ReadTimeout) * time.Second,
		time.Duration(s.WriteTimeout) * time.Second
}

// FindZone searches for a zone that can answer queries for the given domain
func (c *DNSServerConfig) FindZone(domain string) *ZoneConfig {
	// Ensure domain ends with dot
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}

	// Convert to lowercase for comparison (DNS is case-insensitive)
	domain = strings.ToLower(domain)

	// Look for exact matches first, then parent zones
	for _, zone := range c.Zones {
		zoneName := strings.ToLower(zone.Name)
		if domain == zoneName || strings.HasSuffix(domain, "."+zoneName) {
			return &zone
		}
	}

	return nil
}

// IsAuthoritative checks if this server is authoritative for a domain
func (c *DNSServerConfig) IsAuthoritative(domain string) bool {
	return c.FindZone(domain) != nil
}
