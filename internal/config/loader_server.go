package config

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
)

// ConfigLoader handles loading and validating configuration files
type ConfigLoader struct {
	serverConfigPath string
	mainConfigPath   string
	serverConfig     *DNSServerConfig
	mainConfig       *Config
}

// NewConfigLoader is ConfigLoader's constructor
func NewConfigLoader(serverPath string, mainPath string) *ConfigLoader {
	return &ConfigLoader{
		serverConfigPath: serverPath,
		mainConfigPath:   mainPath,
	}
}

// Load reads, validates, and parses/unmarshalls both the SERVER and MAIN configuration files
func (cl *ConfigLoader) Load() (*DNSServerConfig, *Config, error) {

	// A. First just handle the DNS Server Config
	// Step 1: Ensure that config file exists
	if _, err := os.Stat(cl.serverConfigPath); os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("configuration file not found: %s", cl.serverConfigPath)
	}

	// Step 2: Read the file
	yamlServerData, err := os.ReadFile(cl.serverConfigPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read configuration file: %w", err)
	}

	// Step 3: Parse YAML
	var serverConfig DNSServerConfig
	if err := yaml.Unmarshal(yamlServerData, &serverConfig); err != nil {
		return nil, nil, fmt.Errorf("failed to parse YAML configuration: %w", err)
	}

	// Step 4: Apply defaults for missing values
	cl.applyDefaults(&serverConfig)

	// Step 5: Validate the configuration
	if err := serverConfig.Validate(); err != nil {
		return nil, nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	// ------------------------------------------------------------------------------

	// B. Now handle the Main Config
	// Step 1: Ensure that config file exists
	if _, err := os.Stat(cl.mainConfigPath); os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("configuration file not found: %s", cl.mainConfigPath)
	}

	// Step 2: Read the file
	yamlMainData, err := os.ReadFile(cl.mainConfigPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read configuration file: %w", err)
	}

	// Step 3: Parse YAML
	var mainConfig Config
	if err := yaml.Unmarshal(yamlMainData, &mainConfig); err != nil {
		return nil, nil, fmt.Errorf("failed to parse YAML configuration: %w", err)
	}

	cl.serverConfig = &serverConfig
	cl.mainConfig = &mainConfig

	return &serverConfig, &mainConfig, nil

}

// applyDefaults sets sensible default values for any missing configuration
func (cl *ConfigLoader) applyDefaults(config *DNSServerConfig) {
	// Server defaults
	if config.Server.BindAddress == "" {
		config.Server.BindAddress = "0.0.0.0"
	}
	if config.Server.Port == 0 {
		config.Server.Port = 53
	}
	if config.Server.MaxWorkers == 0 {
		config.Server.MaxWorkers = 4
	}
	if config.Server.ReadTimeout == 0 {
		config.Server.ReadTimeout = 5
	}
	if config.Server.WriteTimeout == 0 {
		config.Server.WriteTimeout = 3
	}
	if config.Server.MaxPacketSize == 0 {
		config.Server.MaxPacketSize = 512
	}

	// Logging defaults
	if config.Logging.Level == "" {
		config.Logging.Level = "INFO"
	}
	if config.Logging.Format == "" {
		config.Logging.Format = "TEXT"
	}
	if config.Logging.Output == "" {
		config.Logging.Output = "STDOUT"
	}

	// Security defaults
	if config.Security.ResponsePolicies.MinimumTTL == 0 {
		config.Security.ResponsePolicies.MinimumTTL = 60
	}
	if config.Security.ResponsePolicies.MaximumTTL == 0 {
		config.Security.ResponsePolicies.MaximumTTL = 86400
	}

	// Apply defaults to each zone
	for i := range config.Zones {
		cl.applyZoneDefaults(&config.Zones[i])
	}
}

// applyZoneDefaults sets default values for zone configuration
func (cl *ConfigLoader) applyZoneDefaults(zone *ZoneConfig) {
	// Default TTL if not specified
	if zone.TTL == 0 {
		zone.TTL = 300
	}

	// Apply default TTLs to records that don't have them
	for i := range zone.ARecords {
		if zone.ARecords[i].TTL == 0 {
			zone.ARecords[i].TTL = zone.TTL
		}
	}

	for i := range zone.AAAARecords {
		if zone.AAAARecords[i].TTL == 0 {
			zone.AAAARecords[i].TTL = zone.TTL
		}
	}

	for i := range zone.CNAMERecords {
		if zone.CNAMERecords[i].TTL == 0 {
			zone.CNAMERecords[i].TTL = zone.TTL
		}
	}

	for i := range zone.MXRecords {
		if zone.MXRecords[i].TTL == 0 {
			zone.MXRecords[i].TTL = zone.TTL
		}
	}

	for i := range zone.TXTRecords {
		if zone.TXTRecords[i].TTL == 0 {
			zone.TXTRecords[i].TTL = zone.TTL
		}
	}
}

// PrintConfiguration displays the loaded server configuration in a human-readable format
func (cl *ConfigLoader) PrintConfiguration() {
	if cl.serverConfig == nil {
		fmt.Println("No configuration loaded")
		return
	}

	fmt.Println("=== DNS Server Configuration ===")
	fmt.Printf("Server Address: %s\n", cl.serverConfig.Server.GetAddress())
	fmt.Printf("Max Workers: %d\n", cl.serverConfig.Server.MaxWorkers)
	fmt.Printf("Packet Size Limit: %d bytes\n", cl.serverConfig.Server.MaxPacketSize)

	readTimeout, writeTimeout := cl.serverConfig.Server.GetTimeouts()
	fmt.Printf("Timeouts: Read=%v, Write=%v\n", readTimeout, writeTimeout)

	fmt.Printf("Log Level: %s\n", cl.serverConfig.Logging.Level)
	fmt.Printf("Log Format: %s\n", cl.serverConfig.Logging.Format)

	fmt.Printf("\nConfigured Zones: %d\n", len(cl.serverConfig.Zones))
	for i, zone := range cl.serverConfig.Zones {
		fmt.Printf("  %d. %s (%s)\n", i+1, zone.Name, zone.Description)
		fmt.Printf("     A Records: %d, AAAA Records: %d, CNAME Records: %d\n",
			len(zone.ARecords), len(zone.AAAARecords), len(zone.CNAMERecords))
		fmt.Printf("     MX Records: %d, TXT Records: %d\n",
			len(zone.MXRecords), len(zone.TXTRecords))
	}

	fmt.Printf("\nSecurity Settings:\n")
	fmt.Printf("  Rate Limiting: %t\n", cl.serverConfig.Security.RateLimiting.Enabled)
	fmt.Printf("  Refuse Recursion: %t\n", cl.serverConfig.Security.ResponsePolicies.RefuseRecursion)
	fmt.Printf("  TTL Range: %d - %d seconds\n",
		cl.serverConfig.Security.ResponsePolicies.MinimumTTL,
		cl.serverConfig.Security.ResponsePolicies.MaximumTTL)

	fmt.Println("================================")
}

// ValidateZoneConsistency performs advanced validation checks
func (cl *ConfigLoader) ValidateZoneConsistency() error {
	if cl.serverConfig == nil {
		return fmt.Errorf("no configuration loaded")
	}

	for _, zone := range cl.serverConfig.Zones {
		if err := cl.validateZoneConsistency(&zone); err != nil {
			return fmt.Errorf("zone %s consistency check failed: %w", zone.Name, err)
		}
	}

	return nil
}

// validateZoneConsistency checks for logical consistency within a zone
// it enforces 3 key DNS rules: (1) Nameserver "Glue" Records, (2) CNAME Record Exclusivity, (3) Valid Mail Server Targets
func (cl *ConfigLoader) validateZoneConsistency(zone *ZoneConfig) error {
	// Check 1: Ensure nameservers have corresponding A or AAAA "glue" records
	for _, ns := range zone.Nameservers {
		found := false

		// Check for a matching A record
		for _, aRecord := range zone.ARecords {
			if aRecord.Name == ns.Name && aRecord.IP == ns.IP {
				found = true
				break
			}
		}

		// If not found, check for a matching AAAA record
		if !found {
			for _, aaaaRecord := range zone.AAAARecords {
				if aaaaRecord.Name == ns.Name && aaaaRecord.IP == ns.IP {
					found = true
					break
				}
			}
		}

		if !found {
			return fmt.Errorf("nameserver %s (IP: %s) should have a corresponding A or AAAA record",
				ns.Name, ns.IP)
		}
	}

	// Check 2: Ensure CNAME records don't conflict with other records
	for _, cname := range zone.CNAMERecords {
		// CNAME records cannot coexist with other record types for the same name
		for _, aRecord := range zone.ARecords {
			if aRecord.Name == cname.Name {
				return fmt.Errorf("CNAME record %s conflicts with A record of same name",
					cname.Name)
			}
		}
		for _, aaaaRecord := range zone.AAAARecords {
			if aaaaRecord.Name == cname.Name {
				return fmt.Errorf("CNAME record %s conflicts with AAAA record of same name",
					cname.Name)
			}
		}
	}

	// Check 3: Ensure MX records point to valid targets
	for _, mx := range zone.MXRecords {
		// MX target should either be in this zone or be a FQDN
		if !cl.isValidMXTarget(mx.Target, zone) {
			fmt.Printf("Warning: MX record target %s may not be resolvable\n", mx.Target)
		}
	}

	return nil
}

// isValidMXTarget checks if an MX target is valid
func (cl *ConfigLoader) isValidMXTarget(target string, zone *ZoneConfig) bool {
	// Check if target exists as an A record in this zone
	for _, aRecord := range zone.ARecords {
		if aRecord.Name == target {
			return true
		}
	}

	// Check if target exists as an quad-A record in this zone
	for _, aaaaRecord := range zone.AAAARecords {
		if aaaaRecord.Name == target {
			return true
		}
	}

	// Check if target exists as a CNAME in this zone
	for _, cname := range zone.CNAMERecords {
		if cname.Name == target {
			return true
		}
	}

	// If it's a FQDN pointing outside our zone, assume it's valid
	return false
}
