package config

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
)

// LoadMainConfig reads and parses the MAIN configuration file
func LoadMainConfig(path string) (*Config, error) {

	// We'll provide path to *.yaml to function when we call it
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening config file: %w", err)
	}
	defer file.Close()

	// instantiate struct to unmarshall yaml into
	var cfg Config

	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if err := cfg.ValidateMainConfig(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	
	return &cfg, nil
}
