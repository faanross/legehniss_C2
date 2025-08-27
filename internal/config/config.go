package config

import "time"

type Config struct {
	ClientAddr           string `yaml:"client"`
	ServerAddr           string `yaml:"server"`
	DNSUseSystemDefaults bool   `yaml:"dns_use_system_defaults"`

	Delay    time.Duration `yaml:"delay"`    // Base delay between cycles
	Jitter   int           `yaml:"jitter"`   // Jitter percentage (0-100)}
	Protocol string        `yaml:"protocol"` // this will be the starting protocol

	TlsKey  string `yaml:"tls_key"`
	TlsCert string `yaml:"tls_cert"`

	PathToRequestYAML  string `yaml:"path_to_request"`
	PathToResponseYAML string `yaml:"path_to_response"`
}
