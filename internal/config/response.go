package config

// DNSResponse will hold the complete server-side
// configuration parsed from configs/response.yaml
type DNSResponse struct {
	Header   Header   `yaml:"header"`
	Question Question `yaml:"question"`
	Answers  []Answer `yaml:"answer"`
}

// Answer represents a DNS answer record
type Answer struct {
	Name  string `yaml:"name"`
	Type  string `yaml:"type"`
	Class string `yaml:"class"`
	TTL   uint32 `yaml:"ttl"`
	Data  string `yaml:"data"` // For TXT records, this will be the text content
}
