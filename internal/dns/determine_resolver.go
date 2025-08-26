package dns

import (
	"fmt"
	"github.com/miekg/dns"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

// DetermineResolver determines the default DNS resolver configured
// for the current host independently of the exact OS
func DetermineResolver() (string, error) {
	var dnsConfig *dns.ClientConfig
	var err error

	switch runtime.GOOS {
	case "windows":
		dnsConfig, err = getWindowsDNSConfig()
	default:
		// This works for Linux, macOS, BSD, etc.
		dnsConfig, err = dns.ClientConfigFromFile("/etc/resolv.conf")
	}

	if err != nil {
		return "", fmt.Errorf("could not get system resolver config: %w", err)
	}

	if len(dnsConfig.Servers) == 0 {
		return "", fmt.Errorf("no system DNS servers found")
	}

	// Use the primary system resolver
	primaryServer := dnsConfig.Servers[0]

	// Default port if not specified
	port := dnsConfig.Port
	if port == "" {
		port = "53"
	}

	// Format address with proper IPv6 handling
	addr := formatDNSAddress(primaryServer, port)

	fmt.Printf("Using default DNS Resolver: %s\n", addr)
	return addr, nil
}

// getWindowsDNSConfig retrieves DNS configuration on Windows
func getWindowsDNSConfig() (*dns.ClientConfig, error) {
	cmd := exec.Command("nslookup", "localhost")
	output, err := cmd.Output()
	if err != nil {
		// nslookup might fail but still provide output
		if output == nil {
			return nil, fmt.Errorf("nslookup failed: %w", err)
		}
	}

	// Parse the default server from nslookup output
	re := regexp.MustCompile(`(?:Default Server|Server):[^\n]*\n(?:Address|Addresses?):\s*([^\n]+)`)
	matches := re.FindStringSubmatch(string(output))

	if len(matches) > 1 {
		server := strings.TrimSpace(matches[1])
		// Remove port if present (e.g., "192.168.1.1#53")
		if idx := strings.LastIndex(server, "#"); idx != -1 {
			server = server[:idx]
		}

		return &dns.ClientConfig{
			Servers: []string{server},
			Port:    "53",
		}, nil
	}

	return nil, fmt.Errorf("could not parse nslookup output")
}

// formatDNSAddress properly formats an IP:port combination, handling IPv6
func formatDNSAddress(ip, port string) string {
	// Check if it's an IPv6 address
	if strings.Contains(ip, ":") {
		// IPv6 addresses need brackets
		return fmt.Sprintf("[%s]:%s", ip, port)
	}
	return fmt.Sprintf("%s:%s", ip, port)
}
