package composition

import (
	"fmt"
	"github.com/faanross/legehniss_C2/internal/config"
	"github.com/faanross/legehniss_C2/internal/dns"
)

// NewAgent creates a new communicator based on the protocol
func NewAgent(cfg *config.Config) (Agent, error) {
	switch cfg.Protocol {
	case "https":
		return nil, fmt.Errorf("HTTPS not yet implemented")
	case "dns":
		agent, err := dns.NewDNSAgent(cfg)
		if err != nil {
			return nil, fmt.Errorf("creating DNS agent: %w", err)
		}
		return agent, nil
	case "wss":
		return nil, fmt.Errorf("WSS not yet implemented")
	default:
		return nil, fmt.Errorf("unsupported protocol: %v", cfg.Protocol)
	}
}

// NewServer creates a new server based on the protocol
func NewServer(cfg *config.Config) (Server, error) {
	switch cfg.Protocol {
	case "https":
		return nil, fmt.Errorf("HTTPS not yet implemented")
	case "dns":
		agent, err := dns.NewDNSServer(cfg)
		if err != nil {
			return nil, fmt.Errorf("creating DNS agent: %w", err)
		}
		return agent, nil
	case "wss":
		return nil, fmt.Errorf("WSS not yet implemented")
	default:
		return nil, fmt.Errorf("unsupported protocol: %v", cfg.Protocol)
	}
}
