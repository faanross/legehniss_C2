package dns

import (
	"errors"
	"fmt"
	"github.com/faanross/legehniss_C2/internal/config"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

// DNSServer implements the Server interface for DNS
type DNSServer struct {
	serverConfig config.ServerConfig
	response     config.DNSResponse
	conn         *net.UDPConn
	workers      []worker
	shutdown     chan struct{}
	wg           sync.WaitGroup
}

// worker represents a goroutine that processes DNS queries
// the amount can be set in ServerConfig.MaxWorkers
type worker struct {
	id       string
	server   *DNSServer
	requests chan *DNSRequest
}

// DNSRequest represents an incoming DNS query
type DNSRequest struct {
	Data       []byte
	ClientAddr *net.UDPAddr
	ReceivedAt time.Time
}

// NewDNSServer creates a new DNS server
func NewDNSServer(cfg *config.Config) (*DNSServer, error) {

	// (1) read Response yaml-file from disk
	yamlFile, err := os.ReadFile(cfg.PathToResponseYAML)
	if err != nil {
		return nil, fmt.Errorf("reading YAML file: %w", err)
	}

	// (2) unmarshall YAML -> Struct
	var dnsResponse config.DNSResponse

	err = yaml.Unmarshal(yamlFile, &dnsResponse)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling YAML: %w", err)
	}

	// (3) Validate request fields
	if err := config.ValidateResponse(&dnsResponse); err != nil {
		// Use a type assertion to check if it's the specific type we're looking for.
		var validationErrs config.ValidationErrors
		if errors.As(err, &validationErrs) {
			fmt.Println("Configuration is invalid. Errors:")
			for _, validationErr := range validationErrs {
				fmt.Printf("  - %s\n", validationErr)
			}
		}
		return nil, fmt.Errorf("validating response: %w", err)
	}

	fmt.Println("✅ DNS response configuration is valid!")

	return &DNSServer{
		addr:     cfg.ServerAddr,
		response: dnsResponse,
	}, nil
}

// Start implements Server.Start for DNS
func (s *DNSServer) Start() error {
	// Create and configure the DNS server
	s.server = &dns.Server{
		Addr:    s.addr,
		Net:     "udp",
		Handler: dns.HandlerFunc(s.handleDNSRequest),
	}

	// Start server
	return s.server.ListenAndServe()
}

// handleDNSRequest is our DNS Server's handler
func (s *DNSServer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	// Create response message
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	// Process each question
	for _, question := range r.Question {
		// We only handle A records for now
		if question.Qtype != dns.TypeA {
			continue
		}

		// Log the query
		log.Printf("DNS query for: %s", question.Name)

		// For now, always return 42.42.42.42
		rr := &dns.A{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP("42.42.42.42"),
		}
		m.Answer = append(m.Answer, rr)
	}

	// Send response
	w.WriteMsg(m)
}

// Stop implements Server.Stop for DNS
func (s *DNSServer) Stop() error {
	if s.server == nil {
		return nil
	}
	log.Println("Stopping DNS server...")
	return s.server.Shutdown()
}
