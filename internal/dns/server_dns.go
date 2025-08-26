package dns

import (
	"github.com/faanross/legehniss_C2/internal/config"
	"github.com/miekg/dns"
	"log"
	"net"
)

// DNSServer implements the Server interface for DNS
type DNSServer struct {
	addr   string
	server *dns.Server
}

// NewDNSServer creates a new DNS server
func NewDNSServer(cfg *config.Config) *DNSServer {
	return &DNSServer{
		addr: cfg.ServerAddr,
	}
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
