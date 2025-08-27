package dns

import (
	"context"
	"errors"
	"fmt"
	"github.com/faanross/legehniss_C2/internal/config"
	"github.com/faanross/legehniss_C2/internal/dnsparser"
	"gopkg.in/yaml.v3"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

// DNSServer implements the Server interface for DNS
type DNSServer struct {
	serverConfig *config.DNSServerConfig
	response     *config.DNSResponse
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
func NewDNSServer(cfg *config.Config, sCfg *config.DNSServerConfig) (*DNSServer, error) {

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

	dnsServer := &DNSServer{
		serverConfig: sCfg,
		response:     &dnsResponse,
		shutdown:     make(chan struct{}),
	}

	// Create worker pool
	dnsServer.workers = make([]worker, sCfg.Server.MaxWorkers)
	for i := 0; i < sCfg.Server.MaxWorkers; i++ {
		dnsServer.workers[i] = worker{
			id:       fmt.Sprintf("worker #%d", i),
			server:   dnsServer,
			requests: make(chan *DNSRequest, sCfg.Server.WorkerChannelBufferSize),
		}
	}

	return dnsServer, nil
}

// Start implements Server.Start for DNS
func (s *DNSServer) Start(ctx context.Context) error {
	// Resolve UDP address
	addr, err := net.ResolveUDPAddr("udp", s.serverConfig.Server.GetAddress())
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	// Start listening
	s.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to start UDP listener: %w", err)
	}

	log.Printf("| UDP server started |\n-> Address: %s\n->Workers: %d\n", addr.String(), len(s.workers))

	// Start worker goroutines
	for i := range s.workers {
		s.wg.Add(1)
		go s.workers[i].run()
	}

	// Start accepting connections
	s.wg.Add(1)
	s.acceptLoop(ctx)

	return nil
}

// acceptLoop handles incoming UDP packets
func (s *DNSServer) acceptLoop(ctx context.Context) {
	defer s.wg.Done()

	buffer := make([]byte, s.serverConfig.Server.MaxPacketSize)

	for {
		select {
		case <-ctx.Done():
			log.Printf("Accept loop stopping due to context cancellation")
			return
		case <-s.shutdown:
			log.Printf("Accept loop stopping due to shutdown signal")
			return
		default:
			// Set read timeout
			readTimeout := time.Duration(s.serverConfig.Server.ReadTimeout)

			err := s.conn.SetReadDeadline(time.Now().Add(readTimeout))

			if err != nil {
				log.Printf("SetReadDeadline failed: %v", err)
			}

			// Read packet
			n, clientAddr, err := s.conn.ReadFromUDP(buffer)
			if err != nil {
				// Check if it's a timeout (expected during shutdown)
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					continue
				}
				log.Printf("ReadFromUDP failed: %v", err)
				continue
			}

			// Create request
			request := &DNSRequest{
				Data:       make([]byte, n),
				ClientAddr: clientAddr,
				ReceivedAt: time.Now(),
			}

			// copy data from packet to internal buffer
			copy(request.Data, buffer[:n])

			// Log the incoming request
			log.Printf("| ReadFromUDP Received |\n-> Client: %s\n-> Size: %d\n-> Data_Preview: %s\n ",
				clientAddr.String(), n, fmt.Sprintf("%x", request.Data[:min(n, 16)]))

			// Distribute to workers using round-robin
			workerIndex := len(request.Data) % len(s.workers)
			select {
			case s.workers[workerIndex].requests <- request:
				// Request queued successfully
			default:
				// Worker queue is full, log and drop
				log.Printf("| Dropping request to worker #%d because it has been full", workerIndex)
			}
		}
	}
}

// worker.run processes DNS requests
func (w *worker) run() {
	defer w.server.wg.Done()

	log.Printf("| Worker #%s started", w.id)

	for {
		select {
		case <-w.server.shutdown:
			log.Printf("| Worker #%s stopped", w.id)
			return

		case request := <-w.requests:
			w.processRequest(request)
		}
	}
}

// processRequest represents a single worker handling a single DNS request
func (w *worker) processRequest(request *DNSRequest) {
	startTime := time.Now()

	log.Printf("| Processing DNS request |\n-> Worker ID: %s\n-> Client: %s\n-> Packet Size: %d\n->",
		w.id, request.ClientAddr.String(), len(request.Data))

	log.Printf("| DNS Packet Receiver |\n-> Worker ID: %s\n-> Processing Time: %s\n-> HEX: %s\n->",
		w.id, time.Since(startTime), fmt.Sprintf("%x", request.Data))

	// NEW PARSING CODE STARTS HERE
	// parse packet
	dnsParser := dnsparser.NewDNSParser(w.server.serverConfig)
	parsed := dnsParser.ParsePacket(request.Data, request.ClientAddr.String())

	// Log detailed analysis for interesting packets
	if !parsed.Valid || len(parsed.Analysis.Issues) > 0 || len(parsed.Analysis.Warnings) > 0 {
		log.Printf("Packet analysis found issues\nworker_id=%v\nvalid=%v\nissues=%v\nwarnings=%v", w.id, parsed.Valid, parsed.Analysis.Issues, parsed.Analysis.Warnings)
		//logging.Warn("Packet analysis found issues",
		//	"worker_id", w.id,
		//	"valid", parsed.Valid,
		//	"issues", parsed.Analysis.Issues,
		//	"warnings", parsed.Analysis.Warnings)
	}

	// Log query details if it's a valid query
	if parsed.Valid && parsed.Question != nil {
		log.Printf("DNS Query details\nworker_id=%v\ndomain=%v\ntype=%v\nclass=%v\nauthoritative=%v", w.id, parsed.Question.Name, parsed.Question.QtypeString, parsed.Question.QclassString, parsed.Analysis.SupportedByServer)
		//logging.Info("DNS Query details",
		//	"worker_id", w.id,
		//	"domain", parsed.Question.Name,
		//	"type", parsed.Question.QtypeString,
		//	"class", parsed.Question.QclassString,
		//	"authoritative", parsed.Analysis.SupportedByServer)
	}

	// TODO  process query, send response

}

// Stop gracefully stops the DNS server
func (s *DNSServer) Stop(ctx context.Context) error {
	log.Printf("DNS server stopping...")

	// Signal shutdown
	close(s.shutdown)

	// Close UDP connection
	if s.conn != nil {
		s.conn.Close()
	}

	// Wait for workers to finish with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Printf("DNS server shutdown complete")
		return nil
	case <-ctx.Done():
		log.Printf("DNS server shutdown timed out")
		return ctx.Err()
	}
}
