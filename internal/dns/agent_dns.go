package dns

import (
	"context"
	"errors"
	"fmt"
	"github.com/faanross/legehniss_C2/internal/config"
	"github.com/faanross/legehniss_C2/internal/request"
	"github.com/faanross/legehniss_C2/internal/visualizer"
	"gopkg.in/yaml.v3"
	"net"
	"os"
	"time"
)

var pathToRequestYaml = "./configs/request.yaml"

// DNSAgent implements the CommunicatorAgent interface for DNS
type DNSAgent struct {
	request    config.DNSRequest
	serverAddr string
}

// NewDNSAgent creates a new DNS client
func NewDNSAgent(cfg *config.Config) (*DNSAgent, error) {

	// (1) read Request yaml-file from disk
	yamlFile, err := os.ReadFile(pathToRequestYaml)
	if err != nil {
		return nil, fmt.Errorf("reading YAML file: %w", err)
	}

	// (2) unmarshall YAML -> Struct
	var dnsRequest config.DNSRequest

	err = yaml.Unmarshal(yamlFile, &dnsRequest)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling YAML: %w", err)
	}

	// (3) Validate request fields
	if err := config.ValidateRequest(&dnsRequest); err != nil {
		// Use a type assertion to check if it's the specific type we're looking for.
		var validationErrs config.ValidationErrors
		if errors.As(err, &validationErrs) {
			fmt.Println("Configuration is invalid. Errors:")
			for _, validationErr := range validationErrs {
				fmt.Printf("  - %s\n", validationErr)
			}
		}
		return nil, fmt.Errorf("validating request: %w", err)
	}

	fmt.Println("✅ DNS request configuration is valid!")

	// (4) determine whether to use indicated address, or local resolver
	var finalAddr string

	if cfg.DNSUseSystemDefaults {
		finalAddr, err = DetermineResolver()
		if err != nil {
			// if we fail, revert to using hardcoded address
			fmt.Printf("Could not determine DNS resolver: %v\n", err)
			finalAddr = cfg.ServerAddr
		}
	} else {
		finalAddr = cfg.ServerAddr
	}

	return &DNSAgent{
		request:    dnsRequest,
		serverAddr: finalAddr,
	}, nil
}

func (c *DNSAgent) Send(ctx context.Context) ([]byte, error) {

	// (1) Construct DNS Request msg
	dnsMsg, err := request.BuildDNSRequest(c.request)
	if err != nil {
		return nil, fmt.Errorf("building DNS request: %w", err)
	}

	// (2) Pack the dnsMsg to convert to byte slice (so we can override Z value)
	packedMsg, _ := dnsMsg.Pack()

	// (3) Now we can apply our manual override for the Z value
	err = request.ApplyManualOverride(packedMsg, c.request.Header)
	if err != nil {
		fmt.Printf("Error applying manual overrides: %v\n", err)
		// continue - if we can't change Z, not really an issue.
	}

	// (4) Visualize our packet to terminal
	visualizer.VisualizePacket(packedMsg)

	// (5) Resolve string address into a UDP address object
	rAddr, err := net.ResolveUDPAddr("udp", c.serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	// (6) Establish UDP connection
	conn, err := net.DialUDP("udp", nil, rAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to resolver: %w", err)
	}

	defer conn.Close()

	fmt.Printf("\n🚀 Sending packet to %s\n", c.serverAddr)

	// (7) Send packet
	_, err = conn.Write(packedMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to send packet: %w", err)
	}
	fmt.Println("✅  Packet sent successfully.")

	// Set a read deadline (5 seconds)
	deadline := time.Now().Add(5 * time.Second)
	err = conn.SetReadDeadline(deadline)
	if err != nil {
		return nil, fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Buffer to hold the response
	// DNS responses can be up to 512 bytes for standard UDP
	// Will double just in case of extensions (EDNS)

	response := make([]byte, 1024)

	// Read response, note this is a blocking call
	// until data is received or the deadline is hit
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	fmt.Printf("🫴 Received %d bytes.\n", n)

	// Return only the part of the buffer that contains data
	return response[:n], nil
}
