package runloop

import (
	"context"
	"github.com/faanross/legehniss_C2/internal/composition"
	"github.com/faanross/legehniss_C2/internal/config"
	"github.com/miekg/dns"
	"log"
	"math/rand"
	"time"
)

func RunLoop(ctx context.Context, comm composition.Agent, cfg *config.Config) error {
	for {
		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		response, err := comm.Send(ctx)
		if err != nil {
			log.Printf("Error sending request: %v", err)
			return err
		}

		// BASED ON PROTOCOL, HANDLE PARSING DIFFERENTLY

		switch cfg.Protocol {
		case "https":
			log.Fatalf("HTTPS has not yet been implemented: %v", err)
		case "dns":

			extractAndDisplayDNSResponse(response)
			//ipAddr := string(response)
			//log.Printf("Received response: IP=%v", ipAddr)

		}

		// Calculate sleep duration with jitter
		sleepDuration := CalculateSleepDuration(cfg.Delay, cfg.Jitter)
		log.Printf("Sleeping for %v", sleepDuration)

		// Sleep with cancellation support
		select {
		case <-time.After(sleepDuration):
			// Continue to next iteration
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// CalculateSleepDuration calculates the actual sleep time with jitter
func CalculateSleepDuration(baseDelay time.Duration, jitterPercent int) time.Duration {
	if jitterPercent == 0 {
		return baseDelay
	}

	// Calculate jitter range
	jitterRange := float64(baseDelay) * float64(jitterPercent) / 100.0

	// Random value between -jitterRange and +jitterRange
	jitter := (rand.Float64()*2 - 1) * jitterRange

	// Calculate final duration
	finalDuration := float64(baseDelay) + jitter

	// Ensure we don't go negative
	if finalDuration < 0 {
		finalDuration = 0
	}

	return time.Duration(finalDuration)
}

func extractAndDisplayDNSResponse(response []byte) {

	msg := new(dns.Msg)
	err := msg.Unpack(response)
	if err != nil {
		log.Printf("Error unpacking DNS response: %v", err)
		return
	}

	// Extract and log the answers
	if len(msg.Answer) > 0 {
		var ips []string
		for _, answer := range msg.Answer {
			// Check if it's an A record
			if a, ok := answer.(*dns.A); ok {
				ips = append(ips, a.A.String())
			}
		}
		if len(ips) > 0 {
			log.Printf("Received response: IP=%v", ips)
		} else {
			log.Printf("No A records found in response")
		}
	} else {
		log.Printf("No answers in DNS response")
	}
}
