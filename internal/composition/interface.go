package composition

import "context"

// Agent defines the contract for agents
type Agent interface {
	// Send sends a message and waits for a response
	Send(ctx context.Context) ([]byte, error)
}

// Server defines the contract for servers
type Server interface {
	// Start begins listening for requests
	Start() error

	// Stop gracefully shuts down the server
	Stop() error
}
