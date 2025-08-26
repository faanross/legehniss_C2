package main

import (
	"flag"
	"github.com/faanross/legehniss_C2/internal/composition"
	"github.com/faanross/legehniss_C2/internal/config"
	"log"
	"os"
	"os/signal"
)

const pathToYAML = "./configs/main.yaml"

func main() {
	// Command line flag for config file path
	configPath := flag.String("config", pathToYAML, "path to configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadMainConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Create server using interface's factory function
	server, err := composition.NewServer(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Start the server in own goroutine
	go func() {
		log.Printf("Starting %s server on %s", cfg.Protocol, cfg.ServerAddr)
		if err := server.Start(); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	<-sigChan

	// Graceful shutdown
	log.Println("Shutting down server...")
	if err := server.Stop(); err != nil {
		log.Printf("Error stopping server: %v", err)
	}

}
