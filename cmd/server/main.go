package main

import (
	"flag"
	"fmt"
	"github.com/faanross/legehniss_C2/internal/config"
	"log"
	"os"
	"os/signal"
)

var pathToServerYAML = "./configs/server.yaml"

func main() {

	// Command line flag for config file path
	configPath := flag.String("config", pathToServerYAML, "path to configuration file")
	flag.Parse()

	// instantiate ConfigLoader struct
	loader := config.NewConfigLoader(*configPath)

	// read + validate + unmarshall config file
	cfg, err := loader.Load()
	if err != nil {
		fmt.Printf("Failed to load configuration: %v\n", err)
		fmt.Printf("Please create config file and save it as: %s\n", configPath)
	}

	// print loaded config
	loader.PrintConfiguration()

	// perform zone consistency checks
	if err := loader.ValidateZoneConsistency(); err != nil {
		fmt.Printf("Zone consistency check failed: %v\n", err)
		return
	}

	fmt.Println("\nConfiguration loaded and validated successfully!")

	// test zone lookup functionality
	testDomains := []string{
		"timeserversync.com",
		"www.timeserversync.com",
		"api.timeserversync.com",
		"nonexistent.example.com",
	}

	fmt.Println("\nTesting zone lookup:")
	for _, domain := range testDomains {
		zone := cfg.FindZone(domain)
		if zone != nil {
			fmt.Printf("  %s -> Found in zone: %s\n", domain, zone.Name)
		} else {
			fmt.Printf("  %s -> No authoritative zone found\n", domain)
		}
	}

	// we will also need to use main config to say - we want a DNS/HTTPS server
	// so we pass both main and server configs to FF
	// if it's DNS - pass server config to DNS constructor
	// if its HTTPS - pass main config to HTTPS constructor

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	<-sigChan

	// Graceful shutdown
	log.Println("Shutting down server...")
}
