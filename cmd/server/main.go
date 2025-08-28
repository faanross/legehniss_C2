package main

import (
	"context"
	"fmt"
	"github.com/faanross/legehniss_C2/internal/client"
	"github.com/faanross/legehniss_C2/internal/composition"
	"github.com/faanross/legehniss_C2/internal/config"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var pathToServerYAML = "./configs/server.yaml"
var pathToMainYaml = "./configs/main.yaml"

func main() {

	client.StartControlAPI()

	// Instantiate ConfigLoader struct
	loader := config.NewConfigLoader(pathToServerYAML, pathToMainYaml)

	// read + validate + unmarshall BOTH CONFIG file
	serverCfg, mainCfg, err := loader.Load()

	if err != nil {
		fmt.Printf("Failed to load configuration: %v\n", err)
		fmt.Printf("Please create server config file and save it as: %s\n", pathToServerYAML)
		os.Exit(1)
	}

	// print loaded server config
	loader.PrintConfiguration()

	// perform zone consistency checks
	if err := loader.ValidateZoneConsistency(); err != nil {
		fmt.Printf("Zone consistency check failed: %v\n", err)
		return
	}

	fmt.Println("\nConfiguration loaded and validated successfully!")

	// Now, we need to create our SERVER
	initServer, err := composition.NewServer(mainCfg, serverCfg)
	if err != nil {
		fmt.Printf("Failed to create server: %v\n", err)
		os.Exit(1)
	}

	// set up graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// start server in goroutine
	serverErr := make(chan error, 1)
	go func() {
		log.Printf("| Starting Server |\n-> Type: %s\n->Address: %s\n",
			mainCfg.Protocol, serverCfg.Server.GetAddress())
		serverErr <- initServer.Start(ctx)
	}()

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		log.Printf("| Received signal: %v\n", sig.String())
	case err := <-serverErr:
		if err != nil {
			fmt.Printf("Failed to start server: %v\n", err)
		}
	}

	// Graceful shutdown
	log.Printf(" Shutting down server\n")
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := initServer.Stop(shutdownCtx); err != nil {
		log.Printf("Failed to stop server: %v\n", err)
		os.Exit(1)
	}

	log.Printf("Server stopped successfully!\n")

}
