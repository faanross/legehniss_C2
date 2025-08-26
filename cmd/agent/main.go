package main

import (
	"flag"
	"github.com/faanross/legehniss_C2/internal/composition"
	"github.com/faanross/legehniss_C2/internal/config"
	"log"
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
	_, err = composition.NewAgent(cfg)
	if err != nil {
		log.Fatalf("Failed to create communicator: %v", err)
	}

}
