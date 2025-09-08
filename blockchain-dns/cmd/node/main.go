package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"blockchain-dns/node"
	"blockchain-dns/poa"
)

// keyFilePath generates the expected file path for a validator's key pair.
func keyFilePath(validatorID string) string {
	return fmt.Sprintf("validator_keys/%s_key.json", validatorID)
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	nodeID := flag.String("id", "", "ID for this validator node (e.g., validator-1)")
	apiAddr := flag.String("api", ":8081", "API address for this node (e.g., :8081)")
	peersStr := flag.String("peers", "", "Comma-separated list of peer node API URLs (e.g., http://10.0.0.11:8081,http://10.0.0.12:8081)")
	flag.Parse()

	if *nodeID == "" || *peersStr == "" {
		fmt.Println("Usage: ./node_app -id <node_id> -api <api_address> -peers <comma_separated_peer_urls>")
		fmt.Println("Example: ./node_app -id validator-1 -api :8081 -peers http://10.0.0.11:8081,http://10.0.0.12:8081")
		os.Exit(1)
	}

	peers := strings.Split(*peersStr, ",")
	if len(peers) == 0 {
		log.Fatalf("No peer URLs provided.")
	}

	// assuming the validator_keys have been pre-distributed.
	allValidatorIDs := []string{"validator-1", "validator-2", "validator-3"}
	allValidators := make([]*poa.Validator, 0, len(allValidatorIDs))

	for _, id := range allValidatorIDs {
		keyPath := keyFilePath(id)
		validator, err := poa.LoadKeyPair(keyPath)
		if err != nil {
			log.Fatalf("Failed to load key pair for %s from %s: %v. Keys must be pre-generated and distributed.", id, keyPath, err)
		}
		allValidators = append(allValidators, validator)
	}

	log.Printf("Starting Validator Node: ID=%s, API=%s, Peers=%v", *nodeID, *apiAddr, peers)

	n, err := node.NewNode(*nodeID, *apiAddr, peers, allValidators)
	if err != nil {
		log.Fatalf("Failed to create node: %v", err)
	}
	n.StartNode()

	// keeping the application running until interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Printf("Node %s: Shutting down...", *nodeID)
	n.StopNode()
	log.Printf("Node %s: Stopped.", n.ID)
}
