package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"blockchain-dns/resolver"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	resolverID := flag.String("id", "main-resolver", "ID for this resolver")
	// resolver now listens on its Host-Only interface for client connections
	apiAddr := flag.String("api", "192.168.56.21:8080", "API address for this resolver (e.g., 192.168.56.21:8080)")
	// this flag must contain all three node URLs
	nodeURLsStr := flag.String("nodes", "", "Comma-separated list of validator node API URLs (e.g., http://10.0.0.10:8081,http://10.0.0.11:8081)")
	flag.Parse()

	if *nodeURLsStr == "" {
		fmt.Println("Usage: ./resolver_app -api <api_address> -nodes <comma_separated_node_urls>")
		fmt.Println("Example: ./resolver_app -api 192.168.56.21:8080 -nodes http://10.0.0.10:8081,http://10.0.0.11:8081,http://10.0.0.12:8081")
		os.Exit(1)
	}

	nodeAPIURLs := strings.Split(*nodeURLsStr, ",")
	if len(nodeAPIURLs) == 0 {
		log.Fatalf("No validator node URLs provided.")
	}

	log.Printf("Starting DNS Resolver: ID=%s, API=%s, Nodes=%v", *resolverID, *apiAddr, nodeAPIURLs)

	r := resolver.NewResolver(*resolverID, *apiAddr, nodeAPIURLs)
	r.StartResolver()

	// keeps the application running until interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Printf("Resolver %s: Shutting down...", *resolverID)
	r.StopResolver()
	log.Printf("Resolver %s: Stopped.", *resolverID)
}
