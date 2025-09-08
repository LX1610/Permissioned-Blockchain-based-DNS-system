package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"blockchain-dns/attack"
)

const (
	Node1IP            = "10.0.0.10"
	Node2IP            = "10.0.0.11"
	Node3IP            = "10.0.0.12"
	AttackerIP         = "10.0.0.30" // the IP of attacker node
	NodeAPIPort        = "8081"
	ResolverInternalIP = "10.0.0.21" // Resolver's node facing IP
	ResolverAPIPort    = "8080"
)

var (
	reader                 *bufio.Reader
	node1APIURL            string
	node2APIURL            string
	node3APIURL            string
	resolverInternalAPIURL string
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	reader = bufio.NewReader(os.Stdin)

	fmt.Println("------- Attacker Node Client -------")

	fmt.Println("\nPress Enter to continue to the interactive attack menu...")
	readLine()

	// initializing Node API URLs
	node1APIURL = fmt.Sprintf("http://%s:%s", Node1IP, NodeAPIPort)
	node2APIURL = fmt.Sprintf("http://%s:%s", Node2IP, NodeAPIPort)
	node3APIURL = fmt.Sprintf("http://%s:%s", Node3IP, NodeAPIPort)
	resolverInternalAPIURL = fmt.Sprintf("http://%s:%s", ResolverInternalIP, ResolverAPIPort)

	for {
		printMenu()
		choiceStr := readLine()
		choice, err := strconv.Atoi(strings.TrimSpace(choiceStr))
		if err != nil {
			fmt.Println("Invalid input. Please enter a number.")
			continue
		}

		switch choice {
		case 1:
			handleSimulateUnauthorizedDNSUpdate()
		case 2:
			handleSimulateUnauthorizedBlockInjection()
		case 3:
			handleSimulateBlockTampering()
		case 4:
			handleSimulateImpersonationAttempt()
		case 0:
			fmt.Println("Exiting Attacker node client.")
			return
		default:
			fmt.Println("Invalid choice. Please select an option from the menu.")
		}
		fmt.Println("\n-------- Operation Complete --------")
		time.Sleep(1 * time.Second)
	}
}

func printMenu() {
	fmt.Println("\n-------- Select an Attacker Operation --------")
	fmt.Println("Node-Focused Attacks:")
	fmt.Println("  1. Simulate Unauthorized DNS Update (API Key Bypass)")
	fmt.Println("  2. Simulate Unauthorized Block Injection (Unknown Validator)")
	fmt.Println("  3. Simulate Block Tampering (Invalid Signature)")
	fmt.Println("  4. Simulate Impersonation Attempt (Key Mismatch)")
	fmt.Println("0. Exit")
	fmt.Print("Enter your choice: ")
}

func readLine() string {
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func prompt(message string) string {
	fmt.Print(message)
	return readLine()
}

func promptInt(message string) int {
	for {
		input := prompt(message)
		val, err := strconv.Atoi(input)
		if err != nil {
			fmt.Println("Invalid input. Please enter a number.")
			continue
		}
		return val
	}
}

func handleSimulateUnauthorizedDNSUpdate() {
	fmt.Println("\n------- Simulate Unauthorized DNS Update -------")
	targetNodeChoice := prompt("Enter target node (1, 2, or 3): ")
	var targetNodeAPIURL string
	switch targetNodeChoice {
	case "1":
		targetNodeAPIURL = node1APIURL
	case "2":
		targetNodeAPIURL = node2APIURL
	case "3":
		targetNodeAPIURL = node3APIURL
	default:
		fmt.Println("Invalid node choice. Defaulting to Node A.")
		targetNodeAPIURL = node1APIURL
	}

	maliciousDomain := prompt("Enter malicious domain: ")
	maliciousIP := prompt("Enter malicious IP: ")

	attack.SimulateUnauthorizedDNSUpdate(targetNodeAPIURL, maliciousDomain, maliciousIP)
	fmt.Println("Unauthorized DNS Update attempt finished.")
}

func handleSimulateUnauthorizedBlockInjection() {
	fmt.Println("\n--- Simulate Unauthorized Block Injection (Node - Unknown Validator) ---")
	targetNodeChoice := prompt("Enter target node (1, 2, or 3): ")
	var targetNodeAPIURL string
	switch targetNodeChoice {
	case "1":
		targetNodeAPIURL = node1APIURL
	case "2":
		targetNodeAPIURL = node2APIURL
	case "3":
		targetNodeAPIURL = node3APIURL
	default:
		fmt.Println("Invalid node choice. Defaulting to Node A.")
		targetNodeAPIURL = node1APIURL
	}
	attack.SimulateUnauthorizedBlockInjection(resolverInternalAPIURL, targetNodeAPIURL, node1APIURL)
	fmt.Println("Unauthorized Block Injection attempt finished.")
}

func handleSimulateBlockTampering() {
	fmt.Println("\n------- Simulate Block Tampering (Node - Invalid Signature) -------")
	targetNodeChoice := prompt("Enter target node (1, 2, or 3): ")
	var targetNodeAPIURL string
	switch targetNodeChoice {
	case "1":
		targetNodeAPIURL = node1APIURL
	case "2":
		targetNodeAPIURL = node2APIURL
	case "3":
		targetNodeAPIURL = node3APIURL
	default:
		fmt.Println("Invalid node choice. Defaulting to Node A.")
		targetNodeAPIURL = node1APIURL
	}
	attack.SimulateBlockTampering(resolverInternalAPIURL, targetNodeAPIURL, node1APIURL)
	fmt.Println("Block Tampering attempt finished.")
}

func handleSimulateImpersonationAttempt() {
	fmt.Println("\n-------- Simulate Impersonation Attempt (Node - Key Mismatch) --------")

	targetNodeChoice := prompt("Enter target node (1, 2, or 3): ")
	var targetNodeAPIURL string
	switch targetNodeChoice {
	case "1":
		targetNodeAPIURL = node1APIURL
	case "2":
		targetNodeAPIURL = node2APIURL
	case "3":
		targetNodeAPIURL = node3APIURL
	default:
		fmt.Println("Invalid node choice. Defaulting to Node A.")
		targetNodeAPIURL = node1APIURL
	}
	impersonatedValidatorID := prompt("Enter the ID of a legitimate validator to impersonate (e.g., validator-2): ")

	attack.SimulateImpersonationAttempt(resolverInternalAPIURL, targetNodeAPIURL, node1APIURL, impersonatedValidatorID)
	fmt.Println("Impersonation attempt finished.")
}
