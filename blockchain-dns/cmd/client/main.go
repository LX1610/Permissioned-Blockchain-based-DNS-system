package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"blockchain-dns/attack"
	"blockchain-dns/blockchain"
)

const (
	// Resolver IP (facing client)
	ResolverIP = "192.168.56.21"

	// Client IP
	ClientIP = "192.168.56.20"

	// Resolver API Port
	ResolverAPIPort = "8080"
)

var (
	reader         *bufio.Reader
	resolverAPIURL string
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	reader = bufio.NewReader(os.Stdin) // initializing global reader

	fmt.Println("\nPress Enter to continue to the interactive menu...")
	readLine() // waiting for user to press Enter

	// initialize API URLs based on constants
	resolverAPIURL = fmt.Sprintf("http://%s:%s", ResolverIP, ResolverAPIPort)

	fmt.Println("Ensure all VMs are running their respective applications before proceeding.")
	time.Sleep(2 * time.Second) // giving system time to settle

	for {
		printMenu()
		choiceStr := readLine()
		choice, err := strconv.Atoi(strings.TrimSpace(choiceStr))
		if err != nil {
			fmt.Println("Invalid input. Please enter a valid number.")
			continue
		}

		switch choice {
		case 1:
			handleAddRecord()
		case 2:
			handleUpdateRecord()
		case 3:
			handleDeleteRecord()
		case 4:
			handleResolveRecord()
		case 5:
			handleSimulateDDoS()
		case 6:
			handleSimulateDNSTunneling()
		case 0:
			fmt.Println("Exiting client")
			return
		default:
			fmt.Println("Invalid choice. Please select an option from the menu.")
		}
		fmt.Println("\n-------- Operation Complete --------")
		time.Sleep(1 * time.Second) // small pause before showing menu again
	}
}

func printMenu() {
	fmt.Println("\nSelect a DNS operation")
	fmt.Println("  1. Add DNS Record")
	fmt.Println("  2. Update DNS Record")
	fmt.Println("  3. Delete DNS Record")
	fmt.Println("  4. Resolve DNS Record")
	fmt.Println("Attack Simulations:")
	fmt.Println("  5. Simulate DDoS / NXDOMAIN Flood (Resolver)")
	fmt.Println("  6. Simulate DNS Tunneling Attempt (Resolver)")
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

// standard dns opertation functions

func handleAddRecord() {
	fmt.Println("\nAdd DNS Record")
	domain := prompt("Enter a domain: ")
	ip := prompt("Enter IP Address: ")
	recordType := prompt("Enter Record Type: ")
	ttl := promptInt("Enter TTL in seconds: ")

	record := blockchain.DNSRecord{
		Domain:     domain,
		IPAddress:  ip,
		RecordType: recordType,
		TTL:        ttl,
		Action:     "ADD",
	}
	sendUpdate(record, resolverAPIURL)
	fmt.Println("Waiting for block to be mined...")
	time.Sleep(6 * time.Second)
}

func handleUpdateRecord() {
	fmt.Println("\nUpdate DNS Record")
	domain := prompt("Enter domain to update: ")
	ip := prompt("Enter New IP Address: ")
	recordType := prompt("Enter New Record Type: ")
	ttl := promptInt("Enter New TTL in seconds: ")

	record := blockchain.DNSRecord{
		Domain:     domain,
		IPAddress:  ip,
		RecordType: recordType,
		TTL:        ttl,
		Action:     "UPDATE",
	}
	sendUpdate(record, resolverAPIURL)
	fmt.Println("Waiting for block to be mined...")
	time.Sleep(6 * time.Second)
}

func handleDeleteRecord() {
	fmt.Println("\nDelete DNS Record")
	domain := prompt("Enter domain to delete: ")

	record := blockchain.DNSRecord{
		Domain:     domain,
		IPAddress:  "",
		RecordType: "A",
		TTL:        0,
		Action:     "DELETE",
	}
	sendUpdate(record, resolverAPIURL)
	fmt.Println("Waiting for block to be mined...")
	time.Sleep(6 * time.Second)
}

func handleResolveRecord() {
	fmt.Println("\nResolve DNS Record")
	domain := prompt("Enter domain to resolve: ")
	resolveRecord(domain, resolverAPIURL)
}

//attack simulation functions (resolver-focused)

func handleSimulateDDoS() {
	fmt.Println("\nSimulate DDoS / NXDOMAIN Flood")
	attackTypeChoice := prompt("Choose attack type (1 for DDoS, 2 for NXDOMAIN Flood): ")
	isNXDOMAINFlood := false
	if attackTypeChoice == "2" {
		isNXDOMAINFlood = true
	} else if attackTypeChoice != "1" {
		fmt.Println("Invalid choice. Defaulting to DDoS.")
	}

	targetDomain := prompt("Enter target domain: ")
	numRequests := promptInt("Enter number of requests: ")
	concurrency := promptInt("Enter concurrency: ")

	attack.SimulateDDoS(resolverAPIURL, targetDomain, numRequests, concurrency, isNXDOMAINFlood)
	fmt.Println("DDoS/NXDOMAIN Flood simulation finished.")
}

func handleSimulateDNSTunneling() {
	fmt.Println("\nSimulate DNS Tunneling Attempt (Resolver)")
	message := prompt("Enter a message to attempt to tunnel: ")
	baseDomain := prompt("Enter a base domain for tunneling: ")

	attack.SimulateDNSTunnelingAttempt(resolverAPIURL, message, baseDomain)
	fmt.Println("DNS Tunneling attempt finished.")
}

//shared client helper functions

func sendUpdate(record blockchain.DNSRecord, resolverAddr string) {
	recordBytes, err := json.Marshal(record)
	if err != nil {
		fmt.Printf("Error marshaling record: %v\n", err)
		return
	}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/update", resolverAddr), bytes.NewBuffer(recordBytes))
	if err != nil {
		fmt.Printf("Error creating request to resolver: %v\n", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error sending update to resolver: %v\n", err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Update response from Resolver: Status %d, Body: %s\n", resp.StatusCode, string(body))
}

func resolveRecord(domain string, resolverAddr string) {
	fmt.Printf("\nClient: Resolving %s (via Resolver)...\n", domain)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("%s/resolve?domain=%s", resolverAddr, domain))
	if err != nil {
		fmt.Printf("Error resolving %s: %v\n", domain, err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		var record blockchain.DNSRecord
		if err := json.Unmarshal(body, &record); err != nil {
			fmt.Printf("Error unmarshaling resolved record: %v\n", err)
			return
		}
		fmt.Printf("Resolved %s -> IP: %s, Type: %s, TTL: %d\n", record.Domain, record.IPAddress, record.RecordType, record.TTL)
	} else {
		fmt.Printf("Failed to resolve %s. Status: %d, Message: %s\n", domain, resp.StatusCode, string(body))
	}
}
