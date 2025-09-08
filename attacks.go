package attack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"blockchain-dns/blockchain"
	"blockchain-dns/poa"
)

// sendDNSUpdateToNodeWithoutAuth mimics unauthorized attacks by sending DNS requests to the nodes without including the API key.
func sendDNSUpdateToNodeWithoutAuth(record blockchain.DNSRecord, nodeURL string) error {
	recordBytes, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal DNS record: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/dns/update", nodeURL), bytes.NewBuffer(recordBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send DNS update to node %s: %w", nodeURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("node %s returned non-OK status %d: %s", nodeURL, resp.StatusCode, string(bodyBytes))
	}
	return nil
}

// sendBlockToPeerDirectly sends a block directly to a node
func sendBlockToPeerDirectly(block *blockchain.Block, peerAddr string) error {
	blockBytes, err := json.Marshal(block)
	if err != nil {
		return fmt.Errorf("failed to marshal block: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/block/receive", peerAddr), bytes.NewBuffer(blockBytes))
	if err != nil {
		return fmt.Errorf("failed to create request to %s: %w", peerAddr, err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send block to %s: %w", peerAddr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("peer %s returned non-OK status %d: %s", peerAddr, resp.StatusCode, string(bodyBytes))
	}
	return nil
}

// getLatestBlockFromPeerDirectly fetches latest block from peer and routes it through the resolver.
func getLatestBlockFromPeerDirectly(resolverAPIAddr string, targetNodeAPIAddr string) (*blockchain.Block, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("%s/attack/get-latest-block?target_node_api_addr=%s", resolverAPIAddr, targetNodeAPIAddr)
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest block via resolver %s from node %s: %w", resolverAPIAddr, targetNodeAPIAddr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("resolver %s returned non-OK status %d for node %s: %s", resolverAPIAddr, resp.StatusCode, targetNodeAPIAddr, string(bodyBytes))
	}

	var block blockchain.Block
	if err := json.NewDecoder(resp.Body).Decode(&block); err != nil {
		return nil, fmt.Errorf("failed to decode latest block from resolver %s for node %s: %w", resolverAPIAddr, targetNodeAPIAddr, err)
	}
	return &block, nil
}

func SimulateDDoS(resolverAPIAddr string, targetDomain string, numRequests int, concurrency int, isNXDOMAINFlood bool) {
	attackType := "DDoS"
	if isNXDOMAINFlood {
		attackType = "NXDOMAIN Flood"
		log.Printf("\n--- Simulating %s Attack (on resolver) ---", attackType)
	} else {
		log.Printf("\n--- Simulating %s Attack (on resolver) ---", attackType)
	}

	log.Printf("Starting %s simulation on resolver %s for domain %s with %d requests (concurrency: %d)",
		attackType, resolverAPIAddr, targetDomain, numRequests, concurrency)

	var wg sync.WaitGroup
	requestChan := make(chan struct{}, concurrency)

	startTime := time.Now()
	successCount := 0
	failCount := 0

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		requestChan <- struct{}{}
		go func(reqNum int) {
			defer wg.Done()
			defer func() { <-requestChan }()

			domainToQuery := targetDomain
			if isNXDOMAINFlood {
				domainToQuery = fmt.Sprintf("random-%d-%d.%s", time.Now().UnixNano(), reqNum, targetDomain)
			}

			url := fmt.Sprintf("%s/resolve?domain=%s", resolverAPIAddr, domainToQuery)
			resp, err := http.Get(url)
			if err != nil {
				failCount++
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound {
				successCount++
			} else {
				failCount++
			}
		}(i)
	}

	wg.Wait()
	duration := time.Since(startTime)
	log.Printf("%s simulation completed. Total requests: %d, Success/Found: %d, Failed/Error: %d, Duration: %s",
		attackType, numRequests, successCount, failCount, duration)
}

func SimulateUnauthorizedDNSUpdate(targetNodeAPIAddr string, maliciousDomain string, maliciousIP string) {
	log.Printf("\n--- Simulating Unauthorized DNS Update (on %s directly) ---", targetNodeAPIAddr)

	maliciousRecord := blockchain.DNSRecord{
		Domain:     maliciousDomain,
		IPAddress:  maliciousIP,
		RecordType: "A",
		TTL:        30,
		Action:     "ADD",
	}

	err := sendDNSUpdateToNodeWithoutAuth(maliciousRecord, targetNodeAPIAddr)
	if err != nil {
		log.Printf("Unauthorized DNS Update failed: %v", err)
	} else {
		log.Printf("WARNING! Unauthorized DNS Update detected. Ignored by validator node.")
	}
	time.Sleep(3 * time.Second)
	log.Printf("Unauthorized DNS Update attempt finished")
}

func SimulateUnauthorizedBlockInjection(resolverAPIAddr string, targetNodeAPIAddr string, knownGoodNodeAPIAddr string) {
	log.Printf("\n--- Simulating Unauthorized Block Injection (on %s directly) ---", targetNodeAPIAddr)

	// get the latest block from a known good node to build upon
	latestBlock, err := getLatestBlockFromPeerDirectly(resolverAPIAddr, knownGoodNodeAPIAddr)
	if err != nil {
		log.Printf("Failed to get latest block from good node %s: %v. Cannot proceed.", knownGoodNodeAPIAddr, err)
		return
	}
	log.Printf("Got latest block %d from %s to build upon.", latestBlock.Index, knownGoodNodeAPIAddr)

	// creating a "malicious" validator (not part of the authorized set)
	maliciousValidator, err := poa.NewValidator("malicious-actor-4")
	if err != nil {
		log.Printf("Failed to create malicious validator: %v", err)
		return
	}
	log.Printf("Created malicious validator ID: %s", maliciousValidator.ID)

	// creating a new block with some fake DNS data
	fakeDNSData := []blockchain.DNSRecord{
		{Domain: "malicious.dns", IPAddress: "1.2.3.4", RecordType: "A", TTL: 60, Action: "ADD", Timestamp: time.Now().Unix()},
	}
	maliciousBlock := blockchain.NewBlock(latestBlock.Index+1, latestBlock.Hash, fakeDNSData, maliciousValidator.ID)
	maliciousBlock.Hash = maliciousBlock.CalculateHash()

	// signing the block with the malicious validator's private key
	if err := maliciousValidator.SignBlock(maliciousBlock); err != nil {
		log.Printf("Failed to sign malicious block: %v", err)
		return
	}
	log.Printf("Malicious block %d signed by %s. Sending to %s...", maliciousBlock.Index, maliciousValidator.ID, targetNodeAPIAddr)

	err = sendBlockToPeerDirectly(maliciousBlock, targetNodeAPIAddr)
	if err != nil {
		log.Printf("Unauthorized Block Injection failed: %v", err)
	} else {
		log.Printf("WARNING! Unauthorized Block Injection detected. Ignored by validator node.")
	}

	time.Sleep(3 * time.Second)
	log.Printf("Unauthorized Block Injection attempt finished")
}

func SimulateBlockTampering(resolverAPIAddr string, targetNodeAPIAddr string, knownGoodNodeAPIAddr string) {
	log.Printf("\n--- Simulating Block Tampering (on %s directly) ---", targetNodeAPIAddr)

	//get the latest block from a known good node
	latestBlock, err := getLatestBlockFromPeerDirectly(resolverAPIAddr, knownGoodNodeAPIAddr)
	if err != nil {
		log.Printf("Failed to get latest block from good node %s: %v. Cannot proceed.", knownGoodNodeAPIAddr, err)
		return
	}
	log.Printf("Got latest block %d from %s to tamper with.", latestBlock.Index, knownGoodNodeAPIAddr)

	//creating a tampered version of the block
	tamperedBlock := *latestBlock
	tamperedBlock.DNSData = make([]blockchain.DNSRecord, len(latestBlock.DNSData))
	copy(tamperedBlock.DNSData, latestBlock.DNSData)

	// fake data to tamper it
	tamperedBlock.DNSData = append(tamperedBlock.DNSData,
		blockchain.DNSRecord{Domain: "tampered.dns", IPAddress: "5.6.7.8", RecordType: "A", TTL: 60, Action: "ADD", Timestamp: time.Now().Unix()})
	tamperedBlock.Hash = tamperedBlock.CalculateHash() // recalculating hash for the tampered content

	tamperedBlock.ValidatorSignature = latestBlock.ValidatorSignature // using the original valid signature

	log.Printf("Tampered block %d created. Original signer: %s. Sending to %s...", tamperedBlock.Index, tamperedBlock.ValidatorID, targetNodeAPIAddr)

	err = sendBlockToPeerDirectly(&tamperedBlock, targetNodeAPIAddr)
	if err != nil {
		log.Printf("Successfully sent tampered block. Expected rejection from node: %v", err)
	} else {
		log.Printf("WARNING! Tampered block sent! Ignored by validator node due to hash mismatch")
	}
	time.Sleep(3 * time.Second)
	log.Printf("Block Tampering attempt finished.")
}

func SimulateImpersonationAttempt(resolverAPIAddr string, targetNodeAPIAddr string, knownGoodNodeAPIAddr string, legitimateValidatorID string) {
	log.Printf("\n--- Simulating Impersonation Attempt (on %s directly) ---", targetNodeAPIAddr)

	// get the latest block from a known good node
	latestBlock, err := getLatestBlockFromPeerDirectly(resolverAPIAddr, knownGoodNodeAPIAddr)
	if err != nil {
		log.Printf("Failed to get latest block from good node %s: %v. Cannot proceed.", knownGoodNodeAPIAddr, err)
		return
	}
	log.Printf("Got latest block %d from %s to build upon.", latestBlock.Index, knownGoodNodeAPIAddr)

	// creating a fake validator key pair
	fakeValidator, err := poa.NewValidator("fake-impersonator")
	if err != nil {
		log.Printf("Failed to create fake validator: %v", err)
		return
	}
	log.Printf("Created fake validator key pair. Fake ID: %s", fakeValidator.ID)

	// creating a new block but setting the ValidatorID to an actual one
	impersonatedBlock := blockchain.NewBlock(latestBlock.Index+1, latestBlock.Hash,
		[]blockchain.DNSRecord{
			{Domain: "impersonated.dns", IPAddress: "9.8.7.6", RecordType: "A", TTL: 60, Action: "ADD", Timestamp: time.Now().Unix()},
		},
		legitimateValidatorID)
	impersonatedBlock.Hash = impersonatedBlock.CalculateHash()

	// block signed with the fake validator's private key
	if err := fakeValidator.SignBlock(impersonatedBlock); err != nil {
		log.Printf("Failed to sign impersonated block: %v", err)
		return
	}
	log.Printf("Block %d signed by FAKE key, claiming to be %s. Sending to %s...", impersonatedBlock.Index, legitimateValidatorID, targetNodeAPIAddr)

	err = sendBlockToPeerDirectly(impersonatedBlock, targetNodeAPIAddr)
	if err != nil {
		log.Printf("Impersonation attempt failed: %v", err)
	} else {
		log.Printf("WARNING! Impersonation attempt detected. Ignored by validator node.")
	}
	time.Sleep(3 * time.Second)
	log.Printf("Impersonation attempt finished")
}

func SimulateDNSTunnelingAttempt(resolverAPIAddr string, message string, baseDomain string) {
	log.Printf("\n--- Simulating DNS Tunneling Attempt (on resolver) ---")

	log.Printf("Starting DNS Tunneling attempt on resolver %s for message '%s'", resolverAPIAddr, message)

	chunkSize := 60
	chunks := []string{}
	for i := 0; i < len(message); i += chunkSize {
		end := i + chunkSize
		if end > len(message) {
			end = len(message)
		}
		chunks = append(chunks, message[i:end])
	}

	for i, chunk := range chunks {
		encodedChunk := strings.ReplaceAll(chunk, ".", "-")
		tunnelDomain := fmt.Sprintf("%s-%d.%s", encodedChunk, i, baseDomain)
		url := fmt.Sprintf("%s/resolve?domain=%s", resolverAPIAddr, tunnelDomain)

		log.Printf("(DNS Tunneling) Querying: %s", tunnelDomain)
		resp, err := http.Get(url)
		if err != nil {
			log.Printf("(DNS Tunneling) Query failed for %s: %v", tunnelDomain, err)
		} else {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			log.Printf("(DNS Tunneling) Query response for %s: Status %d, Body: %s", tunnelDomain, resp.StatusCode, string(body))
		}
		time.Sleep(500 * time.Millisecond)
	}
	log.Printf("DNS Tunneling attempt completed.")
}
