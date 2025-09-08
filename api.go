package node

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"blockchain-dns/blockchain"
)

// API key
const AUTH_API_KEY = "super_secret_dns_admin_key_12345"

// Mempool handles pending DNS records before being added to blockchain.
type Mempool struct {
	records []blockchain.DNSRecord
	mu      sync.Mutex
}

// NewMempool creates a new mempool instance
func NewMempool() *Mempool {
	return &Mempool{
		records: make([]blockchain.DNSRecord, 0),
	}
}

// adding a new DNS record to the mempool
func (m *Mempool) AddRecord(record blockchain.DNSRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = append(m.records, record)
	log.Printf("Mempool: Added DNS record for %s. Total pending: %d", record.Domain, len(m.records))
}

// GetPendingRecords retrieves all records from the mempool and clears it.
func (m *Mempool) GetPendingRecords() []blockchain.DNSRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	records := m.records
	m.records = make([]blockchain.DNSRecord, 0)
	return records
}

// Clear() clears all records from the mempool.
func (m *Mempool) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = make([]blockchain.DNSRecord, 0)
	log.Println("Mempool: Cleared all pending records.")
}

// startAPIServer starts the HTTP server for the node.
func (n *Node) startAPIServer() {
	http.HandleFunc("/dns/update", n.handleDNSUpdate)
	http.HandleFunc("/dns/resolve", n.handleDNSResolve)
	http.HandleFunc("/block/latest", n.handleGetLatestBlock)
	http.HandleFunc("/block/receive", n.handleReceiveBlock)
	http.HandleFunc("/status", n.handleStatus)

	// create an IPv4 listener
	listener, err := net.Listen("tcp4", n.NodeAPIAddr)
	if err != nil {
		log.Fatalf("Node %s: Failed to listen on %s (IPv4): %v", n.ID, n.NodeAPIAddr, err)
	}
	defer listener.Close()

	log.Printf("Node %s: API server listening on %s (IPv4)", n.ID, n.NodeAPIAddr)
	err = http.Serve(listener, nil)
	if err != nil {
		log.Fatalf("Node %s: API server failed: %v", n.ID, err)
	}
}

// handleDNSUpdate handles DNS update requests (add, update, delete)
func (n *Node) handleDNSUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	// API Key authentication
	apiKey := r.Header.Get("X-API-Key")
	if apiKey != AUTH_API_KEY {
		http.Error(w, "Unauthorized: Invalid/missing API Key", http.StatusUnauthorized)
		log.Printf("Node %s: Unauthorized DNS update attempt from %s (Key: %s)", n.ID, r.RemoteAddr, apiKey)
		return
	}

	var record blockchain.DNSRecord
	if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	// basic validation for DNS record fields
	if record.Domain == "" || record.RecordType == "" || record.Action == "" {
		http.Error(w, "Missing required DNS record fields (domain, record_type, action)", http.StatusBadRequest)
		return
	}
	if record.Action != "ADD" && record.Action != "UPDATE" && record.Action != "DELETE" {
		http.Error(w, "Invalid action. Must be ADD, UPDATE, or DELETE.", http.StatusBadRequest)
		return
	}
	// For add and update, IPAddress is required
	if (record.Action == "ADD" || record.Action == "UPDATE") && record.IPAddress == "" {
		http.Error(w, "IPAddress is required for ADD/UPDATE actions", http.StatusBadRequest)
		return
	}

	record.Timestamp = time.Now().Unix() // setting timestamp at node reception
	n.Mempool.AddRecord(record)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "DNS update request added to mempool. Will be processed in next block."})
	log.Printf("Node %s: Received AUTHORIZED DNS update request for %s (Action: %s)", n.ID, record.Domain, record.Action)
}

// handleDNSResolve for incoming DNS resolution requests
func (n *Node) handleDNSResolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "Missing 'domain' query parameter", http.StatusBadRequest)
		return
	}

	record := n.GetDNSRecordFromCache(domain)
	if record == nil {
		http.Error(w, "Domain not found or deleted", http.StatusNotFound)
		log.Printf("Node %s: DNS resolution request for %s: Not Found", n.ID, domain)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(record)
	log.Printf("Node %s: DNS resolution request for %s: Resolved to %s", n.ID, domain, record.IPAddress)
}

// handleGetLatestBlock returns the latest block in the node's blockchain
func (n *Node) handleGetLatestBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	n.mu.Lock()
	latestBlock := n.Blockchain.GetLatestBlock()
	n.mu.Unlock()

	if latestBlock == nil {
		http.Error(w, "Blockchain is empty", http.StatusInternalServerError)
		log.Printf("Node %s: Responding to /block/latest, but blockchain is empty.", n.ID)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(latestBlock)
	log.Printf("Node %s: Responded to /block/latest with block %d.", n.ID, latestBlock.Index)
}

// handleReceiveBlock handles incoming blocks from peers nodes
func (n *Node) handleReceiveBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var block blockchain.Block
	if err := json.NewDecoder(r.Body).Decode(&block); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		log.Printf("Node %s: Error decoding incoming block: %v", n.ID, err)
		return
	}

	log.Printf("Node %s: Received block %d from %s for processing.", n.ID, block.Index, block.ValidatorID)
	go n.HandleIncomingBlock(&block)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Block received for processing."})
}

// handleStatus returns the node's current status
func (n *Node) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	n.mu.Lock()
	latestBlockIndex := n.Blockchain.GetLatestBlock().Index
	chainLength := len(n.Blockchain.Blocks)
	pendingRecords := len(n.Mempool.records)
	n.mu.Unlock()

	status := map[string]interface{}{
		"node_id":         n.ID,
		"api_address":     n.NodeAPIAddr,
		"latest_block":    latestBlockIndex,
		"chain_length":    chainLength,
		"pending_records": pendingRecords,
		"is_validator":    true,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(status)
	log.Printf("Node %s: Responded to /status request. Latest block: %d", n.ID, latestBlockIndex)
}

// sendBlockToPeer sends a block to a specific peer's block receiving endpoint
func sendBlockToPeer(block *blockchain.Block, peerAddr string) error {
	blockBytes, err := json.Marshal(block)
	if err != nil {
		return fmt.Errorf("failed to marshal block: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/block/receive", peerAddr), bytes.NewBuffer(blockBytes))
	if err != nil {
		return fmt.Errorf("failed to create request to %s: %w", peerAddr, err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second} // 10 second timeout for post
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

// getLatestBlockFromPeer fetches the latest block from a peer
func getLatestBlockFromPeer(peerAddr string) (*blockchain.Block, error) {
	client := &http.Client{Timeout: 5 * time.Second} // 5 second timeout
	resp, err := client.Get(fmt.Sprintf("%s/block/latest", peerAddr))
	if err != nil {
		return nil, fmt.Errorf("failed to get latest block from %s: %w", peerAddr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("peer %s returned non-OK status %d: %s", peerAddr, resp.StatusCode, string(bodyBytes))
	}

	var block blockchain.Block
	if err := json.NewDecoder(resp.Body).Decode(&block); err != nil {
		return nil, fmt.Errorf("failed to decode latest block from %s: %w", peerAddr, err)
	}
	return &block, nil
}
