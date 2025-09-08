package resolver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"blockchain-dns/blockchain"
)

// DNSRecordCacheEntry stores a DNS record and its expiration time
type DNSRecordCacheEntry struct {
	Record     *blockchain.DNSRecord
	ExpiresAt  time.Time
	IsNXDOMAIN bool // negative cache entry(non-existent)
}

// DNSCache with negative caching
type DNSCache struct {
	mu    sync.RWMutex
	cache map[string]DNSRecordCacheEntry
}

// NewDNSCache creates a new resolver Cache
func NewDNSCache() *DNSCache {
	return &DNSCache{
		cache: make(map[string]DNSRecordCacheEntry),
	}
}

// Get retrieves record from the cache, returns nil if not found/expired.
func (c *DNSCache) Get(domain string) *blockchain.DNSRecord {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.cache[domain]
	if !ok || time.Now().After(entry.ExpiresAt) {
		if ok {
			log.Printf("Cache: Record for %s expired or not found.", domain)
		}
		return nil
	}

	if entry.IsNXDOMAIN {
		log.Printf("Cache: Served NXDOMAIN for %s from negative cache.", domain)
		return nil
	}
	log.Printf("Cache: Served record for %s from positive cache.", domain)
	return entry.Record
}

// Set adds/updates a record in the cache.
func (c *DNSCache) Set(record blockchain.DNSRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()

	ttl := record.TTL
	if ttl <= 0 {
		ttl = 60
	}
	c.cache[record.Domain] = DNSRecordCacheEntry{
		Record:     &record,
		ExpiresAt:  time.Now().Add(time.Duration(ttl) * time.Second),
		IsNXDOMAIN: false,
	}
	log.Printf("Cache: Set positive record for %s (TTL: %d seconds)", record.Domain, ttl)
}

// SetNXDOMAIN adds a negative cache entry for non-existent domains
func (c *DNSCache) SetNXDOMAIN(domain string, ttl int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if ttl <= 0 {
		ttl = 60 // default negative cache TTL
	}
	c.cache[domain] = DNSRecordCacheEntry{
		Record:     nil,
		ExpiresAt:  time.Now().Add(time.Duration(ttl) * time.Second),
		IsNXDOMAIN: true,
	}
	log.Printf("Cache: Set NXDOMAIN for %s (TTL: %d seconds)", domain, ttl)
}

// Invalidate removes  record from the cache
func (c *DNSCache) Invalidate(domain string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.cache, domain)
	log.Printf("Cache: Invalidated record for %s", domain)
}

// Resolver struct
type Resolver struct {
	ID          string
	APIAddr     string   // address this resolver's API listens on
	NodeAPIURLs []string // list of nodes
	Cache       *DNSCache
	stopChan    chan struct{}
}

// NewResolver creates and initializes a new DNS resolver
func NewResolver(id string, apiAddr string, nodeAPIURLs []string) *Resolver {
	return &Resolver{
		ID:          id,
		APIAddr:     apiAddr,
		NodeAPIURLs: nodeAPIURLs,
		Cache:       NewDNSCache(),
		stopChan:    make(chan struct{}),
	}
}

// StartResolver begins the resolver's API server
func (r *Resolver) StartResolver() {
	log.Printf("Resolver %s: Starting API server on %s", r.ID, r.APIAddr)
	http.HandleFunc("/resolve", r.handleResolve)
	http.HandleFunc("/update", r.handleUpdate)
	http.HandleFunc("/status", r.handleStatus)

	http.HandleFunc("/attack/unauth-dns-update", r.handleAttackUnauthorizedDNSUpdate)
	http.HandleFunc("/attack/unauth-block-inject", r.handleAttackUnauthorizedBlockInjection)
	http.HandleFunc("/attack/block-tamper", r.handleAttackBlockTampering)
	http.HandleFunc("/attack/impersonate", r.handleAttackImpersonation)
	http.HandleFunc("/attack/get-latest-block", r.handleAttackGetLatestBlock)

	// IPv4 listener
	listener, err := net.Listen("tcp4", r.APIAddr)
	if err != nil {
		log.Fatalf("Resolver %s: Failed to listen on %s (IPv4): %v", r.ID, r.APIAddr, err)
	}
	defer listener.Close()

	log.Printf("Resolver %s: API server listening on %s (IPv4)", r.ID, r.APIAddr)
	err = http.Serve(listener, nil)
	if err != nil {
		log.Fatalf("Resolver %s: API server failed: %v", r.ID, err)
	}
}

// StopResolver stops the resolver
func (r *Resolver) StopResolver() {
	close(r.stopChan)
	log.Printf("Resolver %s: Stopping...", r.ID)
}

// handleResolve handles incoming DNS requests from clients
func (r *Resolver) handleResolve(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	domain := req.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "Missing 'domain' query parameter", http.StatusBadRequest)
		return
	}

	// basic input validation for domain name
	if len(domain) > 253 || !isValidDomainName(domain) { //basic char check
		http.Error(w, "Invalid domain name format", http.StatusBadRequest)
		log.Printf("Resolver %s: Invalid domain name received: %s", r.ID, domain)
		return
	}

	// trying to resolve from cache
	if cachedRecord := r.Cache.Get(domain); cachedRecord != nil {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(cachedRecord)
		log.Printf("Resolver %s: Resolved %s from cache to %s", r.ID, domain, cachedRecord.IPAddress)
		return
	} else {
		// checking if it's in negative cache(non-existent)
		r.Cache.mu.RLock()
		entry, ok := r.Cache.cache[domain]
		r.Cache.mu.RUnlock()
		if ok && entry.IsNXDOMAIN && !time.Now().After(entry.ExpiresAt) {
			http.Error(w, "Domain not found (cached NXDOMAIN)", http.StatusNotFound)
			log.Printf("Resolver %s: Served NXDOMAIN for %s from negative cache.", r.ID, domain)
			return
		}
	}

	// if not in cache or expired, querying validator nodes
	log.Printf("Resolver %s: %s not in cache, querying validator nodes...", r.ID, domain)
	resolvedRecord, err := r.queryValidatorNodesForDNS(domain)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to resolve domain %s: %v", domain, err), http.StatusInternalServerError)
		log.Printf("Resolver %s: Failed to resolve %s from validators: %v", r.ID, domain, err)
		return
	}

	if resolvedRecord == nil {
		// domain not found in blockchain, set negative cache(since non-existent)
		r.Cache.SetNXDOMAIN(domain, 60)
		http.Error(w, "Domain not found in blockchain", http.StatusNotFound)
		log.Printf("Resolver %s: Domain %s not found in blockchain.", r.ID, domain)
		return
	}

	// caching the result and return
	r.Cache.Set(*resolvedRecord)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resolvedRecord)
	log.Printf("Resolver %s: Resolved %s from blockchain to %s and cached.", r.ID, domain, resolvedRecord.IPAddress)
}

// basic domain validation
func isValidDomainName(domain string) bool {
	if len(domain) == 0 {
		return false
	}
	for _, r := range domain {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			continue
		}
		return false
	}
	return true
}

// handleUpdate handles DNS update requests from client
func (r *Resolver) handleUpdate(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var record blockchain.DNSRecord
	if err := json.NewDecoder(req.Body).Decode(&record); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	// basic validation for DNS record fields
	if record.Domain == "" || record.RecordType == "" || record.Action == "" {
		http.Error(w, "Missing required DNS record fields", http.StatusBadRequest)
		return
	}
	if record.Action != "ADD" && record.Action != "UPDATE" && record.Action != "DELETE" {
		http.Error(w, "Invalid action. Must be ADD, UPDATE, or DELETE.", http.StatusBadRequest)
		return
	}
	if (record.Action == "ADD" || record.Action == "UPDATE") && record.IPAddress == "" {
		http.Error(w, "IP Address is required for ADD/UPDATE actions", http.StatusBadRequest)
		return
	}
	// input validation for domain name in update requests
	if len(record.Domain) > 253 || !isValidDomainName(record.Domain) {
		http.Error(w, "Invalid domain name format in record", http.StatusBadRequest)
		log.Printf("Resolver %s: Invalid domain name received in update: %s", r.ID, record.Domain)
		return
	}

	// forwarding to nodes
	var successCount int
	var errorMessages []string
	for _, nodeURL := range r.NodeAPIURLs {
		log.Printf("Resolver %s: Attempting to forward DNS update for %s to node %s", r.ID, record.Domain, nodeURL)
		err := SendDNSUpdateToNode(record, nodeURL)
		if err != nil {
			errorMessages = append(errorMessages, fmt.Sprintf("node %s: %v", nodeURL, err))
			log.Printf("Resolver %s: Failed to forward DNS update for %s to node %s: %v", r.ID, record.Domain, nodeURL, err)
		} else {
			successCount++
			log.Printf("Resolver %s: Successfully forwarded DNS update for %s to node %s", r.ID, record.Domain, nodeURL)
		}
	}

	if successCount == 0 {
		http.Error(w, fmt.Sprintf("Failed to forward DNS update to any validator node: %s", strings.Join(errorMessages, "; ")), http.StatusInternalServerError)
		return
	}

	// invalidate the cache for the updated domain immediately
	r.Cache.Invalidate(record.Domain)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "DNS update forwarded to validator node(s) for processing."})
	log.Printf("Resolver %s: Forwarded DNS update for %s (Action: %s) to %d node(s) successfully.", r.ID, record.Domain, record.Action, successCount)
}

// handleStatus returns the resolver's current status
func (r *Resolver) handleStatus(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	status := map[string]interface{}{
		"resolver_id":     r.ID,
		"api_address":     r.APIAddr,
		"validator_nodes": r.NodeAPIURLs,
		"cache_size":      len(r.Cache.cache),
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(status)
	log.Printf("Resolver %s: Responded to /status request. Cache size: %d", r.ID, len(r.Cache.cache))
}

// queryValidatorNodesForDNS queries validator nodes
func (r *Resolver) queryValidatorNodesForDNS(domain string) (*blockchain.DNSRecord, error) {
	for _, nodeURL := range r.NodeAPIURLs {
		log.Printf("Resolver %s: Attempting to query node %s for domain %s", r.ID, nodeURL, domain)
		// function from resolver/client.go
		record, err := GetDNSRecordFromNode(domain, nodeURL)
		if err == nil {
			log.Printf("Resolver %s: Successfully got DNS record from node %s for domain %s", r.ID, nodeURL, domain)
			return record, nil
		}
		log.Printf("Resolver %s: Failed to get DNS record from node %s: %v", r.ID, nodeURL, err)
	}
	return nil, fmt.Errorf("all validator nodes failed to resolve domain %s", domain)
}

// AttackPayload struct to receive attack parameters from client
type AttackPayload struct {
	TargetNodeAPIAddr     string `json:"target_node_api_addr"`
	KnownGoodNodeAPIAddr  string `json:"known_good_node_api_addr"`
	LegitimateValidatorID string `json:"legitimate_validator_id"`
	MaliciousDomain       string `json:"malicious_domain"`
	MaliciousIP           string `json:"malicious_ip"`
	// Block data for tampering/injection
	Index              int                    `json:"index"`
	Timestamp          int64                  `json:"timestamp"`
	DNSData            []blockchain.DNSRecord `json:"dns_data"`
	PrevHash           string                 `json:"prev_hash"`
	Hash               string                 `json:"hash"`
	ValidatorID        string                 `json:"validator_id"`
	ValidatorSignature []byte                 `json:"validator_signature"`
}

// handleAttackUnauthorizedDNSUpdate receives unauthorized DNS request from client and forwards it.
func (r *Resolver) handleAttackUnauthorizedDNSUpdate(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}
	var payload AttackPayload
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		http.Error(w, fmt.Sprintf("Invalid payload: %v", err), http.StatusBadRequest)
		return
	}

	record := blockchain.DNSRecord{
		Domain: payload.MaliciousDomain, IPAddress: payload.MaliciousIP,
		RecordType: "A", TTL: 30, Action: "ADD", Timestamp: time.Now().Unix(),
	}
	log.Printf("Resolver %s: Forwarding UNAUTHORIZED DNS Update for %s to %s", r.ID, record.Domain, payload.TargetNodeAPIAddr)
	err := sendDNSUpdateToNodeWithoutAuthResolver(record, payload.TargetNodeAPIAddr)
	if err != nil {
		http.Error(w, fmt.Sprintf("Forwarding failed: %v", err), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Unauthorized DNS Update forwarded."})
}

// handleAttackUnauthorizedBlockInjection receives an unauthorized block injection request and forwards it.
func (r *Resolver) handleAttackUnauthorizedBlockInjection(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}
	var payload AttackPayload
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		http.Error(w, fmt.Sprintf("Invalid payload: %v", err), http.StatusBadRequest)
		return
	}

	block := blockchain.Block{
		Index: payload.Index, Timestamp: payload.Timestamp, DNSData: payload.DNSData,
		PrevHash: payload.PrevHash, Hash: payload.Hash, ValidatorID: payload.ValidatorID,
		ValidatorSignature: payload.ValidatorSignature,
	}
	log.Printf("Resolver %s: Forwarding unauthorized Block Injection (Block %d) to %s", r.ID, block.Index, payload.TargetNodeAPIAddr)
	err := sendBlockToPeerDirectlyResolver(&block, payload.TargetNodeAPIAddr)
	if err != nil {
		http.Error(w, fmt.Sprintf("Forwarding failed: %v", err), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Unauthorized Block Injection forwarded."})
}

// handleAttackBlockTampering receives a block tampering request and forwards it
func (r *Resolver) handleAttackBlockTampering(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}
	var payload AttackPayload
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		http.Error(w, fmt.Sprintf("Invalid payload: %v", err), http.StatusBadRequest)
		return
	}

	block := blockchain.Block{
		Index: payload.Index, Timestamp: payload.Timestamp, DNSData: payload.DNSData,
		PrevHash: payload.PrevHash, Hash: payload.Hash, ValidatorID: payload.ValidatorID,
		ValidatorSignature: payload.ValidatorSignature,
	}
	log.Printf("Resolver %s: Forwarding Block Tampering attempt (Block %d) to %s", r.ID, block.Index, payload.TargetNodeAPIAddr)
	err := sendBlockToPeerDirectlyResolver(&block, payload.TargetNodeAPIAddr)
	if err != nil {
		http.Error(w, fmt.Sprintf("Forwarding failed: %v", err), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Block Tampering attempt forwarded."})
}

// handleAttackImpersonation receives an impersonation request and forwards it
func (r *Resolver) handleAttackImpersonation(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}
	var payload AttackPayload
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		http.Error(w, fmt.Sprintf("Invalid payload: %v", err), http.StatusBadRequest)
		return
	}

	block := blockchain.Block{
		Index: payload.Index, Timestamp: payload.Timestamp, DNSData: payload.DNSData,
		PrevHash: payload.PrevHash, Hash: payload.Hash, ValidatorID: payload.ValidatorID,
		ValidatorSignature: payload.ValidatorSignature,
	}
	log.Printf("Resolver %s: Forwarding Impersonation attempt (Block %d) to %s", r.ID, block.Index, payload.TargetNodeAPIAddr)
	err := sendBlockToPeerDirectlyResolver(&block, payload.TargetNodeAPIAddr)
	if err != nil {
		http.Error(w, fmt.Sprintf("Forwarding failed: %v", err), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Impersonation attempt forwarded."})
}

// handleAttackGetLatestBlock handles requests to get the latest block from a node
func (r *Resolver) handleAttackGetLatestBlock(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, "Only GET allowed", http.StatusMethodNotAllowed)
		return
	}
	targetNodeAPIAddr := req.URL.Query().Get("target_node_api_addr")
	if targetNodeAPIAddr == "" {
		http.Error(w, "Missing 'target_node_api_addr' query parameter", http.StatusBadRequest)
		return
	}

	log.Printf("Resolver %s: Forwarding GetLatestBlock request to node %s", r.ID, targetNodeAPIAddr)
	block, err := getLatestBlockFromPeerDirectlyResolver(targetNodeAPIAddr)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get latest block from node: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(block)
}

func sendDNSUpdateToNodeWithoutAuthResolver(record blockchain.DNSRecord, nodeURL string) error {
	recordBytes, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal error: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/dns/update", nodeURL), bytes.NewBuffer(recordBytes))
	if err != nil {
		return fmt.Errorf("create request error: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// no API Key header here

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send request error: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("non-OK status %d: %s", resp.StatusCode, string(bodyBytes))
	}
	return nil
}

func sendBlockToPeerDirectlyResolver(block *blockchain.Block, peerAddr string) error {
	blockBytes, err := json.Marshal(block)
	if err != nil {
		return fmt.Errorf("marshal error: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/block/receive", peerAddr), bytes.NewBuffer(blockBytes))
	if err != nil {
		return fmt.Errorf("create request error: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send request error: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("non-OK status %d: %s", resp.StatusCode, string(bodyBytes))
	}
	return nil
}

// getLatestBlockFromPeerDirectlyResolver fetches the latest block from a peer's /block/latest endpoint.
func getLatestBlockFromPeerDirectlyResolver(peerAddr string) (*blockchain.Block, error) {
	client := &http.Client{Timeout: 5 * time.Second}
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
