package resolver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"blockchain-dns/blockchain"
)

// API Key
const AUTH_API_KEY = "super_secret_dns_admin_key_12345"

// SendDNSUpdateToNode sends DNS update request to a specific validator node
func SendDNSUpdateToNode(record blockchain.DNSRecord, nodeURL string) error {
	recordBytes, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal DNS record: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/dns/update", nodeURL), bytes.NewBuffer(recordBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", AUTH_API_KEY)

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

// GetDNSRecordFromNode fetches a DNS record from a specific validator node
func GetDNSRecordFromNode(domain string, nodeURL string) (*blockchain.DNSRecord, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("%s/dns/resolve?domain=%s", nodeURL, domain))
	if err != nil {
		return nil, fmt.Errorf("failed to reach node %s: %w", nodeURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("node %s returned non-OK status %d: %s", nodeURL, resp.StatusCode, string(bodyBytes))
	}

	var record blockchain.DNSRecord
	if err := json.NewDecoder(resp.Body).Decode(&record); err != nil {
		return nil, fmt.Errorf("failed to decode DNS record from node %s: %w", nodeURL, err)
	}
	return &record, nil
}
