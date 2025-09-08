package blockchain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// DNS Record struct
type DNSRecord struct {
	Domain     string `json:"domain"`
	IPAddress  string `json:"ip_address"`
	RecordType string `json:"record_type"`
	TTL        int    `json:"ttl"`
	Action     string `json:"action"`
	Timestamp  int64  `json:"timestamp"`
}

// the block struct
type Block struct {
	Index              int         `json:"index"`
	Timestamp          int64       `json:"timestamp"`
	DNSData            []DNSRecord `json:"dns_data"`
	PrevHash           string      `json:"prev_hash"`
	Hash               string      `json:"hash"`
	ValidatorID        string      `json:"validator_id"`
	ValidatorSignature []byte      `json:"validator_signature"`
}

// SHA256 of the block's content
func (b *Block) CalculateHash() string {
	tempBlock := *b
	tempBlock.Hash = ""
	tempBlock.ValidatorSignature = nil

	recordBytes, err := json.Marshal(tempBlock)
	if err != nil {
		panic(fmt.Sprintf("Error marshaling block for hashing: %v", err))
	}
	hash := sha256.Sum256(recordBytes) //returns 32-bit array
	return hex.EncodeToString(hash[:]) // converting to a slice to be used in fucntions
}

// NewBlock creates new block in the blockchain
func NewBlock(index int, prevHash string, dnsData []DNSRecord, validatorID string) *Block {
	block := &Block{
		Index:       index,
		Timestamp:   time.Now().Unix(), // use current time for non-genesis blocks
		DNSData:     dnsData,
		PrevHash:    prevHash,
		ValidatorID: validatorID,
	}
	return block
}

// Blockchain struct represents the entire chain of blocks
type Blockchain struct {
	Blocks []*Block
}

// NewBlockchain creates and returns a new blockchain with a genesis block
func NewBlockchain(genesisValidatorID string, genesisTimestamp int64) *Blockchain {
	ts := genesisTimestamp
	if ts == 0 {
		ts = time.Now().Unix()
	}

	genesisBlock := &Block{
		Index:       0,
		Timestamp:   ts,
		DNSData:     []DNSRecord{},
		PrevHash:    "0",
		ValidatorID: genesisValidatorID,
	}
	genesisBlock.Hash = genesisBlock.CalculateHash()

	return &Blockchain{
		Blocks: []*Block{genesisBlock},
	}
}

// AddBlock adds a new block to the blockchain
func (bc *Blockchain) AddBlock(block *Block) {
	bc.Blocks = append(bc.Blocks, block)
}

// GetLatestBlock returns the last block in the chain
func (bc *Blockchain) GetLatestBlock() *Block {
	if len(bc.Blocks) == 0 {
		return nil
	}
	return bc.Blocks[len(bc.Blocks)-1]
}

// IsValidBlock checks if the entire blockchain is valid
func (bc *Blockchain) IsValidBlock() bool {
	if len(bc.Blocks) == 0 {
		return true
	}

	for i := 1; i < len(bc.Blocks); i++ {
		currentBlock := bc.Blocks[i]
		prevBlock := bc.Blocks[i-1]

		if currentBlock.PrevHash != prevBlock.Hash {
			fmt.Printf("Chain invalid: Block %d's PrevHash (%s) does not match previous block %d's Hash (%s)\n",
				currentBlock.Index, currentBlock.PrevHash, prevBlock.Index, prevBlock.Hash)
			return false
		}

		if currentBlock.Hash != currentBlock.CalculateHash() {
			fmt.Printf("Chain invalid: Block %d's hash (%s) is incorrect, expected (%s)\n",
				currentBlock.Index, currentBlock.Hash, currentBlock.CalculateHash())
			return false
		}
	}
	return true
}

// GetDNSRecord retrieves the latest active DNS record for a given domain
func (bc *Blockchain) GetDNSRecord(domain string) *DNSRecord {
	for i := len(bc.Blocks) - 1; i >= 0; i-- {
		block := bc.Blocks[i]
		for j := len(block.DNSData) - 1; j >= 0; j-- {
			record := block.DNSData[j]
			if record.Domain == domain {
				if record.Action == "DELETE" {
					return nil
				}
				return &record
			}
		}
	}
	return nil
}

// GetAllActiveDNSRecords creates the cache with all currently active DNS records.
func (bc *Blockchain) GetAllActiveDNSRecords() map[string]DNSRecord {
	activeRecords := make(map[string]DNSRecord)

	for _, block := range bc.Blocks {
		for _, record := range block.DNSData {
			switch record.Action {
			case "ADD", "UPDATE":
				activeRecords[record.Domain] = record
			case "DELETE":
				delete(activeRecords, record.Domain)
			}
		}
	}
	return activeRecords
}

// SaveBlockchain saves the blockchain to a file
func SaveBlockchain(bc *Blockchain, filepath string) error {
	data, err := json.MarshalIndent(bc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal blockchain: %w", err)
	}
	return os.WriteFile(filepath, data, 0644)
}

// LoadBlockchain loads the blockchain from a file.
func LoadBlockchain(filepath string) (*Blockchain, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("blockchain file not found at %s", filepath)
		}
		return nil, fmt.Errorf("failed to read blockchain file: %w", err)
	}

	var bc Blockchain
	if err := json.Unmarshal(data, &bc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal blockchain: %w", err)
	}
	return &bc, nil
}
