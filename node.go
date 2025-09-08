package node

import (
	"fmt"
	"log"
	"sync"
	"time"

	"blockchain-dns/blockchain"
	"blockchain-dns/poa"
)

// Single Node struct
type Node struct {
	ID            string
	Validator     *poa.Validator
	Blockchain    *blockchain.Blockchain
	Mempool       *Mempool
	ValidatorSet  *poa.ValidatorSet
	Peers         []string   // list of peer node API addresses
	NodeAPIAddr   string     // current node's API server
	mu            sync.Mutex // mutex to protect blockchain and mempool access
	stopChan      chan struct{}
	dnsStateCache map[string]blockchain.DNSRecord // cache of the current DNS state
}

// To generate the exact same genesis block hash.
const GenesisTimestamp = 1672531200

// NewNode creates and initializes a new validator node
func NewNode(id string, apiAddr string, peers []string, validators []*poa.Validator) (*Node, error) {
	log.Printf("Node %s: Initializing NewNode...", id)
	var selfValidator *poa.Validator
	for _, v := range validators {
		if v.ID == id {
			selfValidator = v
			break
		}
	}
	if selfValidator == nil {
		return nil, fmt.Errorf("validator with ID %s not found in provided validator list", id)
	}

	// initialize blockchain. load from file if exists, otherwise create new.
	filepath := fmt.Sprintf("blockchain_node_%s.json", id)
	var bc *blockchain.Blockchain
	loadedBC, err := blockchain.LoadBlockchain(filepath)
	if err == nil && loadedBC.IsValidBlock() {
		bc = loadedBC
		log.Printf("Node %s: Loaded existing blockchain from file. Latest block index: %d", id, bc.GetLatestBlock().Index)
	} else {
		// Using Node 1 as the genesis creator ID for consistency across all nodes
		bc = blockchain.NewBlockchain("validator-1", GenesisTimestamp)
		log.Printf("Node %s: No valid blockchain found or error loading (%v), starting with new genesis block (ID: %s, Timestamp: %d).", id, err, bc.GetLatestBlock().ValidatorID, bc.GetLatestBlock().Timestamp)
	}

	mempool := NewMempool()
	validatorSet := poa.NewValidatorSet(validators)

	node := &Node{
		ID:            id,
		Validator:     selfValidator,
		Blockchain:    bc,
		Mempool:       mempool,
		ValidatorSet:  validatorSet,
		Peers:         peers,
		NodeAPIAddr:   apiAddr,
		stopChan:      make(chan struct{}),
		dnsStateCache: make(map[string]blockchain.DNSRecord),
	}

	node.updateDNSStateCache() // initializing DNS state cache
	log.Printf("Node %s: NewNode initialization complete.", id)
	return node, nil
}

// StartNode begins the node's API server and block mining loop.
func (n *Node) StartNode() {
	log.Printf("Node %s: Starting API server on %s", n.ID, n.NodeAPIAddr)
	go n.startAPIServer()

	log.Printf("Node %s: Starting block mining loop", n.ID)
	go n.startMiningLoop()

	// periodically sync with peers
	go n.startPeerSyncLoop()
	log.Printf("Node %s: All background services started.", n.ID)
}

// StopNode stops the node
func (n *Node) StopNode() {
	log.Printf("Node %s: Stopping...", n.ID)
	close(n.stopChan)
	// save blockchain on shutdown
	n.mu.Lock()
	defer n.mu.Unlock() // mutex is released
	err := blockchain.SaveBlockchain(n.Blockchain, fmt.Sprintf("blockchain_node_%s.json", n.ID))
	if err != nil {
		log.Printf("Node %s: Error saving blockchain on shutdown: %v", n.ID, err)
	} else {
		log.Printf("Node %s: Blockchain saved successfully on shutdown.", n.ID)
	}
	log.Printf("Node %s: Stopped.", n.ID)
}

// startMiningLoop continuously attempts to mine new blocks.
func (n *Node) startMiningLoop() {
	ticker := time.NewTicker(5 * time.Second) // attempt to mine every 5 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			n.mu.Lock()
			latestBlock := n.Blockchain.GetLatestBlock()
			nextValidatorID := n.ValidatorSet.GetNextValidatorID(latestBlock.Index)
			n.mu.Unlock()

			if nextValidatorID == n.ID {
				log.Printf("Node %s: It's my turn to propose a block (current index %d).", n.ID, latestBlock.Index)
				n.MineBlock()
			} else {
				log.Printf("Node %s: Not my turn. Next validator: %s", n.ID, nextValidatorID)
			}
		case <-n.stopChan:
			log.Printf("Node %s: Mining loop stopped.", n.ID)
			return
		}
	}
}

// MineBlock creates new block, includes pending transactions, signs it and broadcasts it.
func (n *Node) MineBlock() {
	n.mu.Lock()
	defer n.mu.Unlock()

	latestBlock := n.Blockchain.GetLatestBlock()
	newBlockIndex := latestBlock.Index + 1

	// fetching DNS records from mempool
	dnsRecords := n.Mempool.GetPendingRecords()
	if len(dnsRecords) == 0 {
		log.Printf("Node %s: No pending DNS records to include in block %d. Skipping block creation.", n.ID, newBlockIndex)
		return
	}
	log.Printf("Node %s: Preparing to mine block %d with %d records.", n.ID, newBlockIndex, len(dnsRecords))

	newBlock := blockchain.NewBlock(newBlockIndex, latestBlock.Hash, dnsRecords, n.ID)
	newBlock.Hash = newBlock.CalculateHash() // calculate hash before signing
	log.Printf("Node %s: Block %d hash calculated: %s", n.ID, newBlockIndex, newBlock.Hash)

	if err := n.Validator.SignBlock(newBlock); err != nil {
		log.Printf("Node %s: Failed to sign block %d: %v", n.ID, newBlockIndex, err)
		return
	}
	log.Printf("Node %s: Block %d signed.", n.ID, newBlockIndex)

	// adding the block to this node's chain
	n.Blockchain.AddBlock(newBlock)
	n.Mempool.Clear()       // clear mempool after including records in the block
	n.updateDNSStateCache() // update DNS state after adding block

	log.Printf("Node %s: Mined new block %d. Hash: %s, Records: %d. Chain length: %d", n.ID, newBlock.Index, newBlock.Hash, len(dnsRecords), len(n.Blockchain.Blocks))

	// broadcast the new block to peers
	n.broadcastBlock(newBlock)
}

// HandleIncomingBlock processes block received from peers.
func (n *Node) HandleIncomingBlock(block *blockchain.Block) {
	log.Printf("Node %s: Entering HandleIncomingBlock for block %d from %s", n.ID, block.Index, block.ValidatorID)
	log.Printf("Node %s: Attempting to acquire mutex in HandleIncomingBlock.", n.ID)
	n.mu.Lock()
	defer n.mu.Unlock() // mutex is released
	log.Printf("Node %s: Acquired mutex in HandleIncomingBlock.", n.ID)

	latestBlock := n.Blockchain.GetLatestBlock()

	// basic validation to check if it's the next expected block
	if block.Index != latestBlock.Index+1 {
		log.Printf("Node %s: Received out-of-order block %d from %s. Expected %d. Ignoring for now.",
			n.ID, block.Index, block.ValidatorID, latestBlock.Index+1)
		return
	}
	log.Printf("Node %s: Block %d index is correct.", n.ID, block.Index)

	// verifying previous hash
	if block.PrevHash != latestBlock.Hash {
		log.Printf("Node %s: Received block %d with invalid PrevHash. Expected %s, got %s. From %s. Ignoring.",
			n.ID, block.Index, latestBlock.Hash, block.PrevHash, block.ValidatorID)
		return
	}
	log.Printf("Node %s: Block %d PrevHash is correct.", n.ID, block.Index)

	// verifying block's own hash
	calculatedHash := block.CalculateHash()
	if block.Hash != calculatedHash {
		log.Printf("Node %s: Received block %d with invalid calculated hash. Expected %s, got %s. From %s. Ignoring.",
			n.ID, block.Index, calculatedHash, block.Hash, block.ValidatorID)
		return
	}
	log.Printf("Node %s: Block %d self-hash is correct.", n.ID, block.Index)

	// verifying validator identity and signature
	log.Printf("Node %s: Checking if validator ID '%s' is known in ValidatorSet.", n.ID, block.ValidatorID)
	validatorPublicKey := n.ValidatorSet.GetPublicKey(block.ValidatorID)
	if validatorPublicKey == nil {
		log.Printf("Node %s: Received block %d from unknown validator ID: %s. This validator is NOT in my ValidatorSet. Ignoring.", n.ID, block.Index, block.ValidatorID)
		return
	}
	log.Printf("Node %s: Validator ID '%s' is known. Verifying signature for block %d...", n.ID, block.ValidatorID, block.Index)
	if !poa.VerifyBlockSignature(block, validatorPublicKey) {
		log.Printf("Node %s: Received block %d with invalid signature from validator %s. Ignoring.", n.ID, block.Index, block.ValidatorID)
		return
	}
	log.Printf("Node %s: Block %d signature is valid.", n.ID, block.Index)

	// if all checks passed, add the block
	log.Printf("Node %s: All checks passed for block %d. Adding to blockchain.", n.ID, block.Index)
	n.Blockchain.AddBlock(block)
	log.Printf("Node %s: Block %d added to blockchain. Updating DNS cache.", n.ID, block.Index)
	n.updateDNSStateCache()
	log.Printf("Node %s: Successfully added new block %d from validator %s. Chain length: %d",
		n.ID, block.Index, block.ValidatorID, len(n.Blockchain.Blocks))
}

// broadcastBlock sends a block to all known peers.
func (n *Node) broadcastBlock(block *blockchain.Block) {
	log.Printf("Node %s: Broadcasting block %d to peers: %v", n.ID, block.Index, n.Peers)
	for _, peerAddr := range n.Peers {
		if peerAddr == n.NodeAPIAddr {
			continue // not sent to self
		}
		go func(addr string) {
			err := sendBlockToPeer(block, addr)
			if err != nil {
				log.Printf("Node %s: Failed to send block %d to peer %s: %v", n.ID, block.Index, addr, err)
			} else {
				log.Printf("Node %s: Successfully sent block %d to peer %s", n.ID, block.Index, addr)
			}
		}(peerAddr)
	}
}

// startPeerSyncLoop periodically requests the latest block from peers
func (n *Node) startPeerSyncLoop() {
	ticker := time.NewTicker(10 * time.Second) // syncs every 10 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			log.Printf("Node %s: Initiating peer sync check.", n.ID)
			n.syncWithPeers()
		case <-n.stopChan:
			log.Printf("Node %s: Peer sync loop stopped.", n.ID)
			return
		}
	}
}

// syncWithPeers attempts to fetch the latest block from peers and updates its own chain.
func (n *Node) syncWithPeers() {
	n.mu.Lock()
	currentChainLength := len(n.Blockchain.Blocks)
	currentLatestBlockIndex := n.Blockchain.GetLatestBlock().Index
	n.mu.Unlock()

	log.Printf("Node %s: My current chain length: %d, latest block index: %d", n.ID, currentChainLength, currentLatestBlockIndex)

	for _, peerAddr := range n.Peers {
		if peerAddr == n.NodeAPIAddr {
			continue
		}
		log.Printf("Node %s: Requesting latest block from peer %s...", n.ID, peerAddr)
		latestPeerBlock, err := getLatestBlockFromPeer(peerAddr)
		if err != nil {
			log.Printf("Node %s: Failed to get latest block from peer %s: %v", n.ID, peerAddr, err)
			continue
		}
		log.Printf("Node %s: Received latest block %d from peer %s.", n.ID, latestPeerBlock.Index, peerAddr)

		n.mu.Lock()
		if latestPeerBlock.Index > n.Blockchain.GetLatestBlock().Index {
			log.Printf("Node %s: Peer %s has a longer chain (index %d vs my %d). Attempting to add it.",
				n.ID, peerAddr, latestPeerBlock.Index, n.Blockchain.GetLatestBlock().Index)
			if latestPeerBlock.Index == n.Blockchain.GetLatestBlock().Index+1 {
				log.Printf("Node %s: Attempting to add missing block %d from peer %s...", n.ID, latestPeerBlock.Index, peerAddr)
				n.HandleIncomingBlock(latestPeerBlock)
			} else {
				log.Printf("Node %s: Chain too far behind peer %s (my %d vs peer %d). Manual intervention or full re-sync needed in real system.",
					n.ID, peerAddr, n.Blockchain.GetLatestBlock().Index, latestPeerBlock.Index)
			}
		} else {
			log.Printf("Node %s: Peer %s's chain (index %d) is not longer than mine (index %d). No sync needed from this peer.",
				n.ID, peerAddr, latestPeerBlock.Index, n.Blockchain.GetLatestBlock().Index)
		}
		n.mu.Unlock()
	}
}

// updateDNSStateCache rebuilds the  cache of active DNS records.
func (n *Node) updateDNSStateCache() {
	n.dnsStateCache = n.Blockchain.GetAllActiveDNSRecords()
	log.Printf("Node %s: DNS state cache updated. Active records: %d", n.ID, len(n.dnsStateCache))
}

// GetDNSRecordFromCache retrieves a DNS record from the node's current cache state
func (n *Node) GetDNSRecordFromCache(domain string) *blockchain.DNSRecord {
	n.mu.Lock()
	defer n.mu.Unlock()
	if record, ok := n.dnsStateCache[domain]; ok {
		return &record
	}
	return nil
}
