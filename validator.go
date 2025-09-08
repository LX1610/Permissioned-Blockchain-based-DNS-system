package poa

import (
	"blockchain-dns/blockchain"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"sync"
)

// Validator struct for public/privae key
type Validator struct {
	ID         string
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

// KeyPairJSON represents the private and public key in a serializable format
type KeyPairJSON struct {
	ID         string `json:"id"`
	PrivateKey []byte `json:"private_key"`
	PublicKey  []byte `json:"public_key"`
}

// NewValidator generates new ECDSA key pair for a validator
func NewValidator(id string) (*Validator, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key for %s: %w", id, err)
	}
	log.Printf("Validator %s: Generated new key pair.", id)
	return &Validator{
		ID:         id,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// SaveKeyPair saves a validator's key pair to a file.
func (v *Validator) SaveKeyPair(filepath string) error {
	privateKeyBytes, err := x509.MarshalECPrivateKey(v.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key for %s: %w", v.ID, err)
	}
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(v.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key for %s: %w", v.ID, err)
	}

	keyPair := KeyPairJSON{
		ID:         v.ID,
		PrivateKey: privateKeyBytes,
		PublicKey:  publicKeyBytes,
	}

	data, err := json.MarshalIndent(keyPair, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal key pair JSON for %s: %w", v.ID, err)
	}

	err = os.WriteFile(filepath, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write key pair file for %s: %w", v.ID, err)
	}
	log.Printf("Validator %s: Key pair saved to %s", v.ID, filepath)
	return nil
}

// LoadKeyPair loads a validator's key pair from a file
func LoadKeyPair(filepath string) (*Validator, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key pair file %s: %w", filepath, err)
	}

	var keyPair KeyPairJSON
	if err := json.Unmarshal(data, &keyPair); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key pair JSON from %s: %w", filepath, err)
	}

	privateKey, err := x509.ParseECPrivateKey(keyPair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key from %s: %w", filepath, err)
	}
	publicKey, err := x509.ParsePKIXPublicKey(keyPair.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key from %s: %w", filepath, err)
	}
	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("loaded public key from %s is not an ECDSA public key", filepath)
	}

	log.Printf("Validator %s: Key pair loaded from %s", keyPair.ID, filepath)
	return &Validator{
		ID:         keyPair.ID,
		PrivateKey: privateKey,
		PublicKey:  ecdsaPublicKey,
	}, nil
}

// SignBlock signs block with the validator's private key.
func (v *Validator) SignBlock(block *blockchain.Block) error {
	blockHashBytes, err := hex.DecodeString(block.Hash)
	if err != nil {
		return fmt.Errorf("failed to decode block hash for signing: %w", err)
	}

	r, s, err := ecdsa.Sign(rand.Reader, v.PrivateKey, blockHashBytes)
	if err != nil {
		return fmt.Errorf("failed to sign block: %w", err)
	}

	// stores R and S as a concatenated byte slice
	signature := append(r.Bytes(), s.Bytes()...)
	block.ValidatorSignature = signature
	log.Printf("Validator %s: Block %d signed. Signature length: %d", v.ID, block.Index, len(signature))
	return nil
}

// VerifyBlockSignature verifies the signature of a block using that validator's public key
func VerifyBlockSignature(block *blockchain.Block, publicKey *ecdsa.PublicKey) bool {
	if publicKey == nil || block.ValidatorSignature == nil || len(block.ValidatorSignature) == 0 {
		log.Printf("Verification failed: Public key or signature missing for block %d by validator %s", block.Index, block.ValidatorID)
		return false
	}

	// the hash that was signed is the block's content hash
	blockHashBytes, err := hex.DecodeString(block.Hash)
	if err != nil {
		log.Printf("Verification failed: Failed to decode block hash for verification: %v", err)
		return false
	}

	// Reconstruct R and S (32-byte) from the concatenated signature
	rBytesLen := 32
	sBytesLen := 32

	if len(block.ValidatorSignature) != rBytesLen+sBytesLen {
		log.Printf("Verification failed: Invalid signature length for block %d by validator %s. Expected %d, got %d",
			block.Index, block.ValidatorID, rBytesLen+sBytesLen, len(block.ValidatorSignature))
		return false
	}

	r := new(big.Int).SetBytes(block.ValidatorSignature[:rBytesLen])
	s := new(big.Int).SetBytes(block.ValidatorSignature[rBytesLen:])

	// verifying signature
	isValid := ecdsa.Verify(publicKey, blockHashBytes, r, s)
	if !isValid {
		log.Printf("Verification failed: Signature mismatch for block %d by validator %s", block.Index, block.ValidatorID)
		log.Printf("  Signer ID: %s", block.ValidatorID)
		log.Printf("  Block Hash: %s", block.Hash)
		log.Printf("  Public Key (X): %s", hex.EncodeToString(publicKey.X.Bytes()))
		log.Printf("  Public Key (Y): %s", hex.EncodeToString(publicKey.Y.Bytes()))
		log.Printf("  Signature (R): %s", hex.EncodeToString(r.Bytes()))
		log.Printf("  Signature (S): %s", hex.EncodeToString(s.Bytes()))
	}
	return isValid
}

// ValidatorSet manages the set of authorized validators(storing public keys)
type ValidatorSet struct {
	mu         sync.RWMutex
	Validators map[string]*Validator
	Order      []string
}

// NewValidatorSet creates a new ValidatorSet
func NewValidatorSet(validators []*Validator) *ValidatorSet {
	vs := &ValidatorSet{
		Validators: make(map[string]*Validator),
		Order:      make([]string, len(validators)),
	}
	for i, v := range validators {
		vs.Validators[v.ID] = v
		vs.Order[i] = v.ID
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(v.PublicKey)
		if err != nil {
			log.Printf("ValidatorSet: Error marshaling public key for %s: %v", v.ID, err)
		} else {
			log.Printf("ValidatorSet: Added validator %s with Public Key Hash: %s", v.ID, sha256Hash(pubKeyBytes))
		}
	}
	log.Printf("ValidatorSet: Initialized with validators: %v", vs.Order)
	return vs
}

// GetPublicKey retrieves a validator's public key by ID
func (vs *ValidatorSet) GetPublicKey(validatorID string) *ecdsa.PublicKey {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	if v, ok := vs.Validators[validatorID]; ok {
		return v.PublicKey
	}
	log.Printf("ValidatorSet: Public key not found for validator ID: %s", validatorID)
	return nil
}

// GetNextValidatorID determines whose turn it is to propose the next block
func (vs *ValidatorSet) GetNextValidatorID(latestBlockIndex int) string {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	if len(vs.Order) == 0 {
		return ""
	}
	nextIndex := (latestBlockIndex + 1) % len(vs.Order)
	return vs.Order[nextIndex]
}

// sha256Hash computes the sha256 hash of the bte slice.
func sha256Hash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
