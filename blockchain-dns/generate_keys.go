package main

import (
	"blockchain-dns/poa" // IMPORTANT: Update this to your actual module path (e.g., blockchain-dns-simulation/poa)
	"fmt"
	"log"
	"os"
)

// keyFilePath generates the expected file path for a validator's key pair.
func keyFilePath(validatorID string) string {
	return fmt.Sprintf("validator_keys/%s_key.json", validatorID)
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	fmt.Println("--- Generating and Saving Validator Keys ---")

	// Ensure the validator_keys directory exists
	if err := os.MkdirAll("validator_keys", 0755); err != nil {
		log.Fatalf("Failed to create validator_keys directory: %v", err)
	}

	allValidatorIDs := []string{"validator-1", "validator-2", "validator-3"}

	for _, id := range allValidatorIDs {
		keyPath := keyFilePath(id)
		validator, err := poa.NewValidator(id) // Generate a NEW key pair
		if err != nil {
			log.Fatalf("Failed to generate key pair for %s: %v", id, err)
		}
		if err := validator.SaveKeyPair(keyPath); err != nil { // Save it to file
			log.Fatalf("Failed to save key pair for %s: %v", id, err)
		}
		fmt.Printf("Generated and saved key for %s to %s\n", id, keyPath)
	}
	fmt.Println("--- Key Generation Complete. Distribute 'validator_keys' folder to all VMs. ---")
}
