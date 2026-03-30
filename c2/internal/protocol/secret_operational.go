//go:build operational

package protocol

import (
	"log"
	"os"
)

// GetSecret reads the encryption key from the VOIDLINK_SECRET environment variable.
// Fatally exits if the variable is empty or unset — operational mode requires explicit key configuration.
func GetSecret() string {
	secret := os.Getenv("VOIDLINK_SECRET")
	if secret == "" {
		log.Fatal("VOIDLINK_SECRET env var required in operational mode")
	}
	return secret
}
