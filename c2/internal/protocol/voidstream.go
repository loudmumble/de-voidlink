package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// XORKey is the XOR encoding key for config blobs.
	XORKey byte = 0xAA

	// NonceSize is the AES-GCM nonce size in bytes.
	NonceSize = 12

	// LengthSize is the message length prefix size in bytes.
	LengthSize = 4

	// TagSize is the AES-GCM authentication tag size in bytes.
	TagSize = 16
)

// DeriveKey derives an AES-256 key from the shared secret using SHA-256.
// The secret is obtained via GetSecret(), which is build-tag switched between
// a hardcoded test key (benign) and an environment variable (operational).
func DeriveKey() []byte {
	h := sha256.Sum256([]byte(GetSecret()))
	return h[:]
}

// newGCM creates a new AES-256-GCM AEAD cipher from a key.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	return gcm, nil
}

// Encrypt encrypts plaintext using AES-256-GCM with the derived key.
// Message format: [4-byte length][12-byte nonce][encrypted payload][16-byte GCM tag]
func Encrypt(plaintext []byte) ([]byte, error) {
	key := DeriveKey()
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce generation: %w", err)
	}

	// Seal appends ciphertext + GCM tag
	sealed := gcm.Seal(nil, nonce, plaintext, nil)

	// Wire format: [4-byte total length][12-byte nonce][sealed data]
	totalLen := NonceSize + len(sealed)
	msg := make([]byte, LengthSize+totalLen)
	binary.BigEndian.PutUint32(msg[0:LengthSize], uint32(totalLen))
	copy(msg[LengthSize:LengthSize+NonceSize], nonce)
	copy(msg[LengthSize+NonceSize:], sealed)

	return msg, nil
}
