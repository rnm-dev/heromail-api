// Package secrets encrypts values that must survive in the database but must
// not be readable from a dump — today, DKIM private keys.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
)

// KeyEnvVar holds a base64-encoded 32-byte key. It is deliberately required
// rather than defaulted: a process that silently invents its own key would
// encrypt data nothing else can ever read.
const KeyEnvVar = "SECRET_KEY"

var ErrNoKey = errors.New("no encryption key configured")

// Sealer performs authenticated encryption. AES-256-GCM: the tag means a
// tampered ciphertext fails to open rather than decrypting to garbage.
type Sealer struct {
	aead cipher.AEAD
}

func New(key []byte) (*Sealer, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%s must decode to 32 bytes, got %d", KeyEnvVar, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

// NewFromEnv reads the key from the environment.
func NewFromEnv() (*Sealer, error) {
	raw := os.Getenv(KeyEnvVar)
	if raw == "" {
		return nil, fmt.Errorf("%w: set %s to a base64-encoded 32-byte key "+
			"(openssl rand -base64 32)", ErrNoKey, KeyEnvVar)
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%s is not valid base64: %w", KeyEnvVar, err)
	}
	return New(key)
}

// Seal returns base64(nonce || ciphertext || tag). The nonce is random per
// call and stored alongside, which is what makes reusing the key safe.
func (s *Sealer) Seal(plaintext []byte) (string, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := s.aead.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Open reverses Seal.
func (s *Sealer) Open(encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("ciphertext is not valid base64: %w", err)
	}
	if len(raw) < s.aead.NonceSize() {
		return nil, errors.New("ciphertext is too short to contain a nonce")
	}
	nonce, body := raw[:s.aead.NonceSize()], raw[s.aead.NonceSize():]

	plaintext, err := s.aead.Open(nil, nonce, body, nil)
	if err != nil {
		// Either the key is wrong or the data was altered; both are fatal for
		// the caller and neither should be papered over.
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}
