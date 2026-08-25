// Package apikey generates and hashes workspace API keys. It is shared by the
// HTTP server and the issuing CLI so both agree on the exact format.
package apikey

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Prefix is the human-visible marker at the start of every key. "live" leaves
// room for a future "hm_test_" tier without changing the parsing.
const Prefix = "hm_live_"

// PrefixLen is how much of the key is stored in plaintext for the UI: the
// marker plus four characters — enough to tell two keys apart in a list, and
// useless for authenticating.
const PrefixLen = len(Prefix) + 4

// New returns the plaintext key to show the operator exactly once, the display
// prefix, and the SHA-256 digest to store. The plaintext is never persisted.
func New() (key, prefix string, hash []byte, err error) {
	raw := make([]byte, 24)
	if _, err = rand.Read(raw); err != nil {
		return "", "", nil, err
	}
	key = Prefix + hex.EncodeToString(raw)
	return key, key[:PrefixLen], Hash(key), nil
}

// Hash is the one-way function guarding the api_keys table. Because the stored
// value is already a digest of a high-entropy secret, lookup by equality is
// safe: there is nothing to compare in variable time.
func Hash(key string) []byte {
	sum := sha256.Sum256([]byte(key))
	return sum[:]
}

// LooksLikeKey reports whether s has the shape of one of our keys. It is a
// cheap filter for logging and error messages, never an authorisation check.
func LooksLikeKey(s string) bool {
	return strings.HasPrefix(s, Prefix) && len(s) > PrefixLen
}
