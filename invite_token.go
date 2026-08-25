package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// newInviteToken returns the plaintext token to put in the invite link, plus
// the SHA-256 digest to store in invites.token_hash. The plaintext is never
// persisted; acceptance looks the invite up by hashing the incoming token.
func newInviteToken() (token string, hash []byte, err error) {
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return "", nil, err
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	return token, hashInviteToken(token), nil
}

func hashInviteToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}
