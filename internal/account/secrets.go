package account

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

// bcryptCost is the work factor. The default (10) is the usual starting point;
// raise it as hardware improves — existing hashes keep their own cost, so a
// change only affects passwords set afterwards.
const bcryptCost = bcrypt.DefaultCost

// Password rules. Length beats composition requirements: forcing a symbol
// produces "Password1!" far more often than it produces entropy.
const (
	minPasswordLen = 10
	// bcrypt silently ignores everything past 72 bytes, so reject longer
	// passwords instead of pretending to store them.
	maxPasswordBytes = 72
)

var ErrWeakPassword = errors.New("weak password")

// hashPassword validates and hashes. It returns ErrWeakPassword for anything
// the caller can fix by choosing a different password.
func hashPassword(plain string) ([]byte, error) {
	if utf8.RuneCountInString(plain) < minPasswordLen {
		return nil, fmt.Errorf("%w: must be at least %d characters", ErrWeakPassword, minPasswordLen)
	}
	if len(plain) > maxPasswordBytes {
		return nil, fmt.Errorf("%w: must be at most %d bytes", ErrWeakPassword, maxPasswordBytes)
	}
	return bcrypt.GenerateFromPassword([]byte(plain), bcryptCost)
}

// verifyPassword reports whether plain matches the stored hash.
func verifyPassword(hash []byte, plain string) bool {
	return bcrypt.CompareHashAndPassword(hash, []byte(plain)) == nil
}

// dummyHash is compared against when no user exists, so that a request for an
// unknown address costs the same as one for a known address. Without it,
// response time alone tells an attacker which emails are registered.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("heromail-timing-equaliser"), bcryptCost)

func burnPasswordTime() { bcrypt.CompareHashAndPassword(dummyHash, []byte("x")) }

// newToken returns a URL-safe secret and its SHA-256 digest. Sessions and
// emailed links both use it: the plaintext travels, only the digest is stored.
func newToken() (token string, hash []byte, err error) {
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return "", nil, err
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	return token, hashToken(token), nil
}

func hashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}
