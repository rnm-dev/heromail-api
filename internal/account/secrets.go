package account

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
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

// otpDigits is 6 because that is what people expect to be asked for and what
// authenticator apps and SMS have trained everyone to type. The entropy that
// costs (~20 bits) is bought back by the attempt cap, not by more digits.
const otpDigits = 6

// newOTP returns a zero-padded numeric code.
//
// rand.Int over an exact power-of-ten bound rather than reading bytes and
// taking a remainder: the modulo version skews towards low codes, which is
// exactly the part of the keyspace a guesser would try first.
func newOTP() (string, error) {
	max := big.NewInt(1)
	for i := 0; i < otpDigits; i++ {
		max.Mul(max, big.NewInt(10))
	}
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", otpDigits, n), nil
}

// hashOTP digests the code together with the user it belongs to.
//
// The user id is in the hash because user_tokens.token_hash is globally
// unique: with only a million possible codes, two users would eventually be
// issued the same one and the second insert would fail. Scoping the digest
// keeps that index meaningful and means a stolen digest cannot be replayed
// against a different account.
func hashOTP(userID, code string) []byte {
	sum := sha256.Sum256([]byte(userID + ":" + strings.TrimSpace(code)))
	return sum[:]
}
