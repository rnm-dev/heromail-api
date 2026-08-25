package secrets

import (
	"bytes"
	"strings"
	"testing"
)

func testSealer(t *testing.T) *Sealer {
	t.Helper()
	s, err := New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestSealOpenRoundTrip(t *testing.T) {
	s := testSealer(t)
	plaintext := []byte("a DKIM private key, pretend this is DER")

	sealed, err := s.Seal(plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if strings.Contains(sealed, "DKIM private key") {
		t.Fatal("the ciphertext contains the plaintext")
	}

	opened, err := s.Open(sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Errorf("round trip = %q, want %q", opened, plaintext)
	}
}

func TestSealUsesAFreshNonce(t *testing.T) {
	s := testSealer(t)

	first, _ := s.Seal([]byte("same input"))
	second, _ := s.Seal([]byte("same input"))
	if first == second {
		t.Fatal("sealing twice produced identical ciphertext, so the nonce is being reused")
	}
}

func TestOpenRejectsTamperingAndWrongKey(t *testing.T) {
	s := testSealer(t)
	sealed, _ := s.Seal([]byte("signing material"))

	// Flip a character in the middle of the ciphertext.
	body := []byte(sealed)
	mid := len(body) / 2
	if body[mid] == 'A' {
		body[mid] = 'B'
	} else {
		body[mid] = 'A'
	}
	if _, err := s.Open(string(body)); err == nil {
		t.Error("a tampered ciphertext opened; the authentication tag is not being checked")
	}

	other, _ := New(bytes.Repeat([]byte{9}, 32))
	if _, err := other.Open(sealed); err == nil {
		t.Error("a different key opened the ciphertext")
	}

	if _, err := s.Open("not base64 at all!!"); err == nil {
		t.Error("garbage input was accepted")
	}
	if _, err := s.Open(""); err == nil {
		t.Error("an empty ciphertext was accepted")
	}
}

func TestNewRejectsWrongKeyLength(t *testing.T) {
	for _, size := range []int{0, 16, 31, 33} {
		if _, err := New(bytes.Repeat([]byte{1}, size)); err == nil {
			t.Errorf("a %d-byte key was accepted; AES-256 needs exactly 32", size)
		}
	}
}
