// Package provider abstracts the transport that actually delivers mail, so the
// rest of the backend never talks to SMTP (or any future HTTP provider API)
// directly.
package provider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Message is one outbound message, in the shape the sending code thinks in.
// It mirrors the emails table without depending on it: a provider must not
// need a database row to do its job.
type Message struct {
	Cc       []string
	Bcc      []string
	From     string
	To       []string
	Subject  string
	HTMLBody string
	TextBody string

	// Headers are extra headers to set, e.g. Reply-To or List-Unsubscribe.
	// Implementations may reject headers they generate themselves.
	Headers map[string]string

	// Attachments are files to attach. Content is read once during Send and
	// not closed by the implementation — the caller owns its lifetime.
	Attachments []Attachment

	// DKIM signs the message when set. Left nil, the message goes out
	// unsigned — the caller decides that (typically: the From domain has no
	// verified key yet), not the transport.
	DKIM *DKIM
}

// DKIM is what is needed to sign a message: the domain and selector that go
// into the signature's d= and s= tags, and the private key that produces it.
// PrivateKeyDER is PKCS#8, matching what internal/maildomain generates and
// internal/secrets decrypts.
type DKIM struct {
	Domain        string
	Selector      string
	PrivateKeyDER []byte
}

// Attachment is one file to attach to a Message. It carries a reader rather
// than bytes so a large file does not have to sit fully in memory between
// being fetched from storage and being written to the wire.
type Attachment struct {
	Filename    string
	ContentType string
	Content     io.Reader
}

// Sender hands a message to a transport and returns the identifier under which
// it can later be correlated with delivery events.
//
// The returned providerMessageID is stored in emails.provider_message_id.
type Sender interface {
	Send(ctx context.Context, msg Message) (providerMessageID string, err error)
}

// ErrInvalidMessage is returned when a message cannot be sent as constructed.
// It wraps the specific reason, so callers can distinguish "caller's fault"
// from a transport failure and skip pointless retries.
var ErrInvalidMessage = errors.New("invalid message")

// Validate mirrors the CHECK constraints on the emails table, so a message
// rejected by the database is also rejected here, and vice versa.
func (m Message) Validate() error {
	if strings.TrimSpace(m.From) == "" {
		return fmt.Errorf("%w: From is empty", ErrInvalidMessage)
	}
	if len(m.To) == 0 {
		return fmt.Errorf("%w: no recipients", ErrInvalidMessage)
	}
	for i, to := range m.To {
		if strings.TrimSpace(to) == "" {
			return fmt.Errorf("%w: recipient %d is empty", ErrInvalidMessage, i)
		}
	}
	if strings.TrimSpace(m.HTMLBody) == "" && strings.TrimSpace(m.TextBody) == "" {
		return fmt.Errorf("%w: both bodies are empty", ErrInvalidMessage)
	}
	return nil
}
