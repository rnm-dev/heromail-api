// Package inbound receives mail. Postfix accepts a message on port 25 and
// hands it here over LMTP; this package decides whether we have somewhere to
// put it, parses it, and stores it.
//
// It is deliberately separate from internal/email, which is outbound. The two
// share a domain and nothing else: outbound is a queue with retries and
// reputation to protect, inbound is an accept-or-reject decision made while
// the sending server waits.
package inbound

import (
	"errors"
	"time"
)

// ErrNoMailbox means nothing here accepts mail for that address. The LMTP
// layer turns it into a permanent rejection, so the sender gets a bounce
// rather than retrying for days against an address that will never exist.
var ErrNoMailbox = errors.New("no mailbox for this address")

// ErrDuplicate means this message is already stored. Not an error to the
// sender: a retry after a timeout is normal, and the correct answer is to
// accept it again rather than make them keep trying.
var ErrDuplicate = errors.New("message already delivered")

// Mailbox is an address we accept mail for.
type Mailbox struct {
	OwnerUserID *string   `json:"owner_user_id,omitempty"`
	ID          string    `json:"id"`
	DomainID    string    `json:"domain_id"`
	WorkspaceID string    `json:"workspace_id"`
	Address     string    `json:"address"`
	Name        *string   `json:"name,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Message is one received message.
//
// Raw is omitted from JSON: the list and detail views are built from the
// parsed fields, and shipping the whole source to a browser that only wanted a
// subject line would be wasteful.
type Message struct {
	ID        string `json:"id"`
	MailboxID string `json:"mailbox_id"`

	EnvelopeFrom string `json:"envelope_from"`
	EnvelopeTo   string `json:"envelope_to"`

	MessageID *string    `json:"message_id,omitempty"`
	FromAddr  *string    `json:"from"`
	FromName  *string    `json:"from_name,omitempty"`
	Subject   string     `json:"subject"`
	SentAt    *time.Time `json:"sent_at,omitempty"`

	TextBody *string `json:"text,omitempty"`
	HTMLBody *string `json:"html,omitempty"`

	Raw       []byte `json:"-"`
	SizeBytes int    `json:"size_bytes"`

	SPFPass  *bool `json:"spf_pass,omitempty"`
	DKIMPass *bool `json:"dkim_pass,omitempty"`

	ReadAt     *time.Time `json:"read_at,omitempty"`
	ReceivedAt time.Time  `json:"received_at"`
}

func (m Message) Read() bool { return m.ReadAt != nil }
