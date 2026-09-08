package inbound

import (
	"context"
	"errors"
	"io"
	"log"
	"time"

	"github.com/emersion/go-smtp"
)

// MaxMessageBytes caps what we accept. Postfix has its own limit in front of
// this; the point of a second one is that the raw message goes into a Postgres
// column, so an unbounded message is an unbounded row.
const MaxMessageBytes = 25 << 20

// Backend is the go-smtp entry point, in LMTP mode.
//
// LMTP rather than SMTP because the sender is Postfix on the same host, not
// the internet: it has already done the spam checks, TLS and queueing, and
// LMTP gives a per-recipient reply so one bad address does not fail the others.
type Backend struct{ store *Store }

func NewBackend(store *Store) *Backend { return &Backend{store: store} }

func (b *Backend) NewSession(_ *smtp.Conn) (smtp.Session, error) {
	return &session{store: b.store}, nil
}

type session struct {
	store *Store
	from  string
	// Resolved at RCPT time. Rejecting an unknown address there rather than
	// after DATA saves the sender from transmitting a message we will refuse.
	recipients []*Mailbox
}

func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	s.from = from
	return nil
}

func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	mailbox, err := s.store.MailboxByAddress(context.Background(), to)
	if errors.Is(err, ErrNoMailbox) {
		// 550 is permanent on purpose: the address does not exist and will not
		// start existing because they retried. A temporary code would have
		// them trying for days before bouncing.
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 1, 1},
			Message:      "No such user here",
		}
	}
	if err != nil {
		log.Printf("inbound: resolve %s: %v", to, err)
		// Ours, not theirs: ask them to come back rather than bouncing mail we
		// might well have accepted a minute later.
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 3, 0},
			Message:      "Temporary failure, try again later",
		}
	}

	s.recipients = append(s.recipients, mailbox)
	return nil
}

func (s *session) Data(r io.Reader) error {
	raw, err := io.ReadAll(io.LimitReader(r, MaxMessageBytes+1))
	if err != nil {
		return &smtp.SMTPError{Code: 451, Message: "Could not read message"}
	}
	if len(raw) > MaxMessageBytes {
		return &smtp.SMTPError{
			Code:         552,
			EnhancedCode: smtp.EnhancedCode{5, 3, 4},
			Message:      "Message too large",
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, mailbox := range s.recipients {
		_, err := s.store.Deliver(ctx, DeliverParams{
			MailboxID:    mailbox.ID,
			EnvelopeFrom: s.from,
			EnvelopeTo:   mailbox.Address,
			Raw:          raw,
		})
		switch {
		case errors.Is(err, ErrDuplicate):
			// Already have it. Accepting is the right answer — the sender is
			// retrying because our earlier acknowledgement went missing, and
			// refusing would make them keep going.
			log.Printf("inbound: duplicate for %s, accepting", mailbox.Address)
		case err != nil:
			log.Printf("inbound: deliver to %s: %v", mailbox.Address, err)
			return &smtp.SMTPError{
				Code:         451,
				EnhancedCode: smtp.EnhancedCode{4, 3, 0},
				Message:      "Could not store message, try again later",
			}
		default:
			log.Printf("inbound: delivered to %s (%d bytes)", mailbox.Address, len(raw))
		}
	}
	return nil
}

func (s *session) Reset() { s.from = ""; s.recipients = nil }

func (s *session) Logout() error { return nil }

// NewServer builds the LMTP listener.
func NewServer(store *Store, addr string) *smtp.Server {
	srv := smtp.NewServer(NewBackend(store))
	srv.LMTP = true
	srv.Addr = addr
	srv.Domain = "heromail"
	srv.ReadTimeout = 60 * time.Second
	srv.WriteTimeout = 60 * time.Second
	srv.MaxMessageBytes = MaxMessageBytes
	srv.MaxRecipients = 50
	// No AUTH and no TLS: this listens on loopback and speaks only to the
	// Postfix beside it. Requiring credentials between two processes on one
	// host would be ceremony, not security — the protection is the bind
	// address, which is why it must never become 0.0.0.0.
	srv.AllowInsecureAuth = false
	return srv
}
