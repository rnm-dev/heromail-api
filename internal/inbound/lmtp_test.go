package inbound

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These drive a real LMTP conversation against a real database, because the
// parts most likely to be wrong are the protocol replies and the SQL — neither
// of which a fake would exercise.

type harness struct {
	store   *Store
	pool    *pgxpool.Pool
	addr    string
	mailbox *Mailbox
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL is not set; skipping inbound tests")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	// A verified domain under a throwaway workspace: MailboxByAddress refuses
	// unverified domains, so the fixture has to satisfy that too.
	suffix := time.Now().UnixNano()
	slug := fmt.Sprintf("inb-%d", suffix)
	domain := fmt.Sprintf("inb-%d.test", suffix)

	var workspaceID, domainID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO workspaces (slug, name) VALUES ($1, 'Inbound Test') RETURNING id`,
		slug).Scan(&workspaceID); err != nil {
		t.Fatalf("workspace: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id = $1`, workspaceID)
	})
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (workspace_id, domain, verification_token, verified_at)
		 VALUES ($1, $2, 'tok', now()) RETURNING id`,
		workspaceID, domain).Scan(&domainID); err != nil {
		t.Fatalf("domain: %v", err)
	}

	store := NewStore(pool)
	mailbox, err := store.CreateMailbox(ctx, domainID, "sales", "Sales")
	if err != nil {
		t.Fatalf("mailbox: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := NewServer(store, ln.Addr().String())
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	return &harness{store: store, pool: pool, addr: ln.Addr().String(), mailbox: mailbox}
}

// deliver runs one LMTP conversation by hand.
//
// go-smtp's client speaks SMTP (EHLO) and our server answers LMTP (LHLO), so
// the exchange is written out directly. That is a feature for a test: it
// checks the actual reply codes on the wire, which is the part Postfix will
// depend on.
func (h *harness) deliver(t *testing.T, to, raw string) error {
	t.Helper()

	conn, err := net.DialTimeout("tcp", h.addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	r := bufio.NewReader(conn)
	read := func() (int, string) {
		t.Helper()
		var last string
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			last = strings.TrimRight(line, "\r\n")
			// Multiline replies use "250-"; the final one uses "250 ".
			if len(last) < 4 || last[3] != '-' {
				break
			}
		}
		code := 0
		fmt.Sscanf(last, "%d", &code)
		return code, last
	}
	send := func(format string, args ...any) (int, string) {
		t.Helper()
		fmt.Fprintf(conn, format+"\r\n", args...)
		return read()
	}

	read() // banner

	if code, line := send("LHLO test"); code != 250 {
		t.Fatalf("LHLO: %s", line)
	}
	if code, line := send("MAIL FROM:<sender@acme.test>"); code != 250 {
		t.Fatalf("MAIL FROM: %s", line)
	}
	if code, line := send("RCPT TO:<%s>", to); code != 250 {
		return &smtp.SMTPError{Code: code, Message: line}
	}
	if code, line := send("DATA"); code != 354 {
		return &smtp.SMTPError{Code: code, Message: line}
	}
	fmt.Fprint(conn, raw)
	if code, line := send("."); code != 250 {
		return &smtp.SMTPError{Code: code, Message: line}
	}
	return nil
}

const sampleMessage = "From: Viktor <viktor@acme.test>\r\n" +
	"Subject: Hello\r\n" +
	"Message-ID: <m1@acme.test>\r\n" +
	"Content-Type: text/plain\r\n\r\n" +
	"body text\r\n"

func TestDeliverStoresAMessage(t *testing.T) {
	h := newHarness(t)

	if err := h.deliver(t, h.mailbox.Address, sampleMessage); err != nil {
		t.Fatalf("deliver: %v", err)
	}

	msgs, err := h.store.ListMessages(context.Background(), h.mailbox.ID, 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("stored %d messages, want 1", len(msgs))
	}
	m := msgs[0]
	if m.Subject != "Hello" {
		t.Errorf("subject = %q", m.Subject)
	}
	if m.FromAddr == nil || *m.FromAddr != "viktor@acme.test" {
		t.Errorf("from = %v", m.FromAddr)
	}
	if m.EnvelopeFrom != "sender@acme.test" {
		t.Errorf("envelope from = %q — it must be kept apart from the header", m.EnvelopeFrom)
	}
	if m.Read() {
		t.Error("a freshly delivered message should be unread")
	}
	if m.SizeBytes == 0 {
		t.Error("size was not recorded")
	}
}

// An address nobody claimed must be refused permanently. A temporary code
// would have the sender retrying for days before finally bouncing.
func TestUnknownAddressIsRejectedPermanently(t *testing.T) {
	h := newHarness(t)

	err := h.deliver(t, "nobody@"+strings.SplitN(h.mailbox.Address, "@", 2)[1], sampleMessage)
	if err == nil {
		t.Fatal("an unknown address was accepted")
	}
	var smtpErr *smtp.SMTPError
	if !errorAs(err, &smtpErr) {
		t.Fatalf("error was %T (%v), want an SMTPError", err, err)
	}
	if smtpErr.Code != 550 {
		t.Errorf("code = %d, want 550 (permanent)", smtpErr.Code)
	}
}

// A domain nobody proved they own must not receive mail here, or pointing an
// MX at us would be enough to intercept somebody else's.
func TestUnverifiedDomainIsRejected(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	var domainID string
	name := fmt.Sprintf("unverified-%d.test", time.Now().UnixNano())
	var workspaceID string
	h.pool.QueryRow(ctx, `SELECT d.workspace_id FROM domains d JOIN mailboxes m ON m.domain_id = d.id
		WHERE m.id = $1`, h.mailbox.ID).Scan(&workspaceID)
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO domains (workspace_id, domain, verification_token) VALUES ($1, $2, 'tok')
		 RETURNING id`, workspaceID, name).Scan(&domainID); err != nil {
		t.Fatalf("domain: %v", err)
	}
	if _, err := h.store.CreateMailbox(ctx, domainID, "sales", ""); err != nil {
		t.Fatalf("mailbox: %v", err)
	}

	if err := h.deliver(t, "sales@"+name, sampleMessage); err == nil {
		t.Fatal("mail was accepted for an unverified domain")
	}
}

// A sender whose acknowledgement went missing retries the same message. The
// right answer is to accept it and store it once, not to bounce it.
func TestRetryOfTheSameMessageIsAcceptedOnce(t *testing.T) {
	h := newHarness(t)

	for i := 0; i < 2; i++ {
		if err := h.deliver(t, h.mailbox.Address, sampleMessage); err != nil {
			t.Fatalf("delivery %d: %v", i+1, err)
		}
	}

	msgs, _ := h.store.ListMessages(context.Background(), h.mailbox.ID, 10)
	if len(msgs) != 1 {
		t.Errorf("stored %d copies, want 1", len(msgs))
	}
}

// Scoping: another workspace must not be able to read this mailbox's mail.
func TestMessagesAreScopedToTheOwningWorkspace(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	if err := h.deliver(t, h.mailbox.Address, sampleMessage); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	msgs, _ := h.store.ListMessages(ctx, h.mailbox.ID, 1)

	var otherWorkspace string
	h.pool.QueryRow(ctx, `INSERT INTO workspaces (slug, name) VALUES ($1, 'Other') RETURNING id`,
		fmt.Sprintf("other-%d", time.Now().UnixNano())).Scan(&otherWorkspace)
	t.Cleanup(func() {
		h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id = $1`, otherWorkspace)
	})

	if _, err := h.store.MessageByID(ctx, otherWorkspace, msgs[0].ID); err == nil {
		t.Error("another workspace read this message")
	}
	if _, err := h.store.MessageByID(ctx, h.mailbox.WorkspaceID, msgs[0].ID); err != nil {
		t.Errorf("the owning workspace could not read its own message: %v", err)
	}
}

func errorAs(err error, target **smtp.SMTPError) bool {
	if e, ok := err.(*smtp.SMTPError); ok {
		*target = e
		return true
	}
	return false
}
