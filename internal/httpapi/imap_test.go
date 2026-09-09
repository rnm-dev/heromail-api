package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/rnm/heromail/backend/internal/imapservice"
	"github.com/rnm/heromail/backend/internal/inbound"
	"io"
	"math/big"
	"net"
	"slices"
	"testing"
	"time"
)

func TestIMAPPrivateMailboxRoundTrip(t *testing.T) {
	h := newHarness(t)
	ctx := t.Context()
	token, userID, _ := h.registerUser("imap-user")
	ws := h.workspaceFor(token, "imap-test")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	domain := h.verifiedDomainFor(t, ws)
	store := inbound.NewStore(h.pool)
	box, err := store.CreateMailbox(ctx, mustDomainID(t, h, domain), "reader", "Reader", &userID)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: Alice <alice@example.test>\r\nTo: reader@" + domain + "\r\nSubject: IMAP hello\r\nMessage-ID: <imap-test@example.test>\r\n\r\nHello from saved inbound\r\n")
	msg, err := store.Deliver(ctx, inbound.DeliverParams{MailboxID: box.ID, EnvelopeFrom: "alice@example.test", EnvelopeTo: box.Address, Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	parsed, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := imapservice.Server(imapservice.New(h.pool, nil), "", "", "")
	srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	go srv.Serve(tls.NewListener(listener, srv.TLSConfig))
	t.Cleanup(func() { srv.Close() })
	connect := func() *client.Client {
		c, err := client.DialTLS(listener.Addr().String(), &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12})
		if err != nil {
			t.Fatal(err)
		}
		c.Timeout = 5 * time.Second
		t.Cleanup(func() { c.Terminate() })
		return c
	}
	bad := connect()
	if err := bad.Login(box.Address, "wrong-password"); err == nil {
		t.Fatal("wrong password accepted")
	}
	bad.Logout()
	c := connect()
	if err := c.Login(box.Address, "correct-horse-battery"); err != nil {
		t.Fatal(err)
	}
	status, err := c.Select("INBOX", true)
	if err != nil || status.Messages != 1 {
		t.Fatalf("select: %+v %v", status, err)
	}
	validity := status.UidValidity
	set := new(imap.SeqSet)
	set.AddNum(1)
	fetch := func(c *client.Client, peek bool) (*imap.Message, []byte) {
		section := &imap.BodySectionName{Peek: peek}
		ch := make(chan *imap.Message, 1)
		if err := c.Fetch(set, []imap.FetchItem{imap.FetchUid, imap.FetchFlags, section.FetchItem()}, ch); err != nil {
			t.Fatal(err)
		}
		m := <-ch
		if m == nil {
			t.Fatal("missing message")
		}
		b, err := io.ReadAll(m.GetBody(section))
		if err != nil {
			t.Fatal(err)
		}
		return m, b
	}
	first, body := fetch(c, false)
	if !bytes.Equal(body, raw) {
		t.Fatalf("raw changed: %q", body)
	}
	stored, _ := store.MessageByID(ctx, ws, msg.ID)
	if stored.ReadAt != nil {
		t.Fatal("EXAMINE changed seen flag")
	}
	if _, err = c.Select("INBOX", false); err != nil {
		t.Fatal(err)
	}
	fetch(c, false)
	stored, _ = store.MessageByID(ctx, ws, msg.ID)
	if stored.ReadAt == nil {
		t.Fatal("FETCH did not mark read")
	}
	if err = c.Store(set, imap.RemoveFlags, []interface{}{imap.SeenFlag}, nil); err != nil {
		t.Fatal(err)
	}
	stored, _ = store.MessageByID(ctx, ws, msg.ID)
	if stored.ReadAt != nil {
		t.Fatal("STORE did not clear seen")
	}
	if err = c.Create("Archive"); err != nil {
		t.Fatal(err)
	}
	if err = c.Copy(set, "Archive"); err != nil {
		t.Fatal(err)
	}
	if err = c.Append("INBOX", []string{imap.SeenFlag}, time.Now(), bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	status, err = c.Select("INBOX", false)
	if err != nil || status.Messages != 2 || status.UidValidity != validity || status.UidNext <= first.Uid {
		t.Fatalf("UID stability: %+v %v", status, err)
	}
	criteria := imap.NewSearchCriteria()
	criteria.Body = []string{"saved inbound"}
	ids, err := c.Search(criteria)
	if err != nil || len(ids) != 2 {
		t.Fatalf("search: %v %v", ids, err)
	}
	if err = c.Store(set, imap.AddFlags, []interface{}{imap.DeletedFlag}, nil); err != nil {
		t.Fatal(err)
	}
	if err = c.Expunge(nil); err != nil {
		t.Fatal(err)
	}
	status, err = c.Select("Archive", false)
	if err != nil || status.Messages != 1 {
		t.Fatalf("copy: %+v %v", status, err)
	}
	copied, _ := fetch(c, true)
	if copied.Uid == first.Uid || slices.Contains(copied.Flags, imap.DeletedFlag) {
		t.Fatal("copy retained UID or deleted flag")
	}
	// A second client sees arrivals and flag changes through NOOP and IDLE.
	watcher := connect()
	if err = watcher.Login(box.Address, "correct-horse-battery"); err != nil {
		t.Fatal(err)
	}
	if _, err = watcher.Select("INBOX", false); err != nil {
		t.Fatal(err)
	}
	if err = c.Append("INBOX", nil, time.Now(), bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	if err = watcher.Noop(); err != nil {
		t.Fatal(err)
	}
	if watcher.Mailbox().Messages != 2 {
		t.Fatalf("NOOP did not report arrival: %+v", watcher.Mailbox())
	}
	stopIdle := make(chan struct{})
	idleDone := make(chan error, 1)
	updates := make(chan client.Update, 20)
	watcher.Updates = updates
	go func() { idleDone <- watcher.Idle(stopIdle, nil) }()
	if err = c.Append("INBOX", nil, time.Now(), bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	timeout := time.After(5 * time.Second)
	waiting := true
	for waiting {
		select {
		case update := <-updates:
			if u, ok := update.(*client.MailboxUpdate); ok && u.Mailbox.Messages == 3 {
				waiting = false
			}
		case <-timeout:
			t.Fatal("IDLE did not report arrival")
		}
	}
	close(stopIdle)
	if err = <-idleDone; err != nil {
		t.Fatal(err)
	}
	if err = watcher.Move(set, "Archive"); err != nil {
		t.Fatal(err)
	}
	if watcher.Mailbox().Messages != 2 {
		t.Fatalf("MOVE did not expunge source: %+v", watcher.Mailbox())
	}
	status, err = watcher.Status("Archive", []imap.StatusItem{imap.StatusMessages})
	if err != nil || status.Messages != 2 {
		t.Fatalf("MOVE destination: %+v %v", status, err)
	}
	// Reassignment revokes existing authenticated connections.

	otherToken, otherID, _ := h.registerUser("imap-other")
	_ = otherToken
	if _, err = h.pool.Exec(ctx, `INSERT INTO workspace_members(workspace_id,user_id,role) VALUES($1,$2,'member')`, ws, otherID); err != nil {
		t.Fatal(err)
	}
	if err = store.AssignOwner(ctx, ws, box.ID, &otherID); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Select("INBOX", false); err == nil {
		t.Fatal("live connection survived reassignment")
	}
}
func mustDomainID(t *testing.T, h *harness, domain string) string {
	t.Helper()
	var id string
	if err := h.pool.QueryRow(t.Context(), `SELECT id FROM domains WHERE domain=$1`, domain).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}
