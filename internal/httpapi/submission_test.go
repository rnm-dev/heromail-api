package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/rnm/heromail/backend/internal/inbound"
	"github.com/rnm/heromail/backend/internal/submission"
)

func TestSubmissionAuthenticatedDeliveryAndRevocation(t *testing.T) {
	h := newHarness(t)
	ctx := t.Context()
	token, uid, _ := h.registerUser("smtp-user")
	ws := h.workspaceFor(token, "smtp-test")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	domain := fmt.Sprintf("smtp-%d.test", time.Now().UnixNano())
	if _, err := h.domains.Add(ctx, ws, domain); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `UPDATE domains SET verified_at=now() WHERE domain=$1`, domain); err != nil {
		t.Fatal(err)
	}
	store := inbound.NewStore(h.pool)
	box, err := store.CreateMailbox(ctx, mustDomainID(t, h, domain), "sender", "Sender", &uid)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	parsed, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	delivered := make(chan []byte, 4)
	var relayFails atomic.Bool
	b := &submission.Backend{Pool: h.pool, Sign: submission.DKIM(h.domains), Relay: func(_ context.Context, from string, to []string, raw []byte) error {
		if relayFails.Load() {
			return errors.New("queue unavailable")
		}
		if from != box.Address || len(to) != 2 {
			t.Error("wrong envelope")
		}
		delivered <- raw
		return nil
	}}
	srv := submission.Server(b, "", "", "")
	srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	connect := func() *smtp.Client {
		c, e := smtp.DialStartTLS(ln.Addr().String(), &tls.Config{RootCAs: roots})
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	plain, e := smtp.Dial(ln.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer plain.Close()
	if ok, _ := plain.Extension("AUTH"); ok {
		t.Fatal("AUTH exposed without TLS")
	}
	if plain.Mail(box.Address, nil) == nil {
		t.Fatal("unauthenticated relay allowed")
	}
	c := connect()
	if c.Auth(sasl.NewPlainClient("", box.Address, "wrong")) == nil {
		t.Fatal("wrong password accepted")
	}
	if c.Auth(sasl.NewPlainClient("other@"+domain, box.Address, "correct-horse-battery")) == nil {
		t.Fatal("delegated identity accepted")
	}
	if err = c.Auth(sasl.NewPlainClient("", box.Address, "correct-horse-battery")); err != nil {
		t.Fatal(err)
	}
	if c.Mail("other@"+domain, nil) == nil {
		t.Fatal("envelope spoofing allowed")
	}
	c.Reset()
	raw := []byte("From: " + box.Address + "\r\nTo: target@example.test\r\nBcc: blind@example.test\r\nSubject: SMTP test\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\nAAECAwQ=\r\n--b--\r\n")
	recipients := []string{"target@example.test", "blind@example.test"}
	if err = c.SendMail(box.Address, recipients, bytes.NewReader(bytes.Replace(raw, []byte("From: "+box.Address), []byte("From: forged@"+domain), 1))); err == nil {
		t.Fatal("header spoofing accepted")
	}
	c.Reset()
	if err = c.SendMail(box.Address, recipients, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	received := <-delivered
	if !bytes.Contains(received, []byte("DKIM-Signature:")) || !bytes.Contains(received, []byte("d="+domain)) || !bytes.Contains(received, []byte("AAECAwQ=")) || bytes.Contains(received, []byte("Bcc:")) {
		t.Fatal("missing DKIM/MIME or exposed Bcc")
	}
	relayFails.Store(true)
	if err = c.SendMail(box.Address, recipients, bytes.NewReader(raw)); err == nil {
		t.Fatal("queue outage acknowledged")
	}
	c.Reset()
	relayFails.Store(false)
	h.pool.Exec(ctx, `UPDATE users SET must_change_password=true WHERE id=$1`, uid)
	if c.Mail(box.Address, nil) == nil {
		t.Fatal("existing session survived mandatory password gate")
	}
	gated := connect()
	if gated.Auth(sasl.NewPlainClient("", box.Address, "correct-horse-battery")) == nil {
		t.Fatal("initial password accepted")
	}
	h.pool.Exec(ctx, `UPDATE users SET must_change_password=false WHERE id=$1`, uid)
	for _, change := range []string{`UPDATE mailboxes SET owner_user_id=NULL WHERE id='` + box.ID + `'`, `UPDATE domains SET verified_at=NULL WHERE domain='` + domain + `'`, `UPDATE identities SET password_hash=password_hash||'x' WHERE user_id='` + uid + `' AND provider='password'`, `DELETE FROM workspace_members WHERE workspace_id='` + ws + `' AND user_id='` + uid + `'`} {
		// Each change must independently revoke an already-authenticated connection.
		h.pool.Exec(ctx, `UPDATE domains SET verified_at=now() WHERE domain=$1`, domain)
		next := connect()
		err = next.Auth(sasl.NewPlainClient("", box.Address, "correct-horse-battery"))
		if err != nil {
			t.Fatal(err)
		}
		var old string
		h.pool.QueryRow(ctx, `SELECT password_hash FROM identities WHERE user_id=$1 AND provider='password'`, uid).Scan(&old)
		if _, err = h.pool.Exec(ctx, change); err != nil {
			t.Fatal(err)
		}
		if err = next.Mail(box.Address, nil); err == nil {
			t.Fatal("revoked connection can send: " + change)
		}
		if strings.Contains(change, "owner_user_id") {
			h.pool.Exec(ctx, `UPDATE mailboxes SET owner_user_id=$2 WHERE id=$1`, box.ID, uid)
		}
		if strings.Contains(change, "password_hash") {
			h.pool.Exec(ctx, `UPDATE identities SET password_hash=$2 WHERE user_id=$1 AND provider='password'`, uid, old)
		}
	}
}
