package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
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
	"golang.org/x/crypto/bcrypt"
)

func TestMailboxSMTPPasswordLifecycle(t *testing.T) {
	for _, role := range []string{"owner", "admin"} {
		t.Run(role, func(t *testing.T) { mailboxSMTPPasswordLifecycle(t, role) })
	}
}
func mailboxSMTPPasswordLifecycle(t *testing.T, role string) {
	h := newHarness(t)
	ctx := t.Context()
	owner, uid, _ := h.registerUser("smtp-app-owner")
	member, memberID, _ := h.registerUser("smtp-app-member")
	ws := h.workspaceFor(owner, "smtp-app")
	if role == "admin" {
		if _, err := h.pool.Exec(ctx, `UPDATE workspace_members SET role='admin' WHERE workspace_id=$1 AND user_id=$2`, ws, uid); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	_, err := h.pool.Exec(ctx, `INSERT INTO workspace_members(workspace_id,user_id,role) VALUES($1,$2,'member');`, ws, memberID)
	if err != nil {
		t.Fatal(err)
	}
	domain := h.verifiedDomainFor(t, ws)
	store := inbound.NewStore(h.pool)
	box, err := store.CreateMailbox(ctx, mustDomainID(t, h, domain), "vaultwarden", "Vaultwarden", &memberID)
	if err != nil {
		t.Fatal(err)
	}
	path := "/workspaces/" + h.slugFor(ws) + "/mailboxes/" + box.ID + "/smtp-password"
	const pass = "vaultwarden-test-password-A"
	const next = "vaultwarden-test-password-B"
	payload := fmt.Sprintf(`{"password":%q}`, pass)
	if r := h.do("PUT", path, payload, member); r.Code != 403 {
		t.Fatalf("member may delegate: %d", r.Code)
	}
	if r := h.do("PUT", path, payload, h.apiKeyFor(ws)); r.Code != 401 {
		t.Fatalf("key may delegate: %d", r.Code)
	}
	if r := h.do("PUT", path, `{"password":"short"}`, owner); r.Code != 400 {
		t.Fatalf("weak password: %d", r.Code)
	}
	if r := h.do("PUT", path, payload, owner); r.Code != 204 {
		t.Fatalf("set: %d %s", r.Code, r.Body)
	}
	var hash string
	if err := h.pool.QueryRow(ctx, `SELECT password_hash FROM mailbox_smtp_credentials WHERE mailbox_id=$1`, box.ID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if hash == pass || bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) != nil {
		t.Fatal("password not hashed")
	}
	listing := h.do("GET", "/workspaces/"+h.slugFor(ws)+"/mailboxes", "", owner)
	if strings.Contains(listing.Body.String(), pass) || strings.Contains(listing.Body.String(), hash) {
		t.Fatal("secret leaked")
	}
	if !strings.Contains(listing.Body.String(), `"smtp_password_set":true`) {
		t.Fatal("missing status")
	}
	// Send-only delegation doesn't grant the issuer private Inbox access.
	msg, err := store.Deliver(ctx, inbound.DeliverParams{MailboxID: box.ID, EnvelopeTo: box.Address, Raw: []byte("From: x@example.test\r\n\r\nprivate")})
	if err != nil {
		t.Fatal(err)
	}
	if r := h.do("GET", "/workspaces/"+h.slugFor(ws)+"/messages/"+msg.ID, "", owner); r.Code != 404 {
		t.Fatal("issuer gained Inbox access")
	}
	_, err = h.pool.Exec(ctx, `UPDATE users SET must_change_password=true WHERE id=$1`, memberID)
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
	var delivered atomic.Int32
	srv := submission.Server(&submission.Backend{Pool: h.pool, Sign: func(_ context.Context, _, _ string, raw []byte) ([]byte, error) { return raw, nil }, Relay: func(_ context.Context, from string, to []string, raw []byte) error { delivered.Add(1); return nil }}, "", "", "")
	srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	connect := func() *smtp.Client {
		c, err := smtp.DialStartTLS(ln.Addr().String(), &tls.Config{RootCAs: roots})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	login := func(c *smtp.Client, password string) error {
		return c.Auth(sasl.NewPlainClient("", box.Address, password))
	}
	c := connect()
	if err = login(c, pass); err != nil {
		t.Fatal(err)
	}
	if c.Mail("other@"+domain, nil) == nil {
		t.Fatal("sender spoofing allowed")
	}
	c.Reset()
	if err = c.SendMail(box.Address, []string{"target@example.test"}, bytes.NewBufferString("From: "+box.Address+"\r\n\r\nnotification")); err != nil {
		t.Fatal(err)
	}
	if delivered.Load() != 1 {
		t.Fatal("not relayed")
	}
	if r := h.do("PUT", path, fmt.Sprintf(`{"password":%q}`, next), owner); r.Code != 204 {
		t.Fatal(r.Body)
	}
	if c.Mail(box.Address, nil) == nil {
		t.Fatal("rotation retained old connection")
	}
	if login(connect(), pass) == nil {
		t.Fatal("rotation retained old password")
	}
	fresh := connect()
	if err = login(fresh, next); err != nil {
		t.Fatal(err)
	}
	if r := h.do("DELETE", path, "", owner); r.Code != 204 {
		t.Fatal(r.Body)
	}
	if fresh.Mail(box.Address, nil) == nil || login(connect(), next) == nil {
		t.Fatal("revocation failed")
	}
	// Reassignment deletes the secret; restoring assignment must not revive it.
	if r := h.do("PUT", path, payload, owner); r.Code != 204 {
		t.Fatalf("reset credential: %d %s", r.Code, r.Body)
	}
	if err = store.AssignOwner(ctx, ws, box.ID, &uid); err != nil {
		t.Fatal(err)
	}
	if err = store.AssignOwner(ctx, ws, box.ID, &memberID); err != nil {
		t.Fatal(err)
	}
	if login(connect(), pass) == nil {
		t.Fatal("reassignment revived secret")
	}
	if r := h.do("PUT", path, payload, owner); r.Code != 204 {
		t.Fatalf("reset credential: %d %s", r.Code, r.Body)
	}
	if _, err := h.pool.Exec(ctx, `UPDATE workspace_members SET role='member' WHERE workspace_id=$1 AND user_id=$2`, ws, uid); err != nil {
		t.Fatal(err)
	}
	if login(connect(), pass) == nil {
		t.Fatal("demoted issuer secret accepted")
	}
	if _, err := h.pool.Exec(ctx, `UPDATE workspace_members SET role='owner' WHERE workspace_id=$1 AND user_id=$2`, ws, uid); err != nil {
		t.Fatal(err)
	}
	if login(connect(), pass) == nil {
		t.Fatal("membership restoration revived secret")
	}
	// Reading status never includes a hash or plaintext, even after revocation.
	listing = h.do("GET", "/workspaces/"+h.slugFor(ws)+"/mailboxes", "", owner)
	if listing.Code != 200 || !strings.Contains(listing.Body.String(), `"smtp_password_set":false`) || strings.Contains(listing.Body.String(), hash) || strings.Contains(listing.Body.String(), pass) {
		t.Fatal("invalid revoked status or secret leaked")
	}
}
