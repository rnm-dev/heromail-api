package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/rnm/heromail/backend/internal/imapservice"
	"github.com/rnm/heromail/backend/internal/inbound"
	"github.com/rnm/heromail/backend/internal/submission"
)

func TestAssistantKeyLifecycle(t *testing.T) {
	h := newHarness(t)
	ctx := t.Context()
	token, userID, _ := h.registerUser("ai-owner")
	otherToken, _, _ := h.registerUser("ai-other")
	ws := h.workspaceFor(token, "ai-keys")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	domain := h.verifiedDomainFor(t, ws)
	box, err := inbound.NewStore(h.pool).CreateMailbox(ctx, mustDomainID(t, h, domain), "agent", "Agent", &userID)
	if err != nil {
		t.Fatal(err)
	}

	if r := h.do("PUT", "/assistant-keys/"+box.ID, "", otherToken); r.Code != 404 {
		t.Fatalf("foreign mailbox: %d %s", r.Code, r.Body)
	}
	if r := h.do("GET", "/assistant-keys", "", ""); r.Code != 401 {
		t.Fatalf("anonymous list: %d", r.Code)
	}
	r := h.do("PUT", "/assistant-keys/"+box.ID, "", token)
	if r.Code != 201 {
		t.Fatalf("issue: %d %s", r.Code, r.Body)
	}
	var issued struct {
		Key     string       `json:"key"`
		Mailbox AssistantKey `json:"mailbox"`
	}
	json.Unmarshal(r.Body.Bytes(), &issued)
	if !strings.HasPrefix(issued.Key, "hm_ai_") || issued.Mailbox.KeyPrefix == nil || !strings.HasPrefix(issued.Key, *issued.Mailbox.KeyPrefix) {
		t.Fatalf("issued: %+v", issued)
	}
	var list struct{ Mailboxes []AssistantKey }
	json.Unmarshal(h.do("GET", "/assistant-keys", "", token).Body.Bytes(), &list)
	if len(list.Mailboxes) != 1 || list.Mailboxes[0].Address != box.Address || strings.Contains(h.do("GET", "/assistant-keys", "", token).Body.String(), issued.Key) {
		t.Fatalf("list: %+v", list)
	}

	connect := startTestIMAP(t, h)
	c := connect()
	if err := c.Login(box.Address, issued.Key); err != nil {
		t.Fatalf("assistant key login: %v", err)
	}
	if _, err := c.Select("INBOX", true); err != nil {
		t.Fatal(err)
	}
	sendWithKey(t, h, box.Address, issued.Key)
	if r := h.do("PUT", "/assistant-keys/"+box.ID, "", token); r.Code != 201 {
		t.Fatalf("rotate: %d", r.Code)
	}
	if _, err := c.Select("INBOX", true); err == nil {
		t.Fatal("rotation did not revoke the open session")
	}
	if err := connect().Login(box.Address, issued.Key); err == nil {
		t.Fatal("rotated key accepted")
	}
	if r := h.do("DELETE", "/assistant-keys/"+box.ID, "", token); r.Code != 204 {
		t.Fatalf("delete: %d", r.Code)
	}
	var n int
	h.pool.QueryRow(ctx, `SELECT count(*) FROM mailbox_assistant_keys WHERE mailbox_id=$1`, box.ID).Scan(&n)
	if n != 0 {
		t.Fatal("key not deleted")
	}

	// Reassignment revokes permanently.
	r = h.do("PUT", "/assistant-keys/"+box.ID, "", token)
	json.Unmarshal(r.Body.Bytes(), &issued)
	h.pool.Exec(ctx, `UPDATE mailboxes SET owner_user_id=NULL WHERE id=$1`, box.ID)
	h.pool.Exec(ctx, `UPDATE mailboxes SET owner_user_id=$2 WHERE id=$1`, box.ID, userID)
	if err := connect().Login(box.Address, issued.Key); err == nil {
		t.Fatal("key survived reassignment")
	}
}

func sendWithKey(t *testing.T, h *harness, address, password string) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	parsed, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	var delivered atomic.Int32
	srv := submission.Server(&submission.Backend{Pool: h.pool, Sign: func(_ context.Context, _, _ string, raw []byte) ([]byte, error) { return raw, nil }, Relay: func(context.Context, string, []string, []byte) error { delivered.Add(1); return nil }}, "", "", "")
	srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	c, err := smtp.DialStartTLS(ln.Addr().String(), &tls.Config{RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Auth(sasl.NewPlainClient("", address, password)); err != nil {
		t.Fatalf("smtp auth with assistant key: %v", err)
	}
	if err := c.SendMail(address, []string{"target@example.test"}, bytes.NewBufferString("From: "+address+"\r\nSubject: ai\r\n\r\nhello")); err != nil {
		t.Fatal(err)
	}
	if delivered.Load() != 1 {
		t.Fatal("not relayed")
	}
}

func startTestIMAP(t *testing.T, h *harness) func() *client.Client {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := imapservice.Server(imapservice.New(h.pool, nil), "", "", "")
	srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	go srv.Serve(tls.NewListener(listener, srv.TLSConfig))
	t.Cleanup(func() { srv.Close() })
	return func() *client.Client {
		c, err := client.DialTLS(listener.Addr().String(), &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12})
		if err != nil {
			t.Fatal(err)
		}
		c.Timeout = 5 * time.Second
		t.Cleanup(func() { c.Terminate() })
		return c
	}
}

func TestAssistantRecipients(t *testing.T) {
	h := newHarness(t)
	ctx := t.Context()
	token, userID, _ := h.registerUser("ai-book")
	ws := h.workspaceFor(token, "ai-book")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	domain := h.verifiedDomainFor(t, ws)
	store := inbound.NewStore(h.pool)
	box, err := store.CreateMailbox(ctx, mustDomainID(t, h, domain), "me", "Me", &userID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateMailbox(ctx, mustDomainID(t, h, domain), "colleague", "Коллега Иванов", nil); err != nil {
		t.Fatal(err)
	}
	h.do("PUT", "/contacts/"+"5a7c3e1e-0000-4000-8000-000000000001", `{"name":"Анна Петрова","email":"anna@example.test","version":0}`, token)
	r := h.do("PUT", "/assistant-keys/"+box.ID, "", token)
	var issued struct{ Key string }
	json.Unmarshal(r.Body.Bytes(), &issued)
	get := func(user, pass, q string) (int, string) {
		req := httptest.NewRequest("GET", "/assistant/recipients?q="+url.QueryEscape(q), nil)
		req.SetBasicAuth(user, pass)
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	if code, _ := get(box.Address, "hm_ai_wrong", ""); code != 401 {
		t.Fatalf("wrong key: %d", code)
	}
	if code, _ := get(box.Address, token, ""); code != 401 {
		t.Fatalf("session token accepted: %d", code)
	}
	code, body := get(box.Address, issued.Key, "")
	if code != 200 || !strings.Contains(body, "Анна Петрова") || !strings.Contains(body, "colleague@"+domain) || strings.Contains(body, `"`+box.Address+`"`) {
		t.Fatalf("all: %d %s", code, body)
	}
	if _, body = get(box.Address, issued.Key, "иванов"); !strings.Contains(body, "colleague@") || strings.Contains(body, "anna@") {
		t.Fatalf("search: %s", body)
	}
}

func TestAssistantCalendar(t *testing.T) {
	h := newHarness(t)
	ctx := t.Context()
	token, userID, _ := h.registerUser("ai-cal")
	ws := h.workspaceFor(token, "ai-cal")
	other := h.workspaceFor(token, "ai-cal-other")
	t.Cleanup(func() {
		h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=ANY($1)`, []string{ws, other})
	})
	domain := h.verifiedDomainFor(t, ws)
	store := inbound.NewStore(h.pool)
	box, err := store.CreateMailbox(ctx, mustDomainID(t, h, domain), "cal", "Cal", &userID)
	if err != nil {
		t.Fatal(err)
	}
	r := h.do("PUT", "/assistant-keys/"+box.ID, "", token)
	var issued struct{ Key string }
	json.Unmarshal(r.Body.Bytes(), &issued)
	call := func(method, path, body, key string) *httptest.ResponseRecorder {
		var req *http.Request
		if body == "" {
			req = httptest.NewRequest(method, path, nil)
		} else {
			req = httptest.NewRequest(method, path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
		}
		req.SetBasicAuth(box.Address, key)
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)
		return rec
	}
	slug, otherSlug := h.slugFor(ws), h.slugFor(other)
	if rec := call("GET", "/assistant/me", "", issued.Key); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"workspace":"`+slug+`"`) {
		t.Fatalf("me: %d %s", rec.Code, rec.Body)
	}
	if rec := call("GET", "/workspaces/"+slug+"/calendar/events?from=2026-11-01&to=2026-11-30", "", "hm_ai_bad"); rec.Code != 401 {
		t.Fatalf("bad key: %d", rec.Code)
	}
	if rec := call("GET", "/workspaces/"+otherSlug+"/calendar/events?from=2026-11-01&to=2026-11-30", "", issued.Key); rec.Code != 403 {
		t.Fatalf("other workspace: %d", rec.Code)
	}
	if rec := call("GET", "/workspaces/"+slug+"/members", "", issued.Key); rec.Code != 401 {
		t.Fatalf("non-calendar route: %d", rec.Code)
	}
	ev := `{"title":"Созвон","description":"","location":"","timezone":"Asia/Almaty","all_day":false,"start":"2026-11-20T10:00","end":"2026-11-20T11:00","version":0,"reminder_minutes":0}`
	created := call("POST", "/workspaces/"+slug+"/calendar/events", ev, issued.Key)
	if created.Code != 201 {
		t.Fatalf("create: %d %s", created.Code, created.Body)
	}
	list := call("GET", "/workspaces/"+slug+"/calendar/events?from=2026-11-01&to=2026-11-30", "", issued.Key)
	if list.Code != 200 || !strings.Contains(list.Body.String(), "Созвон") {
		t.Fatalf("list: %d %s", list.Code, list.Body)
	}
	if rec := call("GET", "/workspaces/"+slug+"/calendar/rooms", "", issued.Key); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"rooms"`) {
		t.Fatalf("rooms: %d %s", rec.Code, rec.Body)
	}
	if rec := call("POST", "/workspaces/"+slug+"/calendar/rooms", `{"name":"A","capacity":4}`, issued.Key); rec.Code != 401 {
		t.Fatalf("room create must stay session-only: %d", rec.Code)
	}
	if rec := call("GET", "/workspaces/"+slug+"/calendar/busy?from=2026-11-20&to=2026-11-21", "", issued.Key); rec.Code != 200 || !strings.Contains(rec.Body.String(), "2026-11-20T05:00:00Z") {
		t.Fatalf("busy: %d %s", rec.Code, rec.Body)
	}
	if rec := call("GET", "/workspaces/"+otherSlug+"/calendar/busy?from=2026-11-20&to=2026-11-21", "", issued.Key); rec.Code != 403 {
		t.Fatalf("busy other workspace: %d", rec.Code)
	}
	raw := []byte("From: a@example.test\r\nTo: " + box.Address + "\r\nSubject: hi\r\n\r\nno invite\r\n")
	msg, err := store.Deliver(ctx, inbound.DeliverParams{MailboxID: box.ID, EnvelopeFrom: "a@example.test", EnvelopeTo: box.Address, Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	var uid int64
	h.pool.QueryRow(ctx, `SELECT imap_uid FROM messages WHERE id=$1`, msg.ID).Scan(&uid)
	if rec := call("POST", "/assistant/invite-reply", fmt.Sprintf(`{"uid":%d,"response":"accepted"}`, uid), issued.Key); rec.Code != 400 {
		t.Fatalf("non-invite reply: %d %s", rec.Code, rec.Body)
	}
	if rec := call("POST", "/assistant/invite-reply", `{"uid":4294967000,"response":"accepted"}`, issued.Key); rec.Code != 404 {
		t.Fatalf("foreign uid: %d", rec.Code)
	}
}
