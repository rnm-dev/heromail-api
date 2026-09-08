package httpapi

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rnm/heromail/backend/internal/inbound"
)

func TestExistingPersonalMailboxIsolation(t *testing.T) {
	h := newGuardedHarness(t)
	ctx := t.Context()
	operator, _, _ := h.registerUser("personal-operator")
	serviceWS := h.workspaceFor(operator, "personal-service")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, serviceWS) })
	// Use the configured service domain without modifying its DNS or keys.
	_, err := h.pool.Exec(ctx, `INSERT INTO domains(workspace_id,domain,verification_token,verified_at) VALUES($1,'heromail.kz','test',now()) ON CONFLICT(domain) DO NOTHING`, serviceWS)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("personal%d", time.Now().UnixNano())
	addr := name + "@example.test"
	// Seed a pre-existing private mailbox: signup no longer provisions one.
	token, userID, _ := h.registerUser("existing-personal")
	var ws, slug string
	if err := h.pool.QueryRow(ctx, `INSERT INTO workspaces(slug,name,personal_owner_id) VALUES($1,$2,$3) RETURNING id,slug`, name, addr, userID).Scan(&ws, &slug); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	if _, err := h.pool.Exec(ctx, `INSERT INTO workspace_members(workspace_id,user_id,role) VALUES($1,$2,'owner')`, ws, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `INSERT INTO mailboxes(domain_id,local_part,personal_workspace_id) SELECT id,$1,$2 FROM domains WHERE domain='heromail.kz'`, name, ws); err != nil {
		t.Fatal(err)
	}
	path := "/workspaces/" + slug
	r := h.do("GET", path+"/mailboxes", "", token)
	if r.Code != 200 || !strings.Contains(r.Body.String(), name+"@heromail.kz") || !strings.Contains(r.Body.String(), `"can_send":true`) {
		t.Fatalf("mailbox: %d %s", r.Code, r.Body)
	}
	outsider, outsiderID, _ := h.registerUser("personal-outsider")
	if r = h.do("GET", path+"/mailboxes", "", outsider); r.Code != 404 {
		t.Fatalf("mailbox leaked: %d", r.Code)
	}
	if r = h.do("POST", path+"/members", fmt.Sprintf(`{"email":%q,"role":"member"}`, addr), token); r.Code != 403 {
		t.Fatalf("personal membership: %d %s", r.Code, r.Body)
	}
	if _, err := h.pool.Exec(ctx, `INSERT INTO workspace_members(workspace_id,user_id,role) VALUES($1,$2,'member')`, ws, outsiderID); err == nil {
		t.Fatal("DB allowed another member")
	}
	var domainWorkspace string
	if err := h.pool.QueryRow(ctx, `SELECT workspace_id FROM domains WHERE domain='heromail.kz'`).Scan(&domainWorkspace); err != nil {
		t.Fatal(err)
	}
	if err := h.domains.AllowsAddress(ctx, domainWorkspace, name+"@heromail.kz"); err == nil {
		t.Fatal("domain owner may impersonate personal sender")
	}
	store := inbound.NewStore(h.pool)
	box, err := store.MailboxByAddress(ctx, name+"@heromail.kz")
	if err != nil {
		t.Fatal(err)
	}
	msg, err := store.Deliver(ctx, inbound.DeliverParams{MailboxID: box.ID, EnvelopeFrom: "sender@example.test", EnvelopeTo: box.Address, Raw: []byte("From: sender@example.test\r\nSubject: private\r\n\r\nsecret")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.MessageByID(ctx, domainWorkspace, msg.ID); err == nil {
		t.Fatal("service tenant can read personal message")
	}
	if _, err = store.MarkRead(ctx, domainWorkspace, msg.ID); err == nil {
		t.Fatal("service tenant can mark personal message")
	}
	if _, err = store.MessageByID(ctx, ws, msg.ID); err != nil {
		t.Fatal(err)
	}
	send := fmt.Sprintf(`{"from":%q,"to":["to@example.test"],"text":"private sender"}`, box.Address)
	if r = h.do("POST", path+"/emails", send, token); r.Code != 202 {
		t.Fatalf("send: %d %s", r.Code, r.Body)
	}
	if r = h.do("POST", path+"/emails", strings.Replace(send, name+"@", "support@", 1), token); r.Code != 400 {
		t.Fatalf("spoof: %d %s", r.Code, r.Body)
	}
	// API keys must enforce the full address too, not grant the whole shared domain.
	if r = h.do("POST", "/v1/emails", strings.Replace(send, name+"@", "support@", 1), h.apiKeyFor(ws)); r.Code != 400 {
		t.Fatalf("key spoof: %d %s", r.Code, r.Body)
	}
}

func TestRegistrationDoesNotCreatePersonalMailbox(t *testing.T) {
	h := newHarness(t)
	token, userID, _ := h.registerUser("email-only")
	r := h.do("GET", "/workspaces", "", token)
	if r.Code != 200 || strings.Contains(r.Body.String(), "personal-") {
		t.Fatalf("workspaces: %d %s", r.Code, r.Body)
	}
	var count int
	if err := h.pool.QueryRow(t.Context(), `SELECT count(*) FROM workspaces WHERE personal_owner_id=$1`, userID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("unexpected personal workspace: %d %v", count, err)
	}
	addr := fmt.Sprintf("disabled-%d@example.test", time.Now().UnixNano())
	r = h.do("POST", "/auth/register", fmt.Sprintf(`{"email":%q,"password":"correct-horse-battery","personal_name":"miras-new"}`, addr), "")
	if r.Code != 400 {
		t.Fatalf("stale signup accepted: %d %s", r.Code, r.Body)
	}
	if err := h.pool.QueryRow(t.Context(), `SELECT count(*) FROM users WHERE email=$1`, addr).Scan(&count); err != nil || count != 0 {
		t.Fatalf("stale signup created user: %d %v", count, err)
	}
}
