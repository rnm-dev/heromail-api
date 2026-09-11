package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// TestSentMailIsDKIMSignedForAVerifiedDomain proves the worker actually signs
// with a claimed, verified domain's key — not just that the key exists.
func TestSentMailIsDKIMSignedForAVerifiedDomain(t *testing.T) {
	h, token, slug := domainHarness(t)
	name := fmt.Sprintf("dkim-send-%d.test", time.Now().UnixNano()%1_000_000)
	base := "/workspaces/" + slug + "/domains"

	created := h.do(http.MethodPost, base, fmt.Sprintf(`{"domain":%q}`, name), token)
	if created.Code != http.StatusCreated {
		t.Fatalf("add domain: %d %s", created.Code, created.Body)
	}
	d := decodeDomain(t, created.Body.Bytes())
	by := recordsByPurpose(d)
	dkimRecord := by["dkim"][0]

	// Verify ownership so Verified() is true — SigningKeyForDomain refuses an
	// unverified domain's key on purpose.
	h.dns.publish(by["ownership"][0].Name, by["ownership"][0].Value)
	if rec := h.do(http.MethodPost, base+"/"+name+"/verify", "", token); rec.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", rec.Code, rec.Body)
	}

	var workspaceID string
	h.pool.QueryRow(context.Background(), `SELECT id FROM workspaces WHERE slug = $1`, slug).Scan(&workspaceID)
	key := h.apiKeyFor(workspaceID)
	h.mail.reset()

	body := fmt.Sprintf(`{"from":"noreply@%s","to":["viktor@acme.test"],"text":"hi"}`, name)
	sent := h.do(http.MethodPost, "/v1/emails", body, key)
	if sent.Code != http.StatusAccepted {
		t.Fatalf("send: %d %s", sent.Code, sent.Body)
	}
	var queued struct {
		ID string `json:"id"`
	}
	json.Unmarshal(sent.Body.Bytes(), &queued)

	h.runWorker(queued.ID)

	msg, ok := h.mail.last()
	if !ok {
		t.Fatal("the transport was never called")
	}
	if msg.DKIM == nil {
		t.Fatal("message was not signed, want a DKIM key for the verified domain")
	}
	if msg.DKIM.Domain != name {
		t.Errorf("DKIM domain = %q, want %q", msg.DKIM.Domain, name)
	}
	// The selector on the wire must be the one currently published and
	// active — a stale or wrong selector would sign with a key DNS does not
	// (or no longer) advertise, and receivers would fail the lookup.
	wantSelector := dkimRecord.Name[:len(dkimRecord.Name)-len("._domainkey."+name)]
	if msg.DKIM.Selector != wantSelector {
		t.Errorf("DKIM selector = %q, want %q", msg.DKIM.Selector, wantSelector)
	}
	if len(msg.DKIM.PrivateKeyDER) == 0 {
		t.Error("DKIM private key is empty")
	}
}

// queueEmail inserts a message the way the API would, bypassing the HTTP
// layer. The sender guard now refuses an unverified From at the boundary, so
// the only way to test what the signer does with one is to put the row in
// directly. That is the point: the signer is the second line of defence and
// has to hold on its own if the first is ever bypassed or removed.
func (h *harness) queueEmail(t *testing.T, workspaceID, from string) string {
	t.Helper()
	var id string
	err := h.pool.QueryRow(t.Context(),
		`INSERT INTO emails (workspace_id, from_addr, to_addrs, text_body)
		 VALUES ($1, $2, ARRAY['viktor@acme.test'], 'hi') RETURNING id`,
		workspaceID, from).Scan(&id)
	if err != nil {
		t.Fatalf("queue email directly: %v", err)
	}
	return id
}

// TestSentMailIsUnsignedForAnUnverifiedDomain: claiming a domain generates a
// key immediately, but ownership is not proven yet — signing with it would
// let anyone who merely typed a domain name into our UI mint DKIM signatures
// for mail claiming to be From it.
func TestSentMailIsUnsignedForAnUnverifiedDomain(t *testing.T) {
	h, token, slug := domainHarness(t)
	name := fmt.Sprintf("dkim-unverified-%d.test", time.Now().UnixNano()%1_000_000)
	base := "/workspaces/" + slug + "/domains"

	if rec := h.do(http.MethodPost, base, fmt.Sprintf(`{"domain":%q}`, name), token); rec.Code != http.StatusCreated {
		t.Fatalf("add domain: %d %s", rec.Code, rec.Body)
	}

	var workspaceID string
	h.pool.QueryRow(context.Background(), `SELECT id FROM workspaces WHERE slug = $1`, slug).Scan(&workspaceID)
	key := h.apiKeyFor(workspaceID)
	h.mail.reset()

	// First line of defence: the API refuses the send outright.
	body := fmt.Sprintf(`{"from":"noreply@%s","to":["viktor@acme.test"],"text":"hi"}`, name)
	if sent := h.do(http.MethodPost, "/v1/emails", body, key); sent.Code != http.StatusBadRequest {
		t.Fatalf("send: %d %s, want 400 — an unverified domain must not be a usable sender", sent.Code, sent.Body)
	}

	// Second line: even if such a message reaches the worker, it goes unsigned.
	h.runWorker(h.queueEmail(t, workspaceID, "noreply@"+name))

	msg, ok := h.mail.last()
	if !ok {
		t.Fatal("the transport was never called")
	}
	if msg.DKIM != nil {
		t.Error("message was signed with an unverified domain's key")
	}
}

// TestSentMailIsUnsignedForAnUnclaimedDomain: a domain the workspace never
// registered has no key at all. The lookup must come back empty and the
// message go out unsigned rather than the worker failing on a missing key.
func TestSentMailIsUnsignedForAnUnclaimedDomain(t *testing.T) {
	h := newHarness(t)
	token, _, _ := h.registerUser("dkim-unclaimed")
	workspaceID := h.workspaceFor(token, "dkim-unclaimed")
	key := h.apiKeyFor(workspaceID)
	h.mail.reset()

	body := `{"from":"noreply@never-claimed.test","to":["viktor@acme.test"],"text":"hi"}`
	if sent := h.do(http.MethodPost, "/v1/emails", body, key); sent.Code != http.StatusBadRequest {
		t.Fatalf("send: %d %s, want 400 — an unclaimed domain must not be a usable sender", sent.Code, sent.Body)
	}
	h.runWorker(h.queueEmail(t, workspaceID, "noreply@never-claimed.test"))

	msg, ok := h.mail.last()
	if !ok {
		t.Fatal("the transport was never called")
	}
	if msg.DKIM != nil {
		t.Error("message was signed for a domain nobody claimed")
	}
}
