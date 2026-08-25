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
	if msg.DKIM != nil {
		t.Error("message was signed with an unverified domain's key")
	}
}

// TestSentMailIsUnsignedForAnUnclaimedDomain: sending From a domain the
// workspace never registered at all must not crash or block delivery — it
// just sends unsigned, exactly as permissive as the From address itself
// already is today.
func TestSentMailIsUnsignedForAnUnclaimedDomain(t *testing.T) {
	h := newHarness(t)
	token, _, _ := h.registerUser("dkim-unclaimed")
	workspaceID := h.workspaceFor(token, "dkim-unclaimed")
	key := h.apiKeyFor(workspaceID)
	h.mail.reset()

	body := `{"from":"noreply@never-claimed.test","to":["viktor@acme.test"],"text":"hi"}`
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
	if msg.DKIM != nil {
		t.Error("message was signed for a domain nobody claimed")
	}
}
