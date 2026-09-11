package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// verifiedDomainFor claims a domain for the workspace and marks it verified,
// so a send from it is allowed once the guard is on.
func (h *harness) verifiedDomainFor(t *testing.T, workspaceID string) string {
	t.Helper()

	name := fmt.Sprintf("send-%d.test", time.Now().UnixNano()%1_000_000_000)
	if _, err := h.pool.Exec(t.Context(),
		`INSERT INTO domains (workspace_id, domain, verification_token, verified_at)
		 VALUES ($1, $2, 'tok', now())`, workspaceID, name); err != nil {
		t.Fatalf("claim domain: %v", err)
	}
	return name
}

func TestSessionSendQueuesAMessage(t *testing.T) {
	h := newHarness(t)
	token, _, _ := h.registerUser("session-send")
	workspaceID := h.workspaceFor(token, "session-send")
	slug := h.slugFor(workspaceID)
	domain := h.verifiedDomainFor(t, workspaceID)
	if _, err := h.pool.Exec(t.Context(), `INSERT INTO mailboxes(domain_id,local_part) SELECT id,'noreply' FROM domains WHERE workspace_id=$1 AND domain=$2`, workspaceID, domain); err != nil {
		t.Fatal(err)
	}
	h.mail.reset()

	body := fmt.Sprintf(`{"from":"noreply@%s","to":["viktor@acme.test"],"subject":"Hi","text":"hello"}`, domain)
	rec := h.do(http.MethodPost, "/workspaces/"+slug+"/emails", body, token)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d, want 202; body %s", rec.Code, rec.Body)
	}

	var queued struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	json.Unmarshal(rec.Body.Bytes(), &queued)
	if queued.Status != "queued" || queued.ID == "" {
		t.Fatalf("response = %+v", queued)
	}
	// Same pipeline as the API-key path: recorded and queued, not sent inline.
	if got := h.queue.queued(); len(got) == 0 || got[len(got)-1] != queued.ID {
		t.Errorf("message was not handed to the queue: %v", got)
	}
}

// An API key must not reach a session route, and a session must not reach
// /v1 — the two credentials are deliberately not interchangeable.
func TestSessionSendRefusesAnApiKey(t *testing.T) {
	h := newHarness(t)
	token, _, _ := h.registerUser("session-send-key")
	workspaceID := h.workspaceFor(token, "session-send-key")
	slug := h.slugFor(workspaceID)
	key := h.apiKeyFor(workspaceID)

	body := `{"from":"a@acme.test","to":["b@acme.test"],"text":"x"}`
	if rec := h.do(http.MethodPost, "/workspaces/"+slug+"/emails", body, key); rec.Code != http.StatusUnauthorized {
		t.Errorf("an API key reached a session route (%d)", rec.Code)
	}
}

// A member of one workspace must not send as another.
func TestSessionSendIsScopedToMembership(t *testing.T) {
	h := newHarness(t)
	ownerToken, _, _ := h.registerUser("send-owner")
	ownerWorkspace := h.workspaceFor(ownerToken, "send-owner")
	slug := h.slugFor(ownerWorkspace)

	outsiderToken, _, _ := h.registerUser("send-outsider")
	body := `{"from":"a@acme.test","to":["b@acme.test"],"text":"x"}`
	if rec := h.do(http.MethodPost, "/workspaces/"+slug+"/emails", body, outsiderToken); rec.Code != http.StatusNotFound {
		t.Errorf("a non-member sent as this workspace (%d)", rec.Code)
	}
}

// senderFor is the address a workspace is actually allowed to send as. Tests
// that are about something else — attachments, idempotency, rate limits — use
// it so they exercise the same sender check production applies, instead of
// passing only because enforcement happened to be off.
func (h *harness) senderFor(t *testing.T, workspaceID string) string {
	t.Helper()
	return "noreply@" + h.verifiedDomainFor(t, workspaceID)
}

func TestSendRefusesAnUnverifiedSenderDomain(t *testing.T) {
	h := newHarness(t)
	token, _, _ := h.registerUser("guard-refuse")
	workspaceID := h.workspaceFor(token, "guard-refuse")
	key := h.apiKeyFor(workspaceID)

	// Nothing claimed: sending as anyone's domain must be refused.
	body := `{"from":"ceo@some-bank.test","to":["victim@acme.test"],"text":"wire me money"}`
	rec := h.do(http.MethodPost, "/v1/emails", body, key)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 — a workspace sent as a domain it does not own; body %s", rec.Code, rec.Body)
	}
}

func TestSendAllowsAVerifiedSenderDomain(t *testing.T) {
	h := newHarness(t)
	token, _, _ := h.registerUser("guard-allow")
	workspaceID := h.workspaceFor(token, "guard-allow")
	key := h.apiKeyFor(workspaceID)
	domain := h.verifiedDomainFor(t, workspaceID)

	body := fmt.Sprintf(`{"from":"noreply@%s","to":["viktor@acme.test"],"text":"hi"}`, domain)
	if rec := h.do(http.MethodPost, "/v1/emails", body, key); rec.Code != http.StatusAccepted {
		t.Fatalf("status %d, want 202; body %s", rec.Code, rec.Body)
	}
}

// One workspace verifying a domain must not let another send as it.
func TestSendRefusesAnotherWorkspacesDomain(t *testing.T) {
	h := newHarness(t)

	ownerToken, _, _ := h.registerUser("guard-owner")
	ownerWorkspace := h.workspaceFor(ownerToken, "guard-owner")
	domain := h.verifiedDomainFor(t, ownerWorkspace)

	otherToken, _, _ := h.registerUser("guard-other")
	otherWorkspace := h.workspaceFor(otherToken, "guard-other")
	otherKey := h.apiKeyFor(otherWorkspace)

	body := fmt.Sprintf(`{"from":"noreply@%s","to":["v@acme.test"],"text":"hi"}`, domain)
	if rec := h.do(http.MethodPost, "/v1/emails", body, otherKey); rec.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400 — another workspace's verified domain was usable", rec.Code)
	}
}
