package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

func TestUploadAttachmentThenSendDeliversIt(t *testing.T) {
	h := newHarness(t)
	token, _, _ := h.registerUser("attach")
	workspaceID := h.workspaceFor(token, "attach")
	key := h.apiKeyFor(workspaceID)
	h.mail.reset()

	rec := h.uploadFile(key, "invoice.pdf", "application/pdf", []byte("%PDF-1.4 fake invoice bytes"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload: status %d, body %s", rec.Code, rec.Body)
	}
	var uploaded struct {
		ID          string `json:"id"`
		Filename    string `json:"filename"`
		ContentType string `json:"content_type"`
		SizeBytes   int    `json:"size_bytes"`
	}
	json.Unmarshal(rec.Body.Bytes(), &uploaded)
	if uploaded.ID == "" || uploaded.Filename != "invoice.pdf" || uploaded.ContentType != "application/pdf" {
		t.Fatalf("upload response = %+v", uploaded)
	}
	if uploaded.SizeBytes != len("%PDF-1.4 fake invoice bytes") {
		t.Errorf("size_bytes = %d, want %d", uploaded.SizeBytes, len("%PDF-1.4 fake invoice bytes"))
	}

	body := fmt.Sprintf(`{"from":"noreply@acme.com","to":["viktor@acme.com"],"text":"see attached","attachments":[%q]}`, uploaded.ID)
	sent := h.do(http.MethodPost, "/v1/emails", body, key)
	if sent.Code != http.StatusAccepted {
		t.Fatalf("send: status %d, body %s", sent.Code, sent.Body)
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
	if len(msg.Attachments) != 1 {
		t.Fatalf("transport received %d attachments, want 1", len(msg.Attachments))
	}
	if msg.Attachments[0].Filename != "invoice.pdf" {
		t.Errorf("attachment filename = %q", msg.Attachments[0].Filename)
	}

	// GET reflects what was attached.
	got := h.do(http.MethodGet, "/v1/emails/"+queued.ID, "", key)
	var email struct {
		Attachments []struct {
			ID       string `json:"id"`
			Filename string `json:"filename"`
		} `json:"attachments"`
	}
	json.Unmarshal(got.Body.Bytes(), &email)
	if len(email.Attachments) != 1 || email.Attachments[0].ID != uploaded.ID {
		t.Errorf("GET attachments = %+v, want [%s]", email.Attachments, uploaded.ID)
	}
}

func TestSendWithUnknownAttachmentIsRejected(t *testing.T) {
	h := newHarness(t)
	token, _, _ := h.registerUser("attach-missing")
	workspaceID := h.workspaceFor(token, "attach-missing")
	key := h.apiKeyFor(workspaceID)

	body := `{"from":"noreply@acme.com","to":["viktor@acme.com"],"text":"hi",
	          "attachments":["00000000-0000-0000-0000-000000000000"]}`
	rec := h.do(http.MethodPost, "/v1/emails", body, key)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400; body %s", rec.Code, rec.Body)
	}
}

func TestAttachmentFromAnotherWorkspaceIsRejected(t *testing.T) {
	h := newHarness(t)

	tokenA, _, _ := h.registerUser("attach-owner")
	workspaceA := h.workspaceFor(tokenA, "attach-owner")
	keyA := h.apiKeyFor(workspaceA)

	tokenB, _, _ := h.registerUser("attach-other")
	workspaceB := h.workspaceFor(tokenB, "attach-other")
	keyB := h.apiKeyFor(workspaceB)

	rec := h.uploadFile(keyA, "secret.txt", "text/plain", []byte("mine, not yours"))
	var uploaded struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &uploaded)

	body := fmt.Sprintf(`{"from":"noreply@other.com","to":["v@other.com"],"text":"hi","attachments":[%q]}`, uploaded.ID)
	sent := h.do(http.MethodPost, "/v1/emails", body, keyB)
	if sent.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 — another workspace's attachment must not be usable; body %s", sent.Code, sent.Body)
	}
}

func TestAttachmentCannotBeReused(t *testing.T) {
	h := newHarness(t)
	token, _, _ := h.registerUser("attach-reuse")
	workspaceID := h.workspaceFor(token, "attach-reuse")
	key := h.apiKeyFor(workspaceID)

	rec := h.uploadFile(key, "once.txt", "text/plain", []byte("only for one message"))
	var uploaded struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &uploaded)

	body := fmt.Sprintf(`{"from":"noreply@acme.com","to":["v@acme.com"],"text":"first","attachments":[%q]}`, uploaded.ID)
	first := h.do(http.MethodPost, "/v1/emails", body, key)
	if first.Code != http.StatusAccepted {
		t.Fatalf("first send: status %d, body %s", first.Code, first.Body)
	}

	second := h.do(http.MethodPost, "/v1/emails", body, key)
	if second.Code != http.StatusBadRequest {
		t.Fatalf("second send: status %d, want 400 — an attachment must not be reusable across messages; body %s", second.Code, second.Body)
	}
}

func TestUploadWithoutAFilePartIsRejected(t *testing.T) {
	h := newHarness(t)
	token, _, _ := h.registerUser("attach-empty")
	workspaceID := h.workspaceFor(token, "attach-empty")
	key := h.apiKeyFor(workspaceID)

	r := h.do(http.MethodPost, "/v1/attachments", "", key)
	// No multipart body at all: the strict layer's MultipartReader() call
	// itself fails, which is still a 400 under the shared error envelope.
	if r.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400; body %s", r.Code, r.Body)
	}
}
