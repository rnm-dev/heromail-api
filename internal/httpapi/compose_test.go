package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestComposePipeline(t *testing.T) {
	h := newHarness(t)
	owner, _, _ := h.registerUser("compose-owner")
	member, memberID, _ := h.registerUser("compose-member")
	outsider, _, _ := h.registerUser("compose-outsider")
	ws := h.workspaceFor(owner, "compose")
	t.Cleanup(func() { h.pool.Exec(t.Context(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	slug := h.slugFor(ws)
	path := "/workspaces/" + slug
	domain := h.verifiedDomainFor(t, ws)
	if _, err := h.pool.Exec(t.Context(), `INSERT INTO mailboxes(domain_id,local_part) SELECT id,'hello' FROM domains WHERE workspace_id=$1 AND domain=$2`, ws, domain); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(t.Context(), `INSERT INTO workspace_members(workspace_id,user_id,role) VALUES($1,$2,'member')`, ws, memberID); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"from":"hello@%s","to":["to@example.test"],"cc":["copy@example.test"],"bcc":["secret@example.test"],"text":"Hello from UI"}`, domain)
	for _, token := range []string{"", h.apiKeyFor(ws)} {
		if r := h.do("POST", path+"/emails", body, token); r.Code != 401 {
			t.Fatalf("credential boundary: %d %s", r.Code, r.Body)
		}
	}
	if r := h.do("POST", path+"/emails", body, outsider); r.Code != 404 {
		t.Fatalf("cross tenant: %d", r.Code)
	}
	for _, bad := range []string{strings.Replace(body, "hello@", "unknown@", 1), strings.Replace(body, "copy@example.test", "not-an-email", 1)} {
		if r := h.do("POST", path+"/emails", bad, member); r.Code != 400 {
			t.Fatalf("invalid sender/cc: %d %s", r.Code, r.Body)
		}
	}
	// An outage after storing the row is recoverable with the same key.
	h.queue.err = errors.New("queue unavailable")
	r := h.doWithHeader("POST", path+"/emails", body, member, "Idempotency-Key", "compose-retry")
	if r.Code != 500 {
		t.Fatalf("queue outage: %d %s", r.Code, r.Body)
	}
	h.queue.err = nil
	r = h.doWithHeader("POST", path+"/emails", body, member, "Idempotency-Key", "compose-retry")
	if r.Code != 202 {
		t.Fatalf("recovery: %d %s", r.Code, r.Body)
	}
	var sent struct {
		ID string `json:"id"`
	}
	json.Unmarshal(r.Body.Bytes(), &sent)
	if h.queue.count() != 1 {
		t.Fatalf("recovery did not enqueue: %d", h.queue.count())
	}
	h.mail.reset()
	h.runWorker(sent.ID)
	h.runWorker(sent.ID)
	message, ok := h.mail.last()
	if !ok || h.mail.count() != 1 || len(message.Cc) != 1 || len(message.Bcc) != 1 {
		t.Fatalf("copies/deduplication: %+v count=%d", message, h.mail.count())
	}
	r = h.do("GET", path+"/emails/"+sent.ID, "", member)
	if r.Code != 200 || !strings.Contains(r.Body.String(), `"status":"sent"`) || !strings.Contains(r.Body.String(), "secret@example.test") {
		t.Fatalf("status: %d %s", r.Code, r.Body)
	}
	if r = h.do("GET", path+"/emails/"+sent.ID, "", outsider); r.Code != 404 {
		t.Fatalf("status isolation: %d", r.Code)
	}
	if r = h.doWithHeader("POST", path+"/emails", strings.Replace(body, "Hello from UI", "changed", 1), member, "Idempotency-Key", "compose-retry"); r.Code != 400 {
		t.Fatalf("changed payload accepted under same key: %d", r.Code)
	}
	if _, err := h.pool.Exec(t.Context(), `UPDATE domains SET verified_at=NULL WHERE workspace_id=$1`, ws); err != nil {
		t.Fatal(err)
	}
	if r = h.do("POST", path+"/emails", body, member); r.Code != 400 {
		t.Fatalf("unverified sender accepted: %d", r.Code)
	}
}

func TestComposeAttachmentUpload(t *testing.T) {
	h := newHarness(t)
	token, _, _ := h.registerUser("compose-upload")
	outsider, _, _ := h.registerUser("compose-upload-other")
	ws := h.workspaceFor(token, "compose-upload")
	slug := h.slugFor(ws)
	t.Cleanup(func() { h.pool.Exec(t.Context(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	upload := func(credential string) *httptest.ResponseRecorder {
		var b bytes.Buffer
		writer := multipart.NewWriter(&b)
		part, err := writer.CreateFormFile("file", "hello.txt")
		if err != nil {
			t.Fatal(err)
		}
		part.Write([]byte("attachment bytes"))
		writer.Close()
		r := httptest.NewRequest("POST", "/workspaces/"+slug+"/attachments", &b)
		r.Header.Set("Content-Type", writer.FormDataContentType())
		r.Header.Set("Authorization", "Bearer "+credential)
		w := httptest.NewRecorder()
		h.handler.ServeHTTP(w, r)
		return w
	}
	if r := upload(outsider); r.Code != 404 {
		t.Fatalf("upload scope %d", r.Code)
	}
	if r := upload(h.apiKeyFor(ws)); r.Code != 401 {
		t.Fatalf("upload auth %d", r.Code)
	}
	r := upload(token)
	if r.Code != 201 {
		t.Fatalf("upload %d %s", r.Code, r.Body)
	}
	var a struct {
		ID string `json:"id"`
	}
	json.Unmarshal(r.Body.Bytes(), &a)
	var owner string
	if err := h.pool.QueryRow(t.Context(), `SELECT workspace_id FROM attachments WHERE id=$1`, a.ID).Scan(&owner); err != nil || owner != ws {
		t.Fatalf("attachment owner %s %v", owner, err)
	}
	domain := h.verifiedDomainFor(t, ws)
	if _, err := h.pool.Exec(t.Context(), `INSERT INTO mailboxes(domain_id,local_part) SELECT id,'hello' FROM domains WHERE workspace_id=$1 AND domain=$2`, ws, domain); err != nil {
		t.Fatal(err)
	}
	r = h.do("POST", "/workspaces/"+slug+"/emails", fmt.Sprintf(`{"from":"hello@%s","to":["to@example.test"],"text":"see attachment","attachments":[%q]}`, domain, a.ID), token)
	if r.Code != 202 {
		t.Fatalf("send attachment %d %s", r.Code, r.Body)
	}
	var queued struct {
		ID string `json:"id"`
	}
	json.Unmarshal(r.Body.Bytes(), &queued)
	h.mail.reset()
	h.runWorker(queued.ID)
	m, ok := h.mail.last()
	if !ok || len(m.Attachments) != 1 || m.Attachments[0].Filename != "hello.txt" {
		t.Fatalf("missing attachment: %+v", m)
	}
}
