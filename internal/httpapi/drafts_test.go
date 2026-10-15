package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/rnm/heromail/backend/internal/email"
	"testing"
)

func TestDraftsOwnershipVersionsAndRecovery(t *testing.T) {
	h := newHarness(t)
	token, owner, _ := h.registerUser("draft-owner")
	other, otherID, _ := h.registerUser("draft-peer")
	ws := h.workspaceFor(token, "drafts")
	slug := h.slugFor(ws)
	if _, err := h.pool.Exec(context.Background(), `INSERT INTO workspace_members(workspace_id,user_id,role) VALUES($1,$2,'admin')`, ws, otherID); err != nil {
		t.Fatal(err)
	}
	id := uuid.NewString()
	path := "/workspaces/" + slug + "/drafts/" + id
	save := func(version int, data string, who string, code int) MailDraft {
		t.Helper()
		r := h.do("PUT", path, fmt.Sprintf(`{"version":%d,"data":%s}`, version, data), who)
		if r.Code != code {
			t.Fatalf("save: %d %s", r.Code, r.Body)
		}
		var d MailDraft
		if code == 200 {
			if err := json.Unmarshal(r.Body.Bytes(), &d); err != nil {
				t.Fatal(err)
			}
		}
		return d
	}
	if r := h.do("GET", "/messages/drafts", "", ""); r.Code != 401 {
		t.Fatalf("anonymous: %d", r.Code)
	}
	if r := h.do("GET", "/messages/drafts", "", h.apiKeyFor(ws)); r.Code != 401 {
		t.Fatalf("API key: %d", r.Code)
	}
	a := save(0, `{"body":"first","subject":"Private","richText":true,"bodyHtml":"<b>first</b>"}`, token, 200)
	if a.Data["bodyHtml"] != "<b>first</b>" || a.Data["richText"] != true {
		t.Fatal("formatted draft lost")
	}
	if a.Version != 1 {
		t.Fatal(a.Version)
	}
	// Lost response: identical old-version write is idempotent.
	if b := save(0, `{"body":"first","subject":"Private","richText":true,"bodyHtml":"<b>first</b>"}`, token, 200); b.Version != 1 {
		t.Fatal(b.Version)
	}
	save(0, `{"body":"stale"}`, token, 409)
	save(0, `{"body":"steal"}`, other, 404)
	for _, method := range []string{"GET", "DELETE"} {
		r := h.do(method, path+"?version=1", "", other)
		if r.Code != 404 {
			t.Fatalf("peer %s: %d %s", method, r.Code, r.Body)
		}
	}
	r := h.do("GET", "/messages/drafts", "", other)
	if r.Code != 200 || string(r.Body.Bytes()) == "" {
		t.Fatal(r.Body)
	}
	var listing struct{ Drafts []MailDraft }
	json.Unmarshal(r.Body.Bytes(), &listing)
	if len(listing.Drafts) != 0 {
		t.Fatal("peer can see draft")
	}
	save(1, `{"body":"second"}`, token, 200)
	save(1, `{"body":"concurrent"}`, token, 409)
	if r = h.do("DELETE", path+"?version=1", "", token); r.Code != 409 {
		t.Fatalf("stale delete: %d", r.Code)
	}
	// Owner-only attachments may be saved, foreign uploads may not.
	store := email.NewStore(h.pool)
	upload := func(user string) string {
		a, err := store.InsertAttachment(context.Background(), email.InsertAttachmentParams{WorkspaceID: ws, UploadOwnerID: user, Filename: "test.xlsx", ContentType: "application/octet-stream", SizeBytes: 12, ChecksumSHA: make([]byte, 32), StorageKey: uuid.NewString()})
		if err != nil {
			t.Fatal(err)
		}
		return a.ID
	}
	own := upload(owner)
	foreign := upload(otherID)
	payload := func(id string) string {
		return fmt.Sprintf(`{"body":"files","attachments":[{"upload":%q,"file":{"name":"test.xlsx","size":12}}]}`, id)
	}
	save(2, payload(foreign), token, 400)
	save(2, payload(own), token, 200)
	for _, ctx := range []context.Context{context.Background(), email.WithUploadOwner(context.Background(), otherID)} {
		files, err := store.AttachmentsByIDs(ctx, ws, []string{own})
		if err != nil || len(files) != 0 {
			t.Fatalf("foreign claim: %v %v", files, err)
		}
	}
	files, err := store.AttachmentsByIDs(email.WithUploadOwner(context.Background(), owner), ws, []string{own})
	if err != nil || len(files) != 1 {
		t.Fatalf("own claim: %v %v", files, err)
	}
	pending := fmt.Sprintf(`{"body":"files","attempt":{"workspace":%q,"key":"same-key","payload":{"from":"test@example.test","to":["to@example.test"],"text":"files","attachments":[%q]}}}`, slug, own)
	save(3, pending, token, 200)
	save(3, pending, token, 200)
	save(4, `{"body":"cannot overwrite a sending draft"}`, token, 409)
	// Membership revocation hides content and blocks mutation.
	if _, err = h.pool.Exec(context.Background(), `DELETE FROM workspace_members WHERE workspace_id=$1 AND user_id=$2`, ws, owner); err != nil {
		t.Fatal(err)
	}
	if r = h.do("GET", path, "", token); r.Code != 404 {
		t.Fatalf("revoked read: %d", r.Code)
	}
	r = h.do("GET", "/messages/drafts", "", token)
	json.Unmarshal(r.Body.Bytes(), &listing)
	if len(listing.Drafts) != 0 {
		t.Fatal("revoked list")
	}
}
