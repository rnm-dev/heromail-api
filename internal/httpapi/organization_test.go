package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/rnm/heromail/backend/internal/inbound"
)

func TestMailOrganization(t *testing.T) {
	h := newHarness(t)
	ctx := t.Context()
	token, uid, _ := h.registerUser("organization-owner")
	other, otherID, _ := h.registerUser("organization-admin")
	ws := h.workspaceFor(token, "organization-test")
	t.Cleanup(func() { h.pool.Exec(context.Background(), "DELETE FROM workspaces WHERE id=$1", ws) })
	if _, err := h.pool.Exec(ctx, "INSERT INTO workspace_members(workspace_id,user_id,role) VALUES($1,$2,'admin')", ws, otherID); err != nil {
		t.Fatal(err)
	}
	domain := h.verifiedDomainFor(t, ws)
	store := inbound.NewStore(h.pool)
	box, err := store.CreateMailbox(ctx, mustDomainID(t, h, domain), "private", "Private", &uid)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := store.Deliver(ctx, inbound.DeliverParams{MailboxID: box.ID, Raw: []byte("Subject: organization\r\n\r\nbody")})
	if err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf("/workspaces/%s/mailboxes/%s", h.slugFor(ws), box.ID)
	org := base + "/organization"
	message := fmt.Sprintf("/workspaces/%s/messages/%s", h.slugFor(ws), msg.ID)
	call := func(method, path, body, auth string, want int) []byte {
		t.Helper()
		r := h.do(method, path, body, auth)
		if r.Code != want {
			t.Fatalf("%s %s: %d want %d: %s", method, path, r.Code, want, r.Body)
		}
		return r.Body.Bytes()
	}
	for _, auth := range []string{other, h.apiKeyFor(ws), ""} {
		r := h.do("GET", org, "", auth)
		if r.Code != 401 && r.Code != 404 {
			t.Fatalf("privacy: %d", r.Code)
		}
	}
	call("PUT", org+"/folders", `{"name":"Projects"}`, other, 404)
	call("PUT", org+"/folders", `{"name":"Projects"}`, token, 204)
	call("PUT", org+"/folders", `{"name":"Projects"}`, token, 409)
	call("PUT", org+"/folders", `{"name":"INBOX"}`, token, 400)
	call("PUT", org+"/folders", `{"name":"bad/name"}`, token, 400)
	var data MailOrganization
	if err := json.Unmarshal(call("GET", org, "", token, 200), &data); err != nil {
		t.Fatal(err)
	}
	var validity int64
	for _, f := range data.Folders {
		if f.Name == "Projects" {
			validity = f.Uidvalidity
		}
	}
	if validity == 0 {
		t.Fatal("missing folder")
	}
	label := uuid.NewString()
	call("PUT", org+"/labels/"+label, `{"name":"Important","version":0}`, token, 200)
	call("PATCH", message+"/labels", fmt.Sprintf(`{"id":%q,"applied":true}`, label), other, 404)
	call("PATCH", message+"/labels", fmt.Sprintf(`{"id":%q,"applied":true}`, uuid.NewString()), token, 404)
	for i := 0; i < 2; i++ {
		call("PATCH", message+"/labels", fmt.Sprintf(`{"id":%q,"applied":true}`, label), token, 204)
	}
	call("PUT", message+"/folder", `{"folder":"Projects","expected_folder":"INBOX"}`, token, 200)
	var before, after int64
	h.pool.QueryRow(ctx, "SELECT imap_uid FROM messages WHERE id=$1", msg.ID).Scan(&before)
	call("DELETE", org+"/folders?name=Projects&uidvalidity="+fmt.Sprint(validity), "", token, 409)
	call("PUT", org+"/folders", fmt.Sprintf(`{"name":"Work","old_name":"Projects","uidvalidity":%d}`, validity+1), token, 409)
	call("PUT", org+"/folders", fmt.Sprintf(`{"name":"Work","old_name":"Projects","uidvalidity":%d}`, validity), token, 204)
	h.pool.QueryRow(ctx, "SELECT imap_uid FROM messages WHERE id=$1", msg.ID).Scan(&after)
	if before == 0 || before != after {
		t.Fatal("rename changed UID")
	}
	got, err := store.MessageByID(ctx, ws, msg.ID)
	if err != nil || got.Folder != "Work" {
		t.Fatal("rename did not cascade")
	}
	var labels MessageLabels
	json.Unmarshal(call("GET", message+"/labels", "", token, 200), &labels)
	if len(labels.Labels) != 1 {
		t.Fatal("labels lost after move/rename")
	}
	var listed struct {
		Messages []ReceivedMessage `json:"messages"`
	}
	json.Unmarshal(call("GET", base+"/messages?folder=Work&label="+label, "", token, 200), &listed)
	if len(listed.Messages) != 1 {
		t.Fatal("label filter missed message")
	}
	json.Unmarshal(call("GET", base+"/messages?folder=All&label="+uuid.NewString(), "", token, 200), &listed)
	if len(listed.Messages) != 0 {
		t.Fatal("label filter leaked messages")
	}
	call("PUT", org+"/labels/"+label, `{"name":"Urgent","version":1}`, token, 200)
	call("PUT", org+"/labels/"+label, `{"name":"Stale","version":1}`, token, 409)
	call("DELETE", org+"/labels/"+label+"?version=1", "", token, 409)
	call("DELETE", org+"/labels/"+label+"?version=2", "", token, 204)
	json.Unmarshal(call("GET", message+"/labels", "", token, 200), &labels)
	if len(labels.Labels) != 0 {
		t.Fatal("deleted label association remains")
	}
	call("PUT", message+"/folder", `{"folder":"INBOX","expected_folder":"Work"}`, token, 200)
	call("DELETE", org+"/folders?name="+url.QueryEscape("Work")+"&uidvalidity="+fmt.Sprint(validity), "", token, 204)
	call("PUT", message+"/folder", `{"folder":"Work"}`, token, 404)
	call("GET", message, "", token, 200)
}
