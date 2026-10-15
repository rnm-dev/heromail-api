package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/rnm/heromail/backend/internal/inbound"
	"testing"
)

func TestMessageFlagsFiltersAndCounts(t *testing.T) {
	h := newHarness(t)
	ctx := t.Context()
	token, uid, _ := h.registerUser("flags-owner")
	other, otherID, _ := h.registerUser("flags-admin")
	ws := h.workspaceFor(token, "flags-test")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	if _, err := h.pool.Exec(ctx, `INSERT INTO workspace_members(workspace_id,user_id,role) VALUES($1,$2,'admin')`, ws, otherID); err != nil {
		t.Fatal(err)
	}
	domain := h.verifiedDomainFor(t, ws)
	store := inbound.NewStore(h.pool)
	box, err := store.CreateMailbox(ctx, mustDomainID(t, h, domain), "private", "Private", &uid)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := store.Deliver(ctx, inbound.DeliverParams{MailboxID: box.ID, Raw: []byte("From: a@example.test\r\nSubject: Old unread\r\n\r\nKeep")})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 51; i++ {
		m, err := store.Deliver(ctx, inbound.DeliverParams{MailboxID: box.ID, Raw: []byte(fmt.Sprintf("Subject: newer %d\r\n\r\nBody", i))})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = store.MarkRead(ctx, ws, m.ID); err != nil {
			t.Fatal(err)
		}
	}
	path := "/workspaces/" + h.slugFor(ws)
	flags := path + "/messages/" + msg.ID + "/flags"
	for _, auth := range []string{other, h.apiKeyFor(ws), ""} {
		r := h.do("PATCH", flags, `{"starred":true,"read":true}`, auth)
		if r.Code != 401 && r.Code != 404 {
			t.Fatalf("private flag leak: %d", r.Code)
		}
	}
	for _, body := range []string{`{}`, `{"read":null}`, `{"starred":"yes"}`} {
		if r := h.do("PATCH", flags, body, token); r.Code != 400 {
			t.Fatalf("invalid flags accepted: %d %s", r.Code, r.Body)
		}
	}
	list := func(query string) []ReceivedMessage {
		r := h.do("GET", path+"/mailboxes/"+box.ID+"/messages?"+query, "", token)
		var result struct {
			Messages []ReceivedMessage `json:"messages"`
		}
		if r.Code != 200 {
			t.Fatalf("list: %d %s", r.Code, r.Body)
		}
		if err := json.Unmarshal(r.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result.Messages
	}
	if m := list("unread=true&limit=50"); len(m) != 1 || m[0].Id.String() != msg.ID {
		t.Fatalf("unread filtered after pagination: %d", len(m))
	}
	counts := func(auth string) map[string]int {
		r := h.do("GET", "/messages/unread-counts", "", auth)
		if r.Code != 200 {
			t.Fatalf("counts: %d %s", r.Code, r.Body)
		}
		var c map[string]int
		if err := json.Unmarshal(r.Body.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	if counts(token)["INBOX"] != 1 || counts(other)["INBOX"] != 0 {
		t.Fatal("counts leak or wrong unread count")
	}
	for _, auth := range []string{"", h.apiKeyFor(ws)} {
		if r := h.do("GET", "/messages/unread-counts", "", auth); r.Code != 401 {
			t.Fatalf("counts auth: %d", r.Code)
		}
	}
	// Preserve unrelated flags while setting/removing Flagged, with explicit false.
	if _, err := h.pool.Exec(ctx, `UPDATE messages SET imap_flags=ARRAY['\Answered']::text[] WHERE id=$1`, msg.ID); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"starred":true}`, `{"starred":true}`, `{"read":true}`, `{"read":false}`} {
		if r := h.do("PATCH", flags, body, token); r.Code != 200 {
			t.Fatalf("flags: %d %s", r.Code, r.Body)
		}
	}
	if c := counts(token); c["INBOX"] != 1 || c["starred"] != 1 {
		t.Fatalf("counts after flags: %v", c)
	}
	if _, err := store.MoveMessage(ctx, box.ID, msg.ID, "Archive"); err != nil {
		t.Fatal(err)
	}
	if m := list("folder=All&starred=true&unread=true"); len(m) != 1 || m[0].Folder != "Archive" || m[0].Starred == nil || !*m[0].Starred {
		t.Fatal("starred across folders missing")
	}
	if len(list("folder=INBOX&starred=true")) != 0 {
		t.Fatal("folder filter ignored")
	}
	if r := h.do("PATCH", flags, `{"starred":false}`, token); r.Code != 200 {
		t.Fatal(r.Body)
	}
	var flagList []string
	if err := h.pool.QueryRow(ctx, `SELECT imap_flags FROM messages WHERE id=$1`, msg.ID).Scan(&flagList); err != nil {
		t.Fatal(err)
	}
	if len(flagList) != 1 || flagList[0] != `\Answered` {
		t.Fatalf("unrelated flags changed: %v", flagList)
	}
	if len(list("folder=All&starred=true")) != 0 || counts(token)["starred"] != 0 {
		t.Fatal("unstar failed")
	}
}
