package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/rnm/heromail/backend/internal/inbound"
)

func TestSpamFolderDeliveryMoveAndPrivacy(t *testing.T) {
	h := newHarness(t)
	ctx := t.Context()
	token, uid, _ := h.registerUser("spam-owner")
	ws := h.workspaceFor(token, "spam-folder")
	slug := h.slugFor(ws)
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	domain := h.verifiedDomainFor(t, ws)
	store := inbound.NewStore(h.pool)
	box, err := store.CreateMailbox(ctx, mustDomainID(t, h, domain), "private", "Private", &uid)
	if err != nil {
		t.Fatal(err)
	}
	makeMessage := func(extra, id string) *inbound.Message {
		m, err := store.Deliver(ctx, inbound.DeliverParams{MailboxID: box.ID, EnvelopeFrom: "sender@example.test", EnvelopeTo: box.Address, Raw: []byte("From: sender@example.test\r\nTo: " + box.Address + "\r\nMessage-ID: <" + id + "@example.test>\r\nSubject: Spam routing\r\n" + extra + "\r\nContent\r\n")})
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	spam := makeMessage("X-Heromail-Spam: Yes, score=8.0\r\n", "spam")
	ham := makeMessage("X-Spam-Status: Yes, score=99\r\n", "ham")
	duplicate := makeMessage("X-Heromail-Spam: Yes\r\nX-Heromail-Spam: No\r\n", "ambiguous")
	if spam.Folder != "Junk" || ham.Folder != "INBOX" || duplicate.Folder != "INBOX" {
		t.Fatal("wrong routing")
	}
	list := func(folder string, auth string) []ReceivedMessage {
		r := h.do(http.MethodGet, fmt.Sprintf("/workspaces/%s/mailboxes/%s/messages?folder=%s", slug, box.ID, folder), "", auth)
		if r.Code != 200 {
			t.Fatalf("list %s: %d %s", folder, r.Code, r.Body)
		}
		var result struct {
			Messages []ReceivedMessage `json:"messages"`
		}
		if err := json.Unmarshal(r.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result.Messages
	}
	if len(list("INBOX", token)) != 2 || len(list("Junk", token)) != 1 {
		t.Fatal("folders mixed")
	}
	// Workspace administrator does not inherit another employee's private messages.
	other, otherID, _ := h.registerUser("spam-admin")
	h.pool.Exec(ctx, `INSERT INTO workspace_members(workspace_id,user_id,role) VALUES($1,$2,'admin')`, ws, otherID)
	path := fmt.Sprintf("/workspaces/%s/messages/%s/folder", slug, spam.ID)
	for _, auth := range []string{other, h.apiKeyFor(ws)} {
		r := h.do(http.MethodPut, path, `{"folder":"INBOX"}`, auth)
		if r.Code != 404 && r.Code != 401 {
			t.Fatalf("unauthorized move: %d", r.Code)
		}
	}
	var before, after int64
	h.pool.QueryRow(ctx, `SELECT imap_uid FROM messages WHERE id=$1`, spam.ID).Scan(&before)
	r := h.do(http.MethodPut, path, `{"folder":"INBOX"}`, token)
	if r.Code != 200 {
		t.Fatalf("move: %d %s", r.Code, r.Body)
	}
	if len(list("Junk", token)) != 0 || len(list("INBOX", token)) != 3 {
		t.Fatal("restored message missing")
	}
	h.pool.QueryRow(ctx, `SELECT imap_uid FROM messages WHERE id=$1`, spam.ID).Scan(&after)
	if after <= before {
		t.Fatal("IMAP move did not allocate fresh UID")
	}
	r = h.do(http.MethodPut, path, `{"folder":"INBOX"}`, token)
	if r.Code != 200 {
		t.Fatal(r.Body)
	}
	var again int64
	h.pool.QueryRow(ctx, `SELECT imap_uid FROM messages WHERE id=$1`, spam.ID).Scan(&again)
	if again != after {
		t.Fatal("repeat move changes UID")
	}
	if r = h.do(http.MethodPut, path, `{"folder":"Other"}`, token); r.Code != 400 {
		t.Fatalf("invalid destination %d", r.Code)
	}
	if r = h.do(http.MethodPut, path, `{"folder":"Junk"}`, token); r.Code != 200 {
		t.Fatal(r.Body)
	}
	if len(list("Junk", token)) != 1 {
		t.Fatal("manual spam move missing")
	}
	// Original SMTP retry cannot duplicate a message even after a folder move.
	_, err = store.Deliver(ctx, inbound.DeliverParams{MailboxID: box.ID, Raw: []byte("Message-ID: <spam@example.test>\r\n\r\nretry")})
	if err != inbound.ErrDuplicate {
		t.Fatalf("retry dedup: %v", err)
	}
}
