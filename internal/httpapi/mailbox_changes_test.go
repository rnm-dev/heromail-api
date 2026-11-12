package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/rnm/heromail/backend/internal/inbound"
)

type syncFixture struct {
	h     *harness
	token string
	path  string // /workspaces/{slug}
	box   string
	store *inbound.Store
}

func newSyncFixture(t *testing.T, name string) *syncFixture {
	t.Helper()
	h := newHarness(t)
	token, uid, _ := h.registerUser(name)
	ws := h.workspaceFor(token, name)
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	store := inbound.NewStore(h.pool)
	box, err := store.CreateMailbox(t.Context(), mustDomainID(t, h, h.verifiedDomainFor(t, ws)), "sync", "Sync", &uid)
	if err != nil {
		t.Fatal(err)
	}
	return &syncFixture{h: h, token: token, path: "/workspaces/" + h.slugFor(ws), box: box.ID, store: store}
}

func (f *syncFixture) changesRaw(cursor string, limit int) (int, MailboxChanges, string) {
	f.h.t.Helper()
	q := url.Values{}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	if limit > 0 {
		q.Set("limit", fmt.Sprint(limit))
	}
	r := f.h.do(http.MethodGet, f.path+"/mailboxes/"+f.box+"/changes?"+q.Encode(), "", f.token)
	var c MailboxChanges
	if r.Code == http.StatusOK {
		if err := json.Unmarshal(r.Body.Bytes(), &c); err != nil {
			f.h.t.Fatalf("decode changes: %v", err)
		}
		return r.Code, c, ""
	}
	return r.Code, c, errorCode(f.h.t, r)
}

func (f *syncFixture) changes(cursor string) MailboxChanges {
	f.h.t.Helper()
	code, c, ec := f.changesRaw(cursor, 0)
	if code != http.StatusOK {
		f.h.t.Fatalf("changes: %d %s", code, ec)
	}
	return c
}

func (f *syncFixture) deliver(subject string) string {
	f.h.t.Helper()
	m, err := f.store.Deliver(f.h.t.Context(), inbound.DeliverParams{MailboxID: f.box,
		Raw: []byte("From: a@example.test\r\nSubject: " + subject + "\r\n\r\nBody")})
	if err != nil {
		f.h.t.Fatal(err)
	}
	return m.ID
}

func onlyMessage(t *testing.T, c MailboxChanges, id string) ChangedMessage {
	t.Helper()
	if len(c.Messages) != 1 || c.Messages[0].Message.Id.String() != id {
		t.Fatalf("want exactly message %s, got %+v", id, c.Messages)
	}
	return c.Messages[0]
}

func TestMailboxChangesFollowEveryWritePath(t *testing.T) {
	f := newSyncFixture(t, "sync-paths")
	ctx := context.Background()

	start := f.changes("")
	if start.HasMore || len(start.Messages) != 0 || !start.OrganizationChanged {
		t.Fatalf("initial call: %+v", start)
	}
	if again := f.changes(start.NextCursor); len(again.Messages) != 0 || again.OrganizationChanged {
		t.Fatalf("no-op poll returned changes: %+v", again)
	}

	// Delivery (the LMTP path).
	id := f.deliver("hello")
	c := f.changes(start.NextCursor)
	m := onlyMessage(t, c, id)
	if m.Message.Subject != "hello" || m.Message.Html != nil || c.Unread["INBOX"] != 1 {
		t.Fatalf("delivered card: %+v unread %v", m, c.Unread)
	}
	cursor := c.NextCursor

	// Web flags.
	if r := f.h.do(http.MethodPatch, f.path+"/messages/"+id+"/flags", `{"read":true,"starred":true}`, f.token); r.Code != http.StatusOK {
		t.Fatalf("flags: %d %s", r.Code, r.Body)
	}
	c = f.changes(cursor)
	if m := onlyMessage(t, c, id); m.Message.ReadAt == nil || !*m.Message.Starred || c.Unread["INBOX"] != 0 {
		t.Fatalf("flag change: %+v", m)
	}
	cursor = c.NextCursor

	// IMAP and automation write the same columns with plain UPDATEs; the
	// triggers number them all the same.
	if _, err := f.h.pool.Exec(ctx, `UPDATE messages SET imap_flags = array_remove(imap_flags, '\Flagged') WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	c = f.changes(cursor)
	if m := onlyMessage(t, c, id); *m.Message.Starred {
		t.Fatal("IMAP unflag not reflected")
	}
	cursor = c.NextCursor

	// Folder move.
	if r := f.h.do(http.MethodPut, f.path+"/messages/"+id+"/folder", `{"folder":"Archive"}`, f.token); r.Code != http.StatusOK {
		t.Fatalf("move: %d %s", r.Code, r.Body)
	}
	c = f.changes(cursor)
	if m := onlyMessage(t, c, id); m.Message.Folder != "Archive" {
		t.Fatalf("move not reflected: %s", m.Message.Folder)
	}
	cursor = c.NextCursor

	// Label definition and assignment.
	var label string
	if err := f.h.pool.QueryRow(ctx, `INSERT INTO mail_labels (id, mailbox_id, name) VALUES (gen_random_uuid(), $1, 'Work') RETURNING id`, f.box).Scan(&label); err != nil {
		t.Fatal(err)
	}
	c = f.changes(cursor)
	if !c.OrganizationChanged || len(c.Messages) != 0 {
		t.Fatalf("label definition: %+v", c)
	}
	cursor = c.NextCursor
	if _, err := f.h.pool.Exec(ctx, `INSERT INTO message_labels (mailbox_id, message_id, label_id) VALUES ($1, $2, $3)`, f.box, id, label); err != nil {
		t.Fatal(err)
	}
	c = f.changes(cursor)
	if m := onlyMessage(t, c, id); len(m.LabelIds) != 1 || m.LabelIds[0].String() != label || c.OrganizationChanged {
		t.Fatalf("label assignment: %+v", c)
	}
	cursor = c.NextCursor

	// Deletion.
	if _, err := f.h.pool.Exec(ctx, `DELETE FROM messages WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	c = f.changes(cursor)
	if len(c.Messages) != 0 || len(c.Deleted) != 1 || c.Deleted[0].String() != id {
		t.Fatalf("deletion: %+v", c)
	}
}

func TestMailboxChangesCursorExpired(t *testing.T) {
	f := newSyncFixture(t, "sync-expired")
	other := newSyncFixture(t, "sync-expired-other")
	ctx := context.Background()

	foreign := other.changes("").NextCursor
	for name, cursor := range map[string]string{
		"garbage": "not-a-cursor",
		"foreign": foreign,
		"future":  inbound.EncodeCursor(f.box, 1_000_000_000),
	} {
		if code, _, ec := f.changesRaw(cursor, 0); code != http.StatusGone || ec != "cursor_expired" {
			t.Fatalf("%s cursor: %d %s", name, code, ec)
		}
	}

	start := f.changes("").NextCursor
	id := f.deliver("old")
	f.h.pool.Exec(ctx, `DELETE FROM messages WHERE id = $1`, id)
	f.h.pool.Exec(ctx, `UPDATE message_tombstones SET deleted_at = now() - interval '31 days' WHERE message_id = $1`, id)
	if _, err := f.store.PruneTombstones(ctx, inbound.TombstoneRetention); err != nil {
		t.Fatal(err)
	}
	// The deletion this cursor needed is gone: resync rather than miss it.
	if code, _, ec := f.changesRaw(start, 0); code != http.StatusGone || ec != "cursor_expired" {
		t.Fatalf("pruned cursor: %d %s", code, ec)
	}
	if code, _, _ := f.changesRaw(f.changes("").NextCursor, 0); code != http.StatusOK {
		t.Fatalf("fresh cursor after prune: %d", code)
	}

	stranger, _, _ := f.h.registerUser("sync-stranger")
	if r := f.h.do(http.MethodGet, f.path+"/mailboxes/"+f.box+"/changes", "", stranger); r.Code != http.StatusNotFound {
		t.Fatalf("stranger read changes: %d", r.Code)
	}
	if code, _, _ := f.changesRaw("", 501); code != http.StatusBadRequest {
		t.Fatalf("oversized limit: %d", code)
	}
}

func TestMailboxChangesPaginate10k(t *testing.T) {
	if testing.Short() {
		t.Skip("10k messages")
	}
	f := newSyncFixture(t, "sync-10k")
	ctx := context.Background()
	start := f.changes("").NextCursor

	const total = 10_000
	began := time.Now()
	if _, err := f.h.pool.Exec(ctx, `
		INSERT INTO messages (mailbox_id, envelope_to, subject, raw, size_bytes)
		SELECT $1, 'sync@acme.test', 'bulk ' || g, '\x00'::bytea, 1 FROM generate_series(1, $2) g`, f.box, total); err != nil {
		t.Fatal(err)
	}
	t.Logf("inserted %d messages in %v", total, time.Since(began))

	pull := func(cursor string, limit int) (map[string]bool, map[string]bool, string, int) {
		seen, deleted := map[string]bool{}, map[string]bool{}
		pages := 0
		for {
			code, c, ec := f.changesRaw(cursor, limit)
			if code != http.StatusOK {
				t.Fatalf("page %d: %d %s", pages, code, ec)
			}
			pages++
			if len(c.Messages)+len(c.Deleted) > limit {
				t.Fatalf("page over limit: %d", len(c.Messages)+len(c.Deleted))
			}
			for _, m := range c.Messages {
				if seen[m.Message.Id.String()] {
					t.Fatalf("message %s repeated across pages", m.Message.Id)
				}
				seen[m.Message.Id.String()] = true
			}
			for _, id := range c.Deleted {
				deleted[id.String()] = true
			}
			cursor = c.NextCursor
			if !c.HasMore {
				return seen, deleted, cursor, pages
			}
		}
	}

	began = time.Now()
	seen, _, cursor, pages := pull(start, 500)
	if len(seen) != total || pages != total/500 {
		t.Fatalf("got %d messages in %d pages, want %d in %d", len(seen), pages, total, total/500)
	}
	t.Logf("synced %d messages in %d pages in %v", total, pages, time.Since(began))

	// Mixed page: 100 flag changes and 100 deletions interleave by seq.
	if _, err := f.h.pool.Exec(ctx, `
		UPDATE messages SET read_at = now()
		WHERE id IN (SELECT id FROM messages WHERE mailbox_id = $1 ORDER BY imap_uid LIMIT 100)`, f.box); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.pool.Exec(ctx, `
		DELETE FROM messages
		WHERE id IN (SELECT id FROM messages WHERE mailbox_id = $1 ORDER BY imap_uid DESC LIMIT 100)`, f.box); err != nil {
		t.Fatal(err)
	}
	changed, deleted, _, pages := pull(cursor, 30)
	if len(changed) != 100 || len(deleted) != 100 || pages != 7 {
		t.Fatalf("after edits: %d changed, %d deleted, %d pages", len(changed), len(deleted), pages)
	}
}
