package httpapi

import (
	"context"
	"encoding/json"
	"github.com/rnm/heromail/backend/internal/inbound"
	"net/url"
	"testing"
	"time"
)

func TestReceivedSearchGlobalPagesAndMIME(t *testing.T) {
	h := newHarness(t)
	ctx := t.Context()
	token, uid, _ := h.registerUser("search-owner")
	admin, aid, _ := h.registerUser("search-admin")
	ws := h.workspaceFor(token, "search-test")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	if _, err := h.pool.Exec(ctx, `INSERT INTO workspace_members(workspace_id,user_id,role) VALUES($1,$2,'admin')`, ws, aid); err != nil {
		t.Fatal(err)
	}
	domain := h.verifiedDomainFor(t, ws)
	store := inbound.NewStore(h.pool)
	boxes := []*inbound.Mailbox{}
	for _, local := range []string{"one", "two"} {
		box, err := store.CreateMailbox(ctx, mustDomainID(t, h, domain), local, local, &uid)
		if err != nil {
			t.Fatal(err)
		}
		boxes = append(boxes, box)
	}
	var target string
	for i := 0; i < 52; i++ {
		raw := "From: Sender <sender@example.test>\r\nTo: normal@example.test\r\nSubject: Needle 100%_\r\n\r\nBody"
		if i == 0 {
			raw = "From: Sender <sender@example.test>\r\nTo: rare@example.test\r\nCc: copy@example.test\r\nBcc: hidden@example.test\r\nSubject: Needle 100%_\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nBody\r\n--x\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=file.xlsx\r\nContent-Transfer-Encoding: base64\r\n\r\nAAEC\r\n--x--\r\n"
		}
		box := boxes[i%2]
		m, err := store.Deliver(ctx, inbound.DeliverParams{MailboxID: box.ID, EnvelopeTo: box.Address, Raw: []byte(raw)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = h.pool.Exec(ctx, `UPDATE messages SET received_at=$2 WHERE id=$1`, m.ID, time.Date(2026, 10, 14, 0, 0, i, 0, time.UTC)); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			target = m.ID
			if _, err = store.MoveMessage(ctx, box.ID, m.ID, "Archive"); err != nil {
				t.Fatal(err)
			}
		}
	}
	search := func(query, auth string) ReceivedSearchPage {
		t.Helper()
		r := h.do("GET", "/messages/received-search?"+query, "", auth)
		if r.Code != 200 {
			t.Fatalf("search: %d %s", r.Code, r.Body)
		}
		var page ReceivedSearchPage
		if err := json.Unmarshal(r.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		return page
	}
	first := search("q=Needle&folder=All", token)
	second := search("q=Needle&folder=All&offset=50", token)
	if len(first.Messages) != 50 || !first.HasMore || len(second.Messages) != 2 || second.HasMore {
		t.Fatal("global page boundaries")
	}
	seen := map[string]bool{}
	for _, m := range append(first.Messages, second.Messages...) {
		id := m.Message.Id.String()
		if seen[id] {
			t.Fatal("duplicate between pages")
		}
		seen[id] = true
		if m.Workspace != h.slugFor(ws) {
			t.Fatal("wrong workspace link")
		}
	}
	for _, query := range []string{"to=rare", "to=COPY", "attachments=true", "from=SENDER&to=copy&attachments=true&after=2026-10-14&before=2026-10-14"} {
		p := search(query+"&folder=All", token)
		if len(p.Messages) != 1 || p.Messages[0].Message.Id.String() != target || p.HasMore {
			t.Fatalf("MIME filter before pagination: %s %+v", query, p)
		}
	}
	if len(search("folder=All&attachments=true&offset=1", token).Messages) != 0 {
		t.Fatal("MIME offset ignored")
	}
	if len(search("folder=INBOX&attachments=true", token).Messages) != 0 {
		t.Fatal("folder ignored")
	}
	if len(search("folder=All&to=hidden", token).Messages) != 0 {
		t.Fatal("Bcc searched")
	}
	if len(search("folder=All&after=2026-10-15", token).Messages) != 0 {
		t.Fatal("date ignored")
	}
	if len(search("folder=All&box="+boxes[0].ID, token).Messages) != 26 {
		t.Fatal("box filter ignored")
	}
	if len(search("folder=All&q="+url.QueryEscape("100%_"), token).Messages) != 50 {
		t.Fatal("literal query mishandled")
	}
	if len(search("folder=All", admin).Messages) != 0 || len(search("folder=All&box="+boxes[0].ID, admin).Messages) != 0 {
		t.Fatal("private results leaked")
	}
	for _, auth := range []string{"", h.apiKeyFor(ws)} {
		if r := h.do("GET", "/messages/received-search?q=Needle", "", auth); r.Code != 401 {
			t.Fatal("search auth bypass")
		}
	}
	for _, query := range []string{"limit=0", "limit=101", "offset=-1", "before=nonsense", "after=2026-10-15&before=2026-10-14", "folder=bad%2Fname"} {
		if r := h.do("GET", "/messages/received-search?"+query, "", token); r.Code != 400 {
			t.Fatalf("invalid search accepted %s %d", query, r.Code)
		}
	}
}
