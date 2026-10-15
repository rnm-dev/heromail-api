package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/rnm/heromail/backend/internal/inbound"
	"testing"
)

func TestForwardRawAndConditionalUndo(t *testing.T) {
	h := newHarness(t)
	ctx := t.Context()
	token, uid, _ := h.registerUser("forward-owner")
	other, otherID, _ := h.registerUser("forward-admin")
	ws := h.workspaceFor(token, "forward-test")
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
	raw := []byte("From: sender@example.test\r\nTo: me@example.test\r\nCc: copy@example.test\r\nBcc: hidden@example.test\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/html\r\n\r\n<b>Original</b>\r\n--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=x.bin\r\nContent-Transfer-Encoding: base64\r\n\r\nAAECAw==\r\n--b--\r\n")
	msg, err := store.Deliver(ctx, inbound.DeliverParams{MailboxID: box.ID, Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/workspaces/%s/messages/%s", h.slugFor(ws), msg.ID)
	for _, auth := range []string{other, h.apiKeyFor(ws), ""} {
		r := h.do("GET", path+"/raw", "", auth)
		if r.Code != 401 && r.Code != 404 {
			t.Fatalf("raw privacy: %d", r.Code)
		}
	}
	r := h.do("GET", path+"/raw", "", token)
	if r.Code != 200 || r.Body.String() != string(raw) || r.Header().Get("Content-Type") != "application/octet-stream" || r.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("raw download: %d %v", r.Code, r.Header())
	}
	r = h.do("GET", path, "", token)
	var detail ReceivedMessage
	if err := json.Unmarshal(r.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.To == nil || len(*detail.To) != 1 || detail.Cc == nil || len(*detail.Cc) != 1 {
		t.Fatalf("missing recipients: %s", r.Body)
	}
	move := func(body string, want int) {
		t.Helper()
		r := h.do("PUT", path+"/folder", body, token)
		if r.Code != want {
			t.Fatalf("move: %d want %d %s", r.Code, want, r.Body)
		}
	}
	move(`{"folder":"Archive","expected_folder":"INBOX"}`, 200)
	move(`{"folder":"INBOX","expected_folder":"Archive"}`, 200)
	move(`{"folder":"Archive","expected_folder":"INBOX"}`, 200)
	move(`{"folder":"Trash"}`, 200)
	var before, after int64
	if err := h.pool.QueryRow(ctx, `SELECT imap_uid FROM messages WHERE id=$1`, msg.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	move(`{"folder":"INBOX","expected_folder":"Archive"}`, 409)
	if err := h.pool.QueryRow(ctx, `SELECT imap_uid FROM messages WHERE id=$1`, msg.ID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	got, err := store.MessageByID(ctx, ws, msg.ID)
	if err != nil || got.Folder != "Trash" || before != after {
		t.Fatal("undo overwrote later move")
	}
}
