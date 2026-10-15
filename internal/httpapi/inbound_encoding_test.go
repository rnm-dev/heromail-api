package httpapi

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/rnm/heromail/backend/internal/inbound"
)

func TestMalformedEncodingDeliveryPreservesRaw(t *testing.T) {
	h := newHarness(t)
	ctx := t.Context()
	token, uid, _ := h.registerUser("encoding-owner")
	ws := h.workspaceFor(token, "encoding-test")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	domain := h.verifiedDomainFor(t, ws)
	store := inbound.NewStore(h.pool)
	box, err := store.CreateMailbox(ctx, mustDomainID(t, h, domain), "encoding", "", &uid)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: sender@example.test\r\nSubject: broken \xb4\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nbody \xff with \x00 end")
	msg, err := store.Deliver(ctx, inbound.DeliverParams{MailboxID: box.ID, Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	var saved []byte
	if err = h.pool.QueryRow(ctx, `SELECT raw FROM messages WHERE id=$1`, msg.ID).Scan(&saved); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, saved) {
		t.Fatal("raw MIME changed")
	}
	if msg.TextBody == nil || !utf8.ValidString(*msg.TextBody) || strings.ContainsRune(*msg.TextBody, 0) {
		t.Fatal("display body is not SQL-safe")
	}
}
