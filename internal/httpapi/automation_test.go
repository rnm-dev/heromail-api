package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rnm/heromail/backend/internal/email"
	"github.com/rnm/heromail/backend/internal/inbound"
)

func TestMailAutomationDeliveryAndRecovery(t *testing.T) {
	h := newHarness(t)
	ctx := t.Context()
	token, uid, _ := h.registerUser("automation-owner")
	other, otherID, _ := h.registerUser("automation-other")
	ws := h.workspaceFor(token, "automation")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	if _, err := h.pool.Exec(ctx, `INSERT INTO workspace_members(workspace_id,user_id,role) VALUES($1,$2,'admin')`, ws, otherID); err != nil {
		t.Fatal(err)
	}
	domain := h.verifiedDomainFor(t, ws)
	store := inbound.NewStore(h.pool)
	box, err := store.CreateMailbox(ctx, mustDomainID(t, h, domain), "private", "", &uid)
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/workspaces/%s/mailboxes/%s/automation", h.slugFor(ws), box.ID)
	call := func(method, body, auth string, want int) []byte {
		t.Helper()
		r := h.do(method, path, body, auth)
		if r.Code != want {
			t.Fatalf("%s: %d want %d: %s", method, r.Code, want, r.Body)
		}
		return r.Body.Bytes()
	}
	call("GET", "", other, 404)
	call("GET", "", h.apiKeyFor(ws), 401)
	var settings inbound.Automation
	json.Unmarshal(call("GET", "", token, 200), &settings)
	if settings.Version != 0 || settings.Vacation.Enabled || len(settings.Rules) != 0 {
		t.Fatal("unexpected defaults")
	}
	var folder int64
	if err = h.pool.QueryRow(ctx, `INSERT INTO imap_folders(mailbox_id,name) VALUES($1,'Invoices') RETURNING uidvalidity`, box.ID).Scan(&folder); err != nil {
		t.Fatal(err)
	}
	label := uuid.NewString()
	if _, err = h.pool.Exec(ctx, `INSERT INTO mail_labels(id,mailbox_id,name) VALUES($1,$2,'Finance')`, label, box.ID); err != nil {
		t.Fatal(err)
	}
	settings.Rules = []inbound.MailRule{{Name: "Invoices", Enabled: true, From: "sender@example.test", Subject: "invoice", FolderUID: &folder, LabelID: &label, MarkRead: true, Stop: true}, {Name: "Later", Enabled: true, Subject: "invoice", MarkRead: true}}
	settings.Vacation = inbound.Vacation{Enabled: true, Subject: "Away", Text: "Back soon"}
	save := func(want int) {
		t.Helper()
		raw, _ := json.Marshal(settings)
		result := call("PUT", string(raw), token, want)
		if want == 200 {
			if err := json.Unmarshal(result, &settings); err != nil {
				t.Fatal(err)
			}
		}
	}
	save(200)
	stale := settings
	stale.Version = 0
	raw, _ := json.Marshal(stale)
	call("PUT", string(raw), token, 409)
	call("PUT", string(raw), other, 404)
	bad := settings
	bad.Rules = append([]inbound.MailRule(nil), settings.Rules...)
	missing := uuid.NewString()
	bad.Rules[0].LabelID = &missing
	raw, _ = json.Marshal(bad)
	call("PUT", string(raw), token, 400)
	deliver := func(sender, extra, subject string) (*inbound.Message, error) {
		return store.Deliver(ctx, inbound.DeliverParams{MailboxID: box.ID, EnvelopeFrom: sender, EnvelopeTo: box.Address, Raw: []byte(fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMessage-ID: <%s@example.test>\r\n%s\r\nOriginal", sender, box.Address, subject, uuid.NewString(), extra))})
	}
	msg, err := deliver("sender@example.test", "", "INVOICE 42")
	if err != nil {
		t.Fatal(err)
	}
	if msg.Folder != "Invoices" || msg.ReadAt == nil {
		t.Fatalf("rule not applied: %+v", msg)
	}
	var count int
	h.pool.QueryRow(ctx, `SELECT count(*) FROM message_labels WHERE message_id=$1 AND label_id=$2`, msg.ID, label).Scan(&count)
	if count != 1 {
		t.Fatal("rule label absent")
	}

	var original []byte
	if err = h.pool.QueryRow(ctx, `SELECT raw FROM messages WHERE id=$1`, msg.ID).Scan(&original); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Deliver(ctx, inbound.DeliverParams{MailboxID: box.ID, EnvelopeFrom: "sender@example.test", EnvelopeTo: box.Address, Raw: original}); !errors.Is(err, inbound.ErrDuplicate) {
		t.Fatalf("duplicate: %v", err)
	}
	if err = store.AppendIMAP(ctx, box.ID, "INBOX", original, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	h.pool.QueryRow(ctx, `SELECT count(*) FROM messages WHERE mailbox_id=$1 AND NOT smtp_delivery AND folder='INBOX' AND read_at IS NULL`, box.ID).Scan(&count)
	if count != 1 {
		t.Fatal("IMAP import unexpectedly ran rules")
	}
	// Folder identity follows rename, and reply cooldown survives settings changes.
	if _, err = h.pool.Exec(ctx, `UPDATE imap_folders SET name='Finance' WHERE mailbox_id=$1 AND name='Invoices'`, box.ID); err != nil {
		t.Fatal(err)
	}
	second, err := deliver("sender@example.test", "", "invoice again")
	if err != nil || second.Folder != "Finance" {
		t.Fatalf("rename %v", err)
	}
	h.pool.QueryRow(ctx, `SELECT count(*) FROM vacation_jobs WHERE mailbox_id=$1`, box.ID).Scan(&count)
	if count != 1 {
		t.Fatal("cooldown failed")
	}
	spam, err := deliver("spam@example.test", "X-Heromail-Spam: Yes\r\n", "invoice")
	if err != nil || spam.Folder != "Junk" {
		t.Fatalf("spam moved: %v", err)
	}
	if _, err = deliver("robot@example.test", "Auto-Submitted: auto-replied\r\n", "hello"); err != nil {
		t.Fatal(err)
	}
	h.pool.QueryRow(ctx, `SELECT count(*) FROM vacation_jobs WHERE mailbox_id=$1`, box.ID).Scan(&count)
	if count != 1 {
		t.Fatal("automatic spam reply")
	}
	// Concurrent deliveries reserve only one reply for an address.
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := deliver("concurrent@example.test", "", "hello"); errs <- err }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	h.pool.QueryRow(ctx, `SELECT count(*) FROM vacation_jobs WHERE mailbox_id=$1 AND recipient='concurrent@example.test'`, box.ID).Scan(&count)
	if count != 1 {
		t.Fatal("concurrent cooldown failed")
	}
	// Stable payload/key recovers an email recorded before a Redis failure.
	svc := email.NewService(email.NewStore(h.pool), h.queue, nil)
	dispatcher := inbound.NewVacationDispatcher(h.pool, svc)
	h.queue.err = errors.New("queue unavailable")
	if found, err := dispatcher.ProcessNext(ctx, box.ID); !found || err == nil {
		t.Fatal("queue failure hidden")
	}
	var id, emailID string
	if err = h.pool.QueryRow(ctx, `SELECT id,email_id FROM vacation_jobs WHERE mailbox_id=$1 AND attempts=1`, box.ID).Scan(&id, &emailID); err != nil {
		t.Fatal(err)
	}
	var status inbound.Automation
	json.Unmarshal(call("GET", "", token, 200), &status)
	if status.PendingReplies != 2 {
		t.Fatalf("pending count=%d", status.PendingReplies)
	}
	h.queue.err = nil
	h.pool.Exec(ctx, `UPDATE vacation_jobs SET due_at=now()-interval '1 second' WHERE id=$1`, id)
	if found, err := dispatcher.ProcessNext(ctx, box.ID); !found || err != nil {
		t.Fatalf("retry: %v", err)
	}
	var after string
	h.pool.QueryRow(ctx, `SELECT email_id FROM vacation_jobs WHERE id=$1`, id).Scan(&after)
	if after != emailID {
		t.Fatal("retry created duplicate email")
	}
	if err = h.worker.Deliver(ctx, emailID, 0, 8); err != nil {
		t.Fatal(err)
	}
	sent, ok := h.mail.last()
	if !ok || !sent.NullReversePath || sent.Headers["Auto-Submitted"] != "auto-replied" {
		t.Fatalf("loop protection missing: %+v", sent)
	}
	// Changing/disabling configuration cancels pending jobs, not ordinary inbox delivery.
	settings.Vacation.Enabled = false
	save(200)
	if found, err := dispatcher.ProcessNext(ctx, box.ID); !found || err != nil {
		t.Fatalf("cancel: %v", err)
	}
	h.pool.QueryRow(ctx, `SELECT count(*) FROM vacation_jobs WHERE mailbox_id=$1 AND status='skipped'`, box.ID).Scan(&count)
	if count != 1 {
		t.Fatal("stale job not canceled")
	}
	// A removed target makes the rule inert and doesn't block receiving mail.
	h.pool.Exec(ctx, `DELETE FROM mail_labels WHERE id=$1`, label)
	got, err := deliver("sender@example.test", "", "invoice missing label")
	if err != nil || got.Folder != "INBOX" {
		t.Fatalf("deleted target: %v", err)
	}
	// Out-of-window vacation never creates a job.
	settings.Rules = nil
	settings.Vacation.Enabled = true
	past := time.Now().Add(-time.Hour)
	settings.Vacation.End = &past
	save(200)
	if _, err = deliver("past@example.test", "", "hello"); err != nil {
		t.Fatal(err)
	}
	h.pool.QueryRow(ctx, `SELECT count(*) FROM vacation_jobs WHERE mailbox_id=$1 AND recipient='past@example.test'`, box.ID).Scan(&count)
	if count != 0 {
		t.Fatal("expired vacation replied")
	}
	settings.Vacation.End = nil
	save(200)
	for i := 0; i < 102; i++ {
		if _, err = deliver(fmt.Sprintf("cap%d@example.test", i), "", "hello"); err != nil {
			t.Fatal(err)
		}
	}
	h.pool.QueryRow(ctx, `SELECT count(*) FROM vacation_jobs WHERE mailbox_id=$1`, box.ID).Scan(&count)
	if count != 100 {
		t.Fatalf("daily cap: %d", count)
	}
	// Eight dispatcher failures terminate instead of leaving an endless retry.
	var doomed string
	if err = h.pool.QueryRow(ctx, `SELECT id FROM vacation_jobs WHERE mailbox_id=$1 AND status='pending' LIMIT 1`, box.ID).Scan(&doomed); err != nil {
		t.Fatal(err)
	}
	h.pool.Exec(ctx, `UPDATE vacation_jobs SET attempts=7,due_at=now()-interval '1 minute' WHERE id=$1`, doomed)
	h.queue.err = errors.New("queue offline")
	if found, err := dispatcher.ProcessNext(ctx, box.ID); !found || err == nil {
		t.Fatal("expected terminal dispatch failure")
	}
	var state string
	h.pool.QueryRow(ctx, `SELECT status FROM vacation_jobs WHERE id=$1`, doomed).Scan(&state)
	if state != "dead" {
		t.Fatalf("exhausted dispatch=%s", state)
	}
	json.Unmarshal(call("GET", "", token, 200), &status)
	if status.FailedReplies != 1 {
		t.Fatal("dead dispatch missing from status")
	}

}
