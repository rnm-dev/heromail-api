package httpapi

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/rnm/heromail/backend/internal/fcm"
	"github.com/rnm/heromail/backend/internal/inbound"
	"github.com/rnm/heromail/backend/internal/push"
)

// recordingFCM stands in for fcm.Client; tokens in dead answer UNREGISTERED.
type recordingFCM struct {
	mu   sync.Mutex
	sent []fcm.Message
	dead map[string]bool
}

func (r *recordingFCM) Send(_ context.Context, m fcm.Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, m)
	if r.dead[m.Token] {
		return fcm.ErrUnregistered
	}
	return nil
}

func (r *recordingFCM) take() []fcm.Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.sent
	r.sent = nil
	return out
}

type pushFixture struct {
	*syncFixture
	fcm      *recordingFCM
	notifier *push.Notifier
	token    string // the owner's registered FCM token
	slug     string
}

func newPushFixture(t *testing.T, name string) *pushFixture {
	t.Helper()
	f := newSyncFixture(t, name)
	var addr string
	f.h.pool.QueryRow(context.Background(), `SELECT u.email FROM users u JOIN sessions s ON s.user_id = u.id
		WHERE s.token_hash = sha256(convert_to($1, 'UTF8'))`, f.token).Scan(&addr)
	phone := f.h.loginAs(addr, androidClient)
	token := newPushToken()
	if r := f.h.do(http.MethodPut, "/devices/push", pushBody(token), phone.Token); r.Code != http.StatusOK {
		t.Fatalf("register device: %d %s", r.Code, r.Body)
	}
	rec := &recordingFCM{dead: map[string]bool{}}
	var slug string
	f.h.pool.QueryRow(context.Background(), `SELECT w.slug FROM mailboxes m JOIN domains d ON d.id = m.domain_id
		JOIN workspaces w ON w.id = coalesce(m.personal_workspace_id, d.workspace_id) WHERE m.id = $1`, f.box).Scan(&slug)
	return &pushFixture{syncFixture: f, fcm: rec, notifier: push.NewNotifier(f.h.pool, rec), token: token, slug: slug}
}

func (f *pushFixture) deliverRaw(raw string) string {
	f.h.t.Helper()
	m, err := f.store.Deliver(f.h.t.Context(), inbound.DeliverParams{MailboxID: f.box, Raw: []byte(raw)})
	if err != nil {
		f.h.t.Fatal(err)
	}
	return m.ID
}

func TestNewMessagePushPayload(t *testing.T) {
	f := newPushFixture(t, "push-payload")
	id := f.deliverRaw("From: Alice Doe <alice@example.test>\r\nSubject: Quarterly plan\r\n\r\nHi team,\r\n  the plan is attached.")
	if err := f.notifier.NotifyNewMessage(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	sent := f.fcm.take()
	if len(sent) != 1 {
		t.Fatalf("sent %d pushes, want 1", len(sent))
	}
	m := sent[0]
	if m.Token != f.token {
		t.Fatalf("token %q", m.Token)
	}
	want := map[string]string{"workspace": f.slug, "mailbox_id": f.box, "message_id": id}
	if len(m.Data) != len(want) {
		t.Fatalf("data keys %v, want exactly %v", m.Data, want)
	}
	for k, v := range want {
		if m.Data[k] != v {
			t.Fatalf("data[%s] = %q, want %q", k, m.Data[k], v)
		}
	}
	if m.Notification == nil || m.Notification.Title != "Alice Doe" || m.Notification.Body != "Quarterly plan\nHi team, the plan is attached." {
		t.Fatalf("notification: %+v", m.Notification)
	}
	if m.Android == nil || m.Android.Notification.ChannelID != push.AndroidChannel || m.Android.Notification.Tag != id || m.Android.CollapseKey == "" {
		t.Fatalf("android: %+v", m.Android)
	}
	aps := m.APNS.Payload["aps"].(map[string]any)
	if m.APNS.Headers["apns-collapse-id"] != id || aps["thread-id"] != f.box || aps["mutable-content"] != 1 || aps["badge"] != 1 {
		t.Fatalf("apns: %+v", m.APNS)
	}
}

func TestNewMessagePushRecipients(t *testing.T) {
	f := newPushFixture(t, "push-recipients")
	ctx := context.Background()

	// Not from a person, not in the Inbox, or already read: no notification.
	newsletter := f.deliverRaw("From: news@example.test\r\nSubject: Digest\r\n\r\nx")
	f.h.pool.Exec(ctx, `UPDATE messages SET category = 'newsletters' WHERE id = $1`, newsletter)
	junk := f.deliverRaw("From: spam@example.test\r\nSubject: Win\r\n\r\nx")
	if r := f.h.do(http.MethodPut, f.path+"/messages/"+junk+"/folder", `{"folder":"Junk"}`, f.syncFixture.token); r.Code != http.StatusOK {
		t.Fatalf("move to junk: %d %s", r.Code, r.Body)
	}
	archived := f.deliverRaw("From: a@example.test\r\nSubject: Filed by a rule\r\n\r\nx")
	f.h.pool.Exec(ctx, `UPDATE messages SET folder = 'Archive' WHERE id = $1`, archived)
	read := f.deliverRaw("From: a@example.test\r\nSubject: Seen\r\n\r\nx")
	f.h.pool.Exec(ctx, `UPDATE messages SET read_at = now() WHERE id = $1`, read)
	for _, id := range []string{newsletter, junk, archived, read, "00000000-0000-4000-8000-000000000000"} {
		if err := f.notifier.NotifyNewMessage(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	if sent := f.fcm.take(); len(sent) != 0 {
		t.Fatalf("quiet messages pushed: %d", len(sent))
	}

	// A user without access to the mailbox gets nothing, even with a device.
	_, _, strangerAddr := f.h.registerUser("push-stranger")
	stranger := f.h.loginAs(strangerAddr, androidClient)
	strangerToken := newPushToken()
	f.h.do(http.MethodPut, "/devices/push", pushBody(strangerToken), stranger.Token)

	// A dead token is disabled; it is not tried again.
	f.fcm.dead[f.token] = true
	id := f.deliverRaw("From: a@example.test\r\nSubject: Hello\r\n\r\nx")
	f.notifier.NotifyNewMessage(ctx, id)
	sent := f.fcm.take()
	if len(sent) != 1 || sent[0].Token != f.token {
		t.Fatalf("pushes: %+v", sent)
	}
	var disabled bool
	f.h.pool.QueryRow(ctx, `SELECT disabled_at IS NOT NULL FROM push_devices WHERE token = $1`, f.token).Scan(&disabled)
	if !disabled {
		t.Fatal("UNREGISTERED token not disabled")
	}
	f.notifier.NotifyNewMessage(ctx, id)
	if sent := f.fcm.take(); len(sent) != 0 {
		t.Fatalf("disabled device pushed again: %d", len(sent))
	}

	// Push off (no FCM key): nothing happens, nothing fails.
	if err := push.NewNotifier(f.h.pool, nil).NotifyNewMessage(ctx, id); err != nil {
		t.Fatal(err)
	}
}

func TestSilentPushOnChangeElsewhere(t *testing.T) {
	f := newPushFixture(t, "push-silent")
	id := f.deliverRaw("From: a@example.test\r\nSubject: Read me\r\n\r\nx")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.notifier.ListenChanges(ctx, 50*time.Millisecond); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	time.Sleep(200 * time.Millisecond) // let LISTEN start

	wait := func(what string) fcm.Message {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if sent := f.fcm.take(); len(sent) > 0 {
				if len(sent) != 1 {
					t.Fatalf("%s: %d pushes, want 1 coalesced", what, len(sent))
				}
				return sent[0]
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("%s: no silent push", what)
		return fcm.Message{}
	}

	// Read on the web: one data-only push with the new badge.
	if r := f.h.do(http.MethodPatch, f.path+"/messages/"+id+"/flags", `{"read":true}`, f.syncFixture.token); r.Code != http.StatusOK {
		t.Fatalf("flags: %d", r.Code)
	}
	m := wait("read")
	if m.Notification != nil || m.Data["type"] != "sync" || m.Data["mailbox_id"] != f.box || m.Data["workspace"] != f.slug {
		t.Fatalf("silent push: %+v", m)
	}
	aps := m.APNS.Payload["aps"].(map[string]any)
	if aps["content-available"] != 1 || aps["badge"] != 0 || m.APNS.Headers["apns-push-type"] != "background" {
		t.Fatalf("silent apns: %+v", m.APNS)
	}

	// Moved, then deleted by an IMAP-style plain UPDATE/DELETE: a second
	// notification after the first debounce window proves the connection
	// survived it.
	f.h.pool.Exec(context.Background(), `UPDATE messages SET folder = 'Archive' WHERE id = $1`, id)
	wait("move")
	f.h.pool.Exec(context.Background(), `DELETE FROM messages WHERE id = $1`, id)
	wait("delete")
}
