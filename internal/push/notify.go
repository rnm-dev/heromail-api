package push

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rnm/heromail/backend/internal/fcm"
	"github.com/rnm/heromail/backend/internal/inbound"
)

// TypeNewMessage is the asynq task lmtpd enqueues after storing a message.
const TypeNewMessage = "push:new_message"

// AndroidChannel is the notification channel the app creates for mail.
const AndroidChannel = "mail"

// Sender is fcm.Client in production and a recorder in tests.
type Sender interface {
	Send(ctx context.Context, msg fcm.Message) error
}

type newMessagePayload struct {
	MessageID string `json:"message_id"`
}

// Enqueuer queues new-message pushes. lmtpd holds one; delivery never waits
// on FCM.
type Enqueuer struct{ client *asynq.Client }

func NewEnqueuer(redisAddr string) *Enqueuer {
	return &Enqueuer{client: asynq.NewClient(asynq.RedisClientOpt{Addr: redisAddr})}
}

func (e *Enqueuer) Close() error { return e.client.Close() }

func (e *Enqueuer) EnqueueNewMessage(ctx context.Context, messageID string) error {
	payload, _ := json.Marshal(newMessagePayload{MessageID: messageID})
	// The task id dedupes a redelivery of the same stored message.
	_, err := e.client.EnqueueContext(ctx, asynq.NewTask(TypeNewMessage, payload),
		asynq.TaskID("push:"+messageID), asynq.MaxRetry(3), asynq.Timeout(time.Minute))
	if errors.Is(err, asynq.ErrTaskIDConflict) {
		return nil
	}
	return err
}

// Notifier turns mailbox events into FCM messages. A nil sender means push is
// off: tasks are acknowledged and dropped.
type Notifier struct {
	pool    *pgxpool.Pool
	inbound *inbound.Store
	devices *Store
	sender  Sender
	now     func() time.Time // quiet hours are judged against this; tests pin it
}

func NewNotifier(pool *pgxpool.Pool, sender Sender) *Notifier {
	return &Notifier{pool: pool, inbound: inbound.NewStore(pool), devices: NewStore(pool), sender: sender, now: time.Now}
}

// WithClock replaces the clock quiet hours are checked against.
func (n *Notifier) WithClock(now func() time.Time) *Notifier {
	n.now = now
	return n
}

// HandleNewMessageTask is the asynq handler for TypeNewMessage.
func (n *Notifier) HandleNewMessageTask(ctx context.Context, task *asynq.Task) error {
	var p newMessagePayload
	if err := json.Unmarshal(task.Payload(), &p); err != nil || p.MessageID == "" {
		return fmt.Errorf("%w: bad payload", asynq.SkipRetry)
	}
	return n.NotifyNewMessage(ctx, p.MessageID)
}

// shouldNotify is decided when the task runs, not when it is queued, so it
// sees the message after spam routing and automation rules: anything that left
// the Inbox or was read stays quiet for everyone. Category, starred-only and
// quiet hours are each reader's own settings (delivery.wants).
func shouldNotify(m *inbound.Message) bool {
	return m.Folder == "INBOX" && m.ReadAt == nil
}

// NotifyNewMessage sends the visible notification for one delivered message
// to every device of every user who can read its mailbox.
func (n *Notifier) NotifyNewMessage(ctx context.Context, messageID string) error {
	if n.sender == nil {
		return nil
	}
	m, err := n.inbound.MessageForPush(ctx, messageID)
	if errors.Is(err, inbound.ErrNoMailbox) {
		return nil
	}
	if err != nil {
		return err
	}
	if !shouldNotify(m) {
		return nil
	}
	now := n.now()
	return n.fanOut(ctx, m.MailboxID, func(user, slug string) (func(string, int) fcm.Message, error) {
		d, err := n.devices.deliverySettings(ctx, user, m.MailboxID)
		if err != nil || !d.wants(m, now) {
			return nil, err
		}
		return func(token string, badge int) fcm.Message {
			return NewMessagePush(token, slug, m, badge, d.privacy)
		}, nil
	})
}

// NotifyMailboxChanged sends a silent push so the app pulls /changes and
// updates its badge: a message was read, moved or deleted somewhere else.
// Notification settings do not apply: it shows nothing, and a muted mailbox
// still has to stay in sync.
func (n *Notifier) NotifyMailboxChanged(ctx context.Context, mailboxID string) error {
	if n.sender == nil {
		return nil
	}
	return n.fanOut(ctx, mailboxID, func(_, slug string) (func(string, int) fcm.Message, error) {
		return func(token string, badge int) fcm.Message { return SyncPush(token, slug, mailboxID, badge) }, nil
	})
}

// fanOut asks build, per reader, for a message constructor; nil skips that
// reader.
func (n *Notifier) fanOut(ctx context.Context, mailboxID string, build func(user, slug string) (func(token string, badge int) fcm.Message, error)) error {
	slug, users, err := n.inbound.MailboxReaders(ctx, mailboxID)
	if err != nil {
		return err
	}
	for _, user := range users {
		targets, err := n.devices.Targets(ctx, user)
		if err != nil {
			return err
		}
		if len(targets) == 0 {
			continue
		}
		msgFor, err := build(user, slug)
		if err != nil {
			return err
		}
		if msgFor == nil {
			continue
		}
		counts, err := n.inbound.UnreadCounts(ctx, user, nil)
		if err != nil {
			return err
		}
		for _, t := range targets {
			// Per-token failures never fail the task: the client already
			// retried transient errors, and a task retry would re-notify the
			// devices that did get it.
			err := n.sender.Send(ctx, msgFor(t.Token, counts["INBOX"]))
			switch {
			case errors.Is(err, fcm.ErrUnregistered):
				if err := n.devices.DisableToken(ctx, t.Token); err != nil {
					log.Printf("push: disable device %s: %v", t.DeviceID, err)
				}
			case err != nil:
				log.Printf("push: device %s: %v", t.DeviceID, err)
			}
		}
	}
	return nil
}

// NewMessagePush is the visible notification. `data` carries exactly the
// routing keys the app opens the message with. privacy hides the subject and
// preview; the sender stays.
func NewMessagePush(token, slug string, m *inbound.Message, badge int, privacy bool) fcm.Message {
	title := strings.TrimSpace(deref(m.FromName))
	if title == "" {
		title = strings.TrimSpace(deref(m.FromAddr))
	}
	if title == "" {
		title = "Новое письмо"
	}
	body := strings.TrimSpace(m.Subject)
	if body == "" {
		body = "(без темы)"
	}
	if p := preview(deref(m.TextBody), 140); p != "" {
		body += "\n" + p
	}
	if privacy {
		body = "Новое письмо"
	}
	return fcm.Message{
		Token:        token,
		Notification: &fcm.Notification{Title: title, Body: body},
		Data:         map[string]string{"workspace": slug, "mailbox_id": m.MailboxID, "message_id": m.ID},
		Android: &fcm.AndroidConfig{
			Priority:     "high",
			CollapseKey:  "mail-" + m.MailboxID,
			Notification: &fcm.AndroidNotification{ChannelID: AndroidChannel, Tag: m.ID},
		},
		APNS: &fcm.APNSConfig{
			Headers: map[string]string{"apns-collapse-id": m.ID, "apns-push-type": "alert", "apns-priority": "10"},
			Payload: map[string]any{"aps": map[string]any{
				"badge": badge, "thread-id": m.MailboxID, "mutable-content": 1, "sound": "default",
			}},
		},
	}
}

// SyncPush is data-only (content-available on iOS): no alert, the app wakes,
// pulls /changes and sets the badge.
func SyncPush(token, slug, mailboxID string, badge int) fcm.Message {
	return fcm.Message{
		Token: token,
		Data:  map[string]string{"type": "sync", "workspace": slug, "mailbox_id": mailboxID},
		Android: &fcm.AndroidConfig{
			Priority:    "normal",
			CollapseKey: "sync-" + mailboxID,
		},
		APNS: &fcm.APNSConfig{
			Headers: map[string]string{"apns-push-type": "background", "apns-priority": "5", "apns-collapse-id": "sync-" + mailboxID},
			Payload: map[string]any{"aps": map[string]any{"content-available": 1, "badge": badge}},
		},
	}
}

func preview(text string, n int) string {
	text = strings.Join(strings.Fields(text), " ")
	if utf8.RuneCountInString(text) <= n {
		return text
	}
	r := []rune(text)
	return strings.TrimSpace(string(r[:n])) + "…"
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ListenChanges sends silent pushes for mailbox changes, woken by the
// mailbox_changes NOTIFY that the sync triggers raise at commit — so it covers
// the web UI, IMAP, automation and deliveries alike. Bursts are coalesced per
// mailbox over debounce. Runs until ctx ends, reconnecting on failure.
func (n *Notifier) ListenChanges(ctx context.Context, debounce time.Duration) {
	if n.sender == nil {
		return
	}
	for ctx.Err() == nil {
		if err := n.listen(ctx, debounce); err != nil && ctx.Err() == nil {
			log.Printf("push: listen: %v; reconnecting", err)
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
			}
		}
	}
}

func (n *Notifier) listen(ctx context.Context, debounce time.Duration) error {
	conn, err := n.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `LISTEN mailbox_changes`); err != nil {
		return err
	}
	pending := map[string]bool{}
	var deadline time.Time
	for {
		wait := time.Hour
		if len(pending) > 0 {
			wait = time.Until(deadline)
		}
		waitCtx, cancel := context.WithTimeout(ctx, wait)
		note, err := conn.Conn().WaitForNotification(waitCtx)
		cancel()
		switch {
		case err == nil:
			if len(pending) == 0 {
				deadline = time.Now().Add(debounce)
			}
			pending[note.Payload] = true
			if time.Now().Before(deadline) {
				continue
			}
		case ctx.Err() != nil:
			return ctx.Err()
		case !errors.Is(err, context.DeadlineExceeded):
			// The connection is unusable; drop it rather than return it to the pool.
			conn.Conn().Close(context.Background())
			return err
		}
		for box := range pending {
			if err := n.NotifyMailboxChanged(ctx, box); err != nil {
				log.Printf("push: sync %s: %v", box, err)
			}
		}
		pending = map[string]bool{}
	}
}
