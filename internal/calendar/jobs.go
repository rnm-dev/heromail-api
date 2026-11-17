package calendar

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/email"
	"github.com/rnm/heromail/backend/internal/ratelimit"
)

type job struct {
	ID, EventID, Kind, Recipient, Actor, Response string
	Version, Attempts, ResponseVersion            int
}

// Dispatcher drains durable calendar jobs into the ordinary outbound queue.
// A stale claim is retried using the job ID as the email idempotency key.
type Dispatcher struct {
	pool    *pgxpool.Pool
	emails  *email.Service
	store   *Store
	limiter *ratelimit.Limiter
	pusher  ReminderPusher
}

func NewDispatcher(pool *pgxpool.Pool, emails *email.Service) *Dispatcher {
	return &Dispatcher{pool: pool, emails: emails, store: NewStore(pool)}
}
func (d *Dispatcher) WithLimiter(l *ratelimit.Limiter) *Dispatcher { d.limiter = l; return d }

// WithPusher also sends reminders as push notifications to the calendar
// owner's devices.
func (d *Dispatcher) WithPusher(p ReminderPusher) *Dispatcher { d.pusher = p; return d }

// Reminder is one push reminder about an occurrence, addressed to the owner of
// the calendar. StartAt is set for timed events, StartDate for all-day ones.
type Reminder struct {
	EventID, WorkspaceID, OwnerID string
	Title, Location               string
	StartAt                       *time.Time
	StartDate                     string
}

// ReminderPusher delivers a Reminder (push.CalendarReminders). An error means
// nothing was delivered and the job should be retried.
type ReminderPusher interface {
	PushReminder(ctx context.Context, r Reminder) error
}

// reminderGrace is how late after the start a reminder is still worth sending.
const reminderGrace = 5 * time.Minute

type quotaWait struct{ after time.Duration }

func (e quotaWait) Error() string { return "workspace send quota reached" }
func quotaLimit(name string, fallback int) int {
	n, err := strconv.Atoi(os.Getenv(name))
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func (d *Dispatcher) Run(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		for i := 0; i < 10; i++ {
			found, err := d.ProcessNext(ctx)
			if err != nil {
				log.Printf("calendar dispatcher: %v", err)
				break
			}
			if !found {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (d *Dispatcher) claim(ctx context.Context, eventID *string) (job, bool, error) {
	var j job
	err := d.pool.QueryRow(ctx, `WITH picked AS (
		SELECT id FROM calendar_jobs WHERE due_at<=now() AND attempts<8 AND ($1::uuid IS NULL OR event_id=$1)
		AND (status IN ('pending','failed') OR (status='processing' AND claimed_at<now()-interval '5 minutes'))
		ORDER BY due_at,id LIMIT 1 FOR UPDATE SKIP LOCKED)
		UPDATE calendar_jobs j SET status='processing',claimed_at=now(),attempts=j.attempts+1,updated_at=now()
		FROM picked WHERE j.id=picked.id RETURNING j.id,j.event_id,j.event_version,j.kind,j.recipient,j.actor,j.response,j.attempts,j.response_version`, eventID).Scan(&j.ID, &j.EventID, &j.Version, &j.Kind, &j.Recipient, &j.Actor, &j.Response, &j.Attempts, &j.ResponseVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return j, false, nil
	}
	return j, err == nil, err
}

func (d *Dispatcher) ProcessNext(ctx context.Context) (bool, error) {
	return d.processNext(ctx, nil)
}

// ProcessEvent is useful for a focused retry or integration check. The normal
// worker uses ProcessNext, which drains all due workspaces.
func (d *Dispatcher) ProcessEvent(ctx context.Context, eventID string) (bool, error) {
	return d.processNext(ctx, &eventID)
}
func (d *Dispatcher) processNext(ctx context.Context, eventID *string) (bool, error) {
	j, found, err := d.claim(ctx, eventID)
	if !found || err != nil {
		return found, err
	}
	if err = d.process(ctx, j); err != nil {
		var wait quotaWait
		if errors.As(err, &wait) {
			_, writeErr := d.pool.Exec(ctx, `UPDATE calendar_jobs SET status='pending',attempts=greatest(attempts-1,0),last_error=$2,due_at=now()+$3 * interval '1 second',updated_at=now() WHERE id=$1`, j.ID, err.Error(), max(30, int(wait.after.Seconds())+1))
			return true, writeErr
		}
		backoff := time.Duration(1<<min(j.Attempts, 6)) * time.Minute
		status := "failed"
		if j.Attempts >= 8 {
			status = "dead"
		}
		_, writeErr := d.pool.Exec(ctx, `UPDATE calendar_jobs SET status=$2,last_error=$3,due_at=now()+$4 * interval '1 second',updated_at=now() WHERE id=$1`, j.ID, status, err.Error(), int(backoff.Seconds()))
		if writeErr != nil {
			return true, fmt.Errorf("job %s: %v; record failure: %w", j.ID, err, writeErr)
		}
		return true, fmt.Errorf("job %s: %w", j.ID, err)
	}
	return true, nil
}

func (d *Dispatcher) process(ctx context.Context, j job) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	e, err := scan(tx.QueryRow(ctx, `SELECT `+columns+` FROM calendar_events e WHERE e.id=$1 FOR SHARE`, j.EventID))
	if errors.Is(err, ErrNotFound) {
		return d.skip(ctx, tx, j.ID)
	}
	if err != nil {
		return err
	}
	if e.Version != j.Version || (j.Kind != "cancel" && e.Status != "confirmed") {
		return d.skip(ctx, tx, j.ID)
	}
	if err = d.store.loadAttendees(ctx, tx, &e); err != nil {
		return err
	}
	if j.Kind == "request" {
		present := false
		for _, addr := range e.Attendees {
			if addr == j.Recipient {
				present = true
				break
			}
		}
		if !present {
			return d.skip(ctx, tx, j.ID)
		}
	}
	var ws, owner string
	err = tx.QueryRow(ctx, `SELECT c.workspace_id, c.user_id::text FROM calendars c JOIN calendar_events e ON e.calendar_id=c.id WHERE e.id=$1`, e.ID).Scan(&ws, &owner)
	if err != nil {
		return err
	}
	if e.RoomID != "" {
		e = withRoom(e, d.store.roomNames(ctx, ws))
	}
	if j.Kind == "reminder" {
		return d.remind(ctx, tx, j, e, ws, owner)
	}
	if err = d.mayMail(ctx, tx, ws, e); err != nil {
		return err
	}
	method := "REQUEST"
	subject := "Приглашение: " + e.Title
	if j.Kind == "cancel" {
		method = "CANCEL"
		subject = "Отмена встречи: " + e.Title
	}
	if j.Kind == "reply" {
		method = "REPLY"
		subject = "Ответ на приглашение: " + e.Title
	}
	text := e.Title + "\n" + HumanRange(e)
	if e.Location != "" {
		text += "\nМесто: " + e.Location
	}
	if e.Description != "" && j.Kind != "cancel" {
		text += "\n\n" + e.Description
	}
	if j.Kind == "reply" {
		text = fmt.Sprintf("%s: %s — %s", j.Actor, j.Response, e.Title)
	}
	if j.Kind == "request" {
		var token string
		if err = tx.QueryRow(ctx, `SELECT response_token::text FROM calendar_attendees WHERE event_id=$1 AND email=$2`, e.ID, j.Recipient).Scan(&token); err != nil {
			return err
		}
		base := strings.TrimRight(os.Getenv("APP_BASE_URL"), "/")
		if base == "" {
			return fmt.Errorf("APP_BASE_URL is not set")
		}
		text += "\nОтветить на приглашение: " + base + "/calendar/invite/" + token
	}
	req := email.SendRequest{From: e.Organizer, To: []string{j.Recipient}, Subject: subject, Text: text}
	if j.Kind != "reminder" {
		req.CalendarMethod = method
		attendee := j.Recipient
		if j.Kind == "reply" {
			attendee = j.Actor
		}
		req.CalendarICS = buildICS(e, method, attendee, j.Response)
	}
	// The sender guard admits a private mailbox only for its owner, so send as
	// the calendar owner already checked above, not as an anonymous worker.
	msg, err := d.emails.Send(account.ContextWithUser(ctx, &account.User{ID: owner}), ws, "calendar-job-"+j.ID, req)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE calendar_jobs SET status='queued',email_id=$2,last_error=NULL,updated_at=now() WHERE id=$1`, j.ID, msg.ID)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// errNoOrganizerMailbox means the organizer address can no longer send for
// the calendar owner.
var errNoOrganizerMailbox = errors.New("organizer mailbox is no longer available")

// mayMail checks that the calendar owner may still send as the organizer and
// that the workspace has send quota left.
func (d *Dispatcher) mayMail(ctx context.Context, tx pgx.Tx, ws string, e Event) error {
	var allowed bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mailboxes m JOIN domains dom ON dom.id=m.domain_id
		JOIN workspaces w ON w.id=coalesce(m.personal_workspace_id,dom.workspace_id)
		JOIN calendar_events ev ON ev.id=$3 JOIN calendars c ON c.id=ev.calendar_id
		WHERE w.id=$1 AND lower(m.local_part||'@'||dom.domain)=lower($2)
		AND dom.verified_at IS NOT NULL AND ((coalesce(m.owner_user_id,w.personal_owner_id) IS NULL AND NOT EXISTS(SELECT 1 FROM mailbox_members mx WHERE mx.mailbox_id=m.id)) OR coalesce(m.owner_user_id,w.personal_owner_id)=c.user_id OR EXISTS(SELECT 1 FROM mailbox_members mm WHERE mm.mailbox_id=m.id AND mm.user_id=c.user_id)))`, ws, e.Organizer, e.ID).Scan(&allowed)
	if err != nil {
		return err
	}
	if !allowed {
		return errNoOrganizerMailbox
	}
	if d.limiter != nil {
		for _, rule := range []ratelimit.Rule{{Name: "send:minute", Limit: quotaLimit("SEND_LIMIT_PER_MINUTE", 60), Window: time.Minute}, {Name: "send:day", Limit: quotaLimit("SEND_LIMIT_PER_DAY", 5000), Window: 24 * time.Hour}} {
			res := d.limiter.AllowStrict(ctx, rule, ws)
			if !res.Allowed {
				return quotaWait{after: res.RetryAfter}
			}
		}
	}
	return nil
}

// remind mails the organizer (when there is one) and pushes to the calendar
// owner's devices. A retry re-sends the mail under the same idempotency key;
// the push is only retried when no device got it. A reminder later than
// reminderGrace after the start is dropped. Series schedule their next one.
func (d *Dispatcher) remind(ctx context.Context, tx pgx.Tx, j job, series Event, ws, owner string) error {
	at := time.Unix(int64(j.ResponseVersion)*60, 0)
	e := atOccurrence(series, at)
	status, emailID := "queued", (*string)(nil)
	if start := occurrenceStart(e); time.Now().After(start.Add(reminderGrace)) {
		status = "skipped"
	} else {
		if e.Organizer != "" {
			switch err := d.mayMail(ctx, tx, ws, e); {
			case errors.Is(err, errNoOrganizerMailbox) && d.pusher != nil:
				log.Printf("calendar reminder %s: %v; push only", j.ID, err)
			case err != nil:
				return err
			default:
				text := e.Title + "\n" + HumanRange(e)
				if e.Location != "" {
					text += "\nМесто: " + e.Location
				}
				if e.Description != "" {
					text += "\n\n" + e.Description
				}
				req := email.SendRequest{From: e.Organizer, To: []string{j.Recipient}, Subject: "Напоминание: " + e.Title, Text: text}
				msg, err := d.emails.Send(account.ContextWithUser(ctx, &account.User{ID: owner}), ws, "calendar-job-"+j.ID, req)
				if err != nil {
					return err
				}
				emailID = &msg.ID
			}
		}
		if d.pusher != nil {
			r := Reminder{EventID: e.ID, WorkspaceID: ws, OwnerID: owner, Title: e.Title, Location: e.Location}
			if e.AllDay {
				r.StartDate = e.Start
			} else {
				r.StartAt = e.StartAt
			}
			if err := d.pusher.PushReminder(ctx, r); err != nil {
				return fmt.Errorf("reminder push: %w", err)
			}
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE calendar_jobs SET status=$2,email_id=$3,last_error=NULL,updated_at=now() WHERE id=$1`, j.ID, status, emailID); err != nil {
		return err
	}
	if series.RRule != "" {
		if next, ok := nextReminder(series, at); ok {
			if err := d.store.addReminder(ctx, tx, series, next); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

// occurrenceStart is when the occurrence begins; for all-day events the 09:00
// their reminders count from, so a morning reminder is not already late.
func occurrenceStart(e Event) time.Time {
	if !e.AllDay && e.StartAt != nil {
		return *e.StartAt
	}
	loc, err := Zone(e.Timezone)
	if err != nil {
		loc = time.UTC
	}
	t, _ := time.ParseInLocation("2006-01-02", e.Start, loc)
	return t.Add(9 * time.Hour)
}
func (d *Dispatcher) skip(ctx context.Context, tx pgx.Tx, id string) error {
	_, err := tx.Exec(ctx, `UPDATE calendar_jobs SET status='skipped',updated_at=now() WHERE id=$1`, id)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
