package push

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rnm/heromail/backend/internal/calendar"
	"github.com/rnm/heromail/backend/internal/fcm"
)

// ReminderChannel is the Android notification channel for meeting reminders.
const ReminderChannel = "calendar_reminders"

// CalendarReminders pushes meeting reminders to the calendar owner's devices.
// The global switch, calendar_reminders and privacy mode apply; quiet hours do not, the reminder
// is something the user asked for at that time. A nil sender drops reminders.
type CalendarReminders struct {
	devices *Store
	sender  Sender
	now     func() time.Time
}

func NewCalendarReminders(pool *pgxpool.Pool, sender Sender) *CalendarReminders {
	return &CalendarReminders{devices: NewStore(pool), sender: sender, now: time.Now}
}

// WithClock replaces the clock the "in N min" text is computed against.
func (c *CalendarReminders) WithClock(now func() time.Time) *CalendarReminders {
	c.now = now
	return c
}

// PushReminder fails only when no device got the reminder because of an
// error other than a dead token, so the calendar job retries it.
func (c *CalendarReminders) PushReminder(ctx context.Context, r calendar.Reminder) error {
	if c.sender == nil {
		return nil
	}
	enabled, privacy, err := c.devices.reminderSettings(ctx, r.OwnerID)
	if err != nil || !enabled {
		return err
	}
	targets, err := c.devices.Targets(ctx, r.OwnerID)
	if err != nil {
		return err
	}
	delivered, failed := 0, error(nil)
	for _, t := range targets {
		err := c.sender.Send(ctx, ReminderPush(t.Token, r, c.now(), privacy))
		switch {
		case err == nil:
			delivered++
		case errors.Is(err, fcm.ErrUnregistered):
			if err := c.devices.DisableToken(ctx, t.Token); err != nil {
				log.Printf("push: disable device %s: %v", t.DeviceID, err)
			}
		default:
			log.Printf("push: reminder to device %s: %v", t.DeviceID, err)
			failed = err
		}
	}
	if delivered == 0 && failed != nil {
		return failed
	}
	return nil
}

// reminderSettings: reminders push when both the global switch and
// calendar_reminders are on; no row means defaults.
func (s *Store) reminderSettings(ctx context.Context, userID string) (enabled, privacy bool, err error) {
	err = s.pool.QueryRow(ctx, `SELECT enabled AND calendar_reminders, privacy FROM notification_settings WHERE user_id = $1`, userID).Scan(&enabled, &privacy)
	if errors.Is(err, pgx.ErrNoRows) {
		return true, false, nil
	}
	return enabled, privacy, err
}

// ReminderPush is the visible reminder. data carries only what the app
// routes with (MAL-38): it opens /calendar/event/<workspace>/<event_id>?day=.
// Privacy mode titles it "Встреча" and leaves the place out.
func ReminderPush(token string, r calendar.Reminder, now time.Time, privacy bool) fcm.Message {
	body := "сегодня, весь день"
	if r.StartAt != nil {
		body = inMinutes(r.StartAt.Sub(now))
	}
	title := strings.TrimSpace(r.Title)
	if title == "" || privacy {
		title = "Встреча"
	}
	if !privacy && r.Location != "" {
		body += " · " + r.Location
	}
	tag := "reminder-" + r.EventID
	return fcm.Message{
		Token:        token,
		Notification: &fcm.Notification{Title: title, Body: body},
		Data:         map[string]string{"type": "calendar_reminder", "workspace": r.Workspace, "event_id": r.EventID, "day": r.Day},
		Android: &fcm.AndroidConfig{
			Priority:     "high",
			Notification: &fcm.AndroidNotification{ChannelID: ReminderChannel, Tag: tag},
		},
		// No time-sensitive interruption level: the app lacks the entitlement.
		APNS: &fcm.APNSConfig{
			Headers: map[string]string{"apns-collapse-id": tag, "apns-push-type": "alert", "apns-priority": "10"},
			Payload: map[string]any{"aps": map[string]any{"sound": "default", "thread-id": "calendar"}},
		},
	}
}

// inMinutes renders the time left: "через 10 мин", "через 1 ч", "сейчас".
func inMinutes(d time.Duration) string {
	m := int((d + 30*time.Second) / time.Minute)
	switch {
	case m <= 0:
		return "сейчас"
	case m%60 == 0:
		return fmt.Sprintf("через %d ч", m/60)
	case m > 60:
		return fmt.Sprintf("через %d ч %d мин", m/60, m%60)
	}
	return fmt.Sprintf("через %d мин", m)
}
