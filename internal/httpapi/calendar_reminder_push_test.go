package httpapi

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rnm/heromail/backend/internal/calendar"
	"github.com/rnm/heromail/backend/internal/email"
	"github.com/rnm/heromail/backend/internal/push"
)

type reminderFixture struct {
	h          *harness
	ws, user   string
	addr       string
	token      string // the FCM token of the owner's phone
	fcm        *recordingFCM
	dispatcher *calendar.Dispatcher
}

func newReminderFixture(t *testing.T, name string) *reminderFixture {
	t.Helper()
	h := newHarness(t)
	session, user, addr := h.registerUser(name)
	ws := h.workspaceFor(session, name)
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	phone := h.loginAs(addr, androidClient)
	token := newPushToken()
	if r := h.do(http.MethodPut, "/devices/push", pushBody(token), phone.Token); r.Code != http.StatusOK {
		t.Fatalf("register device: %d %s", r.Code, r.Body)
	}
	rec := &recordingFCM{dead: map[string]bool{}}
	d := calendar.NewDispatcher(h.pool, email.NewService(email.NewStore(h.pool), h.queue, nil).WithDomainGuard(h.domains)).
		WithPusher(push.NewCalendarReminders(h.pool, rec))
	return &reminderFixture{h: h, ws: ws, user: user, addr: addr, token: token, fcm: rec, dispatcher: d}
}

func (f *reminderFixture) save(in calendar.Input, id string) calendar.Event {
	f.h.t.Helper()
	e, err := calendar.NewStore(f.h.pool).Save(f.h.t.Context(), f.ws, f.user, id, in)
	if err != nil {
		f.h.t.Fatal(err)
	}
	return e
}

// fire makes the event's reminders due and runs them.
func (f *reminderFixture) fire(eventID string) {
	f.h.t.Helper()
	if _, err := f.h.pool.Exec(f.h.t.Context(), `UPDATE calendar_jobs SET due_at=now() WHERE event_id=$1 AND kind='reminder'`, eventID); err != nil {
		f.h.t.Fatal(err)
	}
	for {
		ok, err := f.dispatcher.ProcessEvent(f.h.t.Context(), eventID)
		if err != nil {
			f.h.t.Fatal(err)
		}
		if !ok {
			return
		}
	}
}

func (f *reminderFixture) reminderStatus(eventID string, version int) string {
	var status string
	f.h.pool.QueryRow(f.h.t.Context(), `SELECT status FROM calendar_jobs WHERE event_id=$1 AND kind='reminder' AND event_version=$2`, eventID, version).Scan(&status)
	return status
}

func personalEvent(start time.Time, minutes int) calendar.Input {
	return calendar.Input{Title: "Standup", Location: "https://meet.google.com/abc-defg-hij", Timezone: "UTC",
		Start: start.Format("2006-01-02T15:04"), End: start.Add(30 * time.Minute).Format("2006-01-02T15:04"), ReminderMinutes: minutes}
}

func TestCalendarReminderPushForPersonalEvent(t *testing.T) {
	f := newReminderFixture(t, "reminder-push")
	start := time.Now().UTC().Add(10 * time.Minute).Truncate(time.Minute).Add(time.Minute)
	e := f.save(personalEvent(start, 10), "")
	var due time.Time
	if err := f.h.pool.QueryRow(t.Context(), `SELECT due_at FROM calendar_jobs WHERE event_id=$1 AND kind='reminder'`, e.ID).Scan(&due); err != nil {
		t.Fatalf("personal event has no reminder job: %v", err)
	}
	if !due.Equal(start.Add(-10 * time.Minute)) {
		t.Fatalf("due %v, want %v", due, start.Add(-10*time.Minute))
	}
	f.fire(e.ID)
	sent := f.fcm.take()
	if len(sent) != 1 || sent[0].Token != f.token {
		t.Fatalf("pushes %+v", sent)
	}
	m := sent[0]
	want := map[string]string{"type": "calendar_reminder", "event_id": e.ID, "workspace": f.h.slugFor(f.ws), "day": start.Format("2006-01-02")}
	if len(m.Data) != len(want) {
		t.Fatalf("data %v, want %v", m.Data, want)
	}
	for k, v := range want {
		if m.Data[k] != v {
			t.Fatalf("data[%s] = %q, want %q", k, m.Data[k], v)
		}
	}
	if m.Notification.Title != "Standup" || !strings.HasPrefix(m.Notification.Body, "через 1") || !strings.HasSuffix(m.Notification.Body, " мин · https://meet.google.com/abc-defg-hij") {
		t.Fatalf("notification %+v", m.Notification)
	}
	if m.Android.Notification.ChannelID != push.ReminderChannel {
		t.Fatalf("android %+v", m.Android)
	}
	if aps := m.APNS.Payload["aps"].(map[string]any); aps["interruption-level"] != nil {
		t.Fatalf("apns %+v", m.APNS)
	}
	if s := f.reminderStatus(e.ID, e.Version); s != "queued" {
		t.Fatalf("job status %s", s)
	}
}

func TestCalendarReminderPushSettingsAndStaleJobs(t *testing.T) {
	f := newReminderFixture(t, "reminder-push-settings")
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Minute)

	// A moved event drops the old reminder; a cancelled one drops all.
	e := f.save(personalEvent(start, 10), "")
	moved := personalEvent(start.Add(24*time.Hour), 10)
	moved.Version = e.Version
	f.save(moved, e.ID)
	f.fire(e.ID)
	if sent := f.fcm.take(); len(sent) != 1 || sent[0].Data["day"] != start.Add(24*time.Hour).Format("2006-01-02") {
		t.Fatalf("after move: %+v", sent)
	}
	if s := f.reminderStatus(e.ID, e.Version); s != "skipped" {
		t.Fatalf("old reminder %s", s)
	}
	gone := f.save(personalEvent(start, 10), "")
	if err := calendar.NewStore(f.h.pool).Delete(t.Context(), f.ws, f.user, gone.ID, gone.Version); err != nil {
		t.Fatal(err)
	}
	f.fire(gone.ID)
	if sent := f.fcm.take(); len(sent) != 0 {
		t.Fatalf("cancelled event pushed: %+v", sent)
	}

	// Privacy mode: no title or place anywhere.
	if _, err := f.h.pool.Exec(t.Context(), `INSERT INTO notification_settings(user_id,enabled,privacy) VALUES($1,true,true)`, f.user); err != nil {
		t.Fatal(err)
	}
	private := f.save(personalEvent(time.Now().UTC().Add(40*time.Minute).Truncate(time.Minute), 30), "")
	f.fire(private.ID)
	sent := f.fcm.take()
	if len(sent) != 1 {
		t.Fatalf("private pushes %d", len(sent))
	}
	if n := sent[0].Notification; n.Title != "Встреча" || !strings.HasPrefix(n.Body, "через ") || strings.Contains(n.Body, "meet") || len(sent[0].Data) != 4 {
		t.Fatalf("private push %+v", sent[0])
	}

	// Notifications off: nothing, and the job still completes.
	f.h.pool.Exec(t.Context(), `UPDATE notification_settings SET enabled=false WHERE user_id=$1`, f.user)
	off := f.save(personalEvent(start, 10), "")
	f.fire(off.ID)
	if sent := f.fcm.take(); len(sent) != 0 {
		t.Fatalf("disabled notifications pushed: %+v", sent)
	}
	if s := f.reminderStatus(off.ID, off.Version); s != "queued" {
		t.Fatalf("job status %s", s)
	}
	f.h.pool.Exec(t.Context(), `UPDATE notification_settings SET enabled=true WHERE user_id=$1`, f.user)

	// Reminders off on their own: no push either; omitting the field in a
	// save keeps it.
	session := f.h.loginAs(f.addr, androidClient)
	if r := f.h.do(http.MethodPut, "/me/notification-settings", `{"version":0,"enabled":true,"privacy":true,"calendar_reminders":false}`, session.Token); r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"calendar_reminders":false`) {
		t.Fatalf("save: %d %s", r.Code, r.Body)
	}
	if r := f.h.do(http.MethodPut, "/me/notification-settings", `{"version":1,"enabled":true,"privacy":true}`, session.Token); r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"calendar_reminders":false`) {
		t.Fatalf("save without the flag: %d %s", r.Code, r.Body)
	}
	muted := f.save(personalEvent(start, 10), "")
	f.fire(muted.ID)
	if sent := f.fcm.take(); len(sent) != 0 {
		t.Fatalf("muted reminders pushed: %+v", sent)
	}
	f.h.pool.Exec(t.Context(), `UPDATE notification_settings SET calendar_reminders=true WHERE user_id=$1`, f.user)

	// More than five minutes after the start is too late.
	late := f.save(personalEvent(time.Now().UTC().Add(time.Hour).Truncate(time.Minute), 10), "")
	f.h.pool.Exec(t.Context(), `UPDATE calendar_events SET start_at=now()-interval '10 minutes' WHERE id=$1`, late.ID)
	f.fire(late.ID)
	if sent := f.fcm.take(); len(sent) != 0 {
		t.Fatalf("late reminder pushed: %+v", sent)
	}
	if s := f.reminderStatus(late.ID, late.Version); s != "skipped" {
		t.Fatalf("late job status %s", s)
	}
}
