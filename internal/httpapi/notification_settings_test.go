package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

func (f *syncFixture) settings(token string) (NotificationSettings, string) {
	f.h.t.Helper()
	r := f.h.do(http.MethodGet, "/me/notification-settings", "", token)
	if r.Code != http.StatusOK {
		f.h.t.Fatalf("get settings: %d %s", r.Code, r.Body)
	}
	var st NotificationSettings
	json.Unmarshal(r.Body.Bytes(), &st)
	return st, r.Header().Get("ETag")
}

func (f *syncFixture) saveSettings(token, ifMatch, body string) (int, NotificationSettings, string) {
	f.h.t.Helper()
	var rec interface {
		Result() *http.Response
	}
	if ifMatch != "" {
		rec = f.h.doWithHeader(http.MethodPut, "/me/notification-settings", body, token, "If-Match", ifMatch)
	} else {
		rec = f.h.do(http.MethodPut, "/me/notification-settings", body, token)
	}
	res := rec.Result()
	var st NotificationSettings
	json.NewDecoder(res.Body).Decode(&st)
	return res.StatusCode, st, res.Header.Get("ETag")
}

func TestNotificationSettingsDefaultsAndVersions(t *testing.T) {
	f := newSyncFixture(t, "notify-settings")

	st, etag := f.settings(f.token)
	if st.Version != 0 || etag != `"0"` || !st.Enabled || st.Privacy || st.QuietHours != nil || len(st.Mailboxes) != 1 {
		t.Fatalf("defaults: %+v etag %s", st, etag)
	}
	m := st.Mailboxes[0]
	if m.MailboxId.String() != f.box || !m.Enabled || m.StarredOnly || len(m.Categories) != 1 || m.Categories[0] != People || m.Workspace == "" {
		t.Fatalf("mailbox defaults: %+v", m)
	}

	body := fmt.Sprintf(`{"version":0,"enabled":true,"privacy":true,
		"quiet_hours":{"start":"22:00","end":"08:00","timezone":"Asia/Almaty"},
		"mailboxes":[{"mailbox_id":%q,"enabled":true,"categories":["people","newsletters","people"],"starred_only":true}]}`, f.box)
	code, saved, etag := f.saveSettings(f.token, `"0"`, body)
	if code != http.StatusOK || saved.Version != 1 || etag != `"1"` || !saved.Privacy ||
		saved.QuietHours == nil || saved.QuietHours.Start != "22:00" || saved.QuietHours.Timezone != "Asia/Almaty" {
		t.Fatalf("save: %d %+v %s", code, saved, etag)
	}
	if m := saved.Mailboxes[0]; len(m.Categories) != 2 || !m.StarredOnly {
		t.Fatalf("saved mailbox: %+v", m)
	}
	// A lost response: resending the same write is answered, not refused.
	if code, again, _ := f.saveSettings(f.token, "", body); code != http.StatusOK || again.Version != 1 {
		t.Fatalf("resend: %d %+v", code, again)
	}
	// A different write from the stale version is a conflict.
	stale := `{"version":0,"enabled":false,"privacy":false}`
	if code, _, _ := f.saveSettings(f.token, "", stale); code != http.StatusConflict {
		t.Fatalf("stale write: %d", code)
	}
	if code, _, _ := f.saveSettings(f.token, `"0"`, `{"version":1,"enabled":false,"privacy":false}`); code != http.StatusConflict {
		t.Fatalf("If-Match disagreeing with version: %d", code)
	}
	// Mailboxes not listed keep their settings; dropping quiet_hours turns them off.
	code, saved, _ = f.saveSettings(f.token, `"1"`, `{"version":1,"enabled":false,"privacy":false}`)
	if code != http.StatusOK || saved.Version != 2 || saved.Enabled || saved.QuietHours != nil || !saved.Mailboxes[0].StarredOnly {
		t.Fatalf("partial update: %d %+v", code, saved)
	}

	for name, bad := range map[string]string{
		"timezone": `{"version":2,"enabled":true,"privacy":false,"quiet_hours":{"start":"22:00","end":"08:00","timezone":"Mars/Base"}}`,
		"time":     `{"version":2,"enabled":true,"privacy":false,"quiet_hours":{"start":"25:00","end":"08:00","timezone":"UTC"}}`,
		"empty":    `{"version":2,"enabled":true,"privacy":false,"quiet_hours":{"start":"08:00","end":"08:00","timezone":"UTC"}}`,
		"category": fmt.Sprintf(`{"version":2,"enabled":true,"privacy":false,"mailboxes":[{"mailbox_id":%q,"enabled":true,"categories":["spam"],"starred_only":false}]}`, f.box),
	} {
		if code, _, _ := f.saveSettings(f.token, "", bad); code != http.StatusBadRequest {
			t.Fatalf("%s accepted: %d", name, code)
		}
	}
	if r := f.h.do(http.MethodGet, "/me/notification-settings", "", ""); r.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", r.Code)
	}
}

func TestNotificationSettingsHideOtherMailboxes(t *testing.T) {
	f := newSyncFixture(t, "notify-mine")
	other := newSyncFixture(t, "notify-theirs")

	st, _ := f.settings(f.token)
	for _, m := range st.Mailboxes {
		if m.MailboxId.String() == other.box {
			t.Fatal("another user's mailbox listed")
		}
	}
	body := fmt.Sprintf(`{"version":0,"enabled":true,"privacy":false,"mailboxes":[{"mailbox_id":%q,"enabled":false,"categories":[],"starred_only":false}]}`, other.box)
	if code, _, _ := f.saveSettings(f.token, "", body); code != http.StatusNotFound {
		t.Fatalf("changed another user's mailbox: %d", code)
	}
	if st, _ := other.settings(other.token); st.Version != 0 || !st.Mailboxes[0].Enabled {
		t.Fatalf("other user's settings touched: %+v", st)
	}
}

func TestPushHonoursNotificationSettings(t *testing.T) {
	f := newPushFixture(t, "notify-apply")
	ctx := context.Background()
	version := 0
	save := func(global, mailbox string) {
		t.Helper()
		body := fmt.Sprintf(`{"version":%d,%s,"mailboxes":[{"mailbox_id":%q,%s}]}`, version, global, f.box, mailbox)
		code, st, _ := f.saveSettings(f.syncFixture.token, "", body)
		if code != http.StatusOK {
			t.Fatalf("save %s: %d", body, code)
		}
		version = st.Version
	}
	pushed := func(raw string, prep func(id string)) []string {
		t.Helper()
		id := f.deliverRaw(raw)
		if prep != nil {
			prep(id)
		}
		if err := f.notifier.NotifyNewMessage(ctx, id); err != nil {
			t.Fatal(err)
		}
		var bodies []string
		for _, m := range f.fcm.take() {
			bodies = append(bodies, m.Notification.Body)
		}
		return bodies
	}
	person := "From: Alice <alice@example.test>\r\nSubject: Lunch\r\n\r\nAt noon?"
	asNewsletter := func(id string) { f.h.pool.Exec(ctx, `UPDATE messages SET category = 'newsletters' WHERE id = $1`, id) }
	starred := func(id string) {
		f.h.pool.Exec(ctx, `UPDATE messages SET imap_flags = array_append(imap_flags, '\Flagged') WHERE id = $1`, id)
	}

	save(`"enabled":false,"privacy":false`, `"enabled":true,"categories":["people"],"starred_only":false`)
	if b := pushed(person, nil); len(b) != 0 {
		t.Fatal("global switch off still pushed")
	}
	save(`"enabled":true,"privacy":false`, `"enabled":false,"categories":["people"],"starred_only":false`)
	if b := pushed(person, nil); len(b) != 0 {
		t.Fatal("muted mailbox pushed")
	}
	// Muted or not, the silent sync push still goes out.
	if err := f.notifier.NotifyMailboxChanged(ctx, f.box); err != nil {
		t.Fatal(err)
	}
	if s := f.fcm.take(); len(s) != 1 || s[0].Data["type"] != "sync" {
		t.Fatalf("silent push muted: %+v", s)
	}

	save(`"enabled":true,"privacy":false`, `"enabled":true,"categories":["newsletters"],"starred_only":false`)
	if b := pushed(person, nil); len(b) != 0 {
		t.Fatal("people pushed while only newsletters are on")
	}
	if b := pushed(person, asNewsletter); len(b) != 1 {
		t.Fatal("newsletter not pushed")
	}

	save(`"enabled":true,"privacy":true`, `"enabled":true,"categories":["people"],"starred_only":true`)
	if b := pushed(person, nil); len(b) != 0 {
		t.Fatal("unstarred message pushed in starred-only mode")
	}
	if b := pushed(person, starred); len(b) != 1 || b[0] != "Новое письмо" {
		t.Fatalf("privacy mode body: %v", b)
	}

	// Quiet hours 22:00–08:00 in Almaty (UTC+5): 23:30 local is quiet, 12:00 is not.
	save(`"enabled":true,"privacy":false,"quiet_hours":{"start":"22:00","end":"08:00","timezone":"Asia/Almaty"}`,
		`"enabled":true,"categories":["people"],"starred_only":false`)
	f.notifier.WithClock(func() time.Time { return time.Date(2026, 11, 12, 18, 30, 0, 0, time.UTC) })
	if b := pushed(person, nil); len(b) != 0 {
		t.Fatal("pushed during quiet hours")
	}
	f.notifier.WithClock(func() time.Time { return time.Date(2026, 11, 12, 7, 0, 0, 0, time.UTC) })
	if b := pushed(person, nil); len(b) != 1 || b[0] != "Lunch\nAt noon?" {
		t.Fatalf("outside quiet hours: %v", b)
	}
}
