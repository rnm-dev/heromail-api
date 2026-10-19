package inbound

import (
	"context"
	"strings"
	"testing"
)

func mimeFixture(headers string) []byte {
	return []byte(strings.ReplaceAll(strings.TrimSpace(headers), "\n", "\r\n") + "\r\n\r\nbody\r\n")
}

func TestClassifyHeaders(t *testing.T) {
	cases := []struct {
		name, raw, from, subject, want string
	}{
		{"newsletter", "From: news@shop.kz\nList-Unsubscribe: <mailto:u@shop.kz>\nSubject: Скидки", "news@shop.kz", "Скидки", CategoryNewsletters},
		{"esp marketing", "From: reply@mail.example.ru\nX-Mailgun-Tag: promo\nSubject: Вебинар", "reply@mail.example.ru", "Вебинар", CategoryNewsletters},
		{"esp alert without unsubscribe", "From: noreply@po.atlassian.net\nFeedback-ID: 1:2\nSubject: Action required", "noreply@po.atlassian.net", "Action required", CategoryNotifications},
		{"bounce", "From: mailer-daemon@googlemail.com\nContent-Type: multipart/report; report-type=delivery-status; boundary=x\nSubject: Delivery Status Notification", "mailer-daemon@googlemail.com", "Delivery Status Notification", CategoryNotifications},
		{"auto submitted", "From: support@apple.com\nAuto-Submitted: auto-generated\nSubject: Thanks", "support@apple.com", "Thanks", CategoryNotifications},
		{"calendar reply", "From: b@kpmg.kz\nSubject: Accepted: Weekly Call", "b@kpmg.kz", "Accepted: Weekly Call", CategoryNotifications},
		{"underscore noreply", "From: no_reply@email.apple.com\nSubject: Review complete", "no_reply@email.apple.com", "Review complete", CategoryNotifications},
		{"government", "From: hr.enbek@enbek.gov.kz\nSubject: Уведомление", "hr.enbek@enbek.gov.kz", "Уведомление", CategoryNotifications},
		{"invitation from a person", "From: m@raison.finance\nSubject: Invitation: встреча", "m@raison.finance", "Invitation: встреча", CategoryPeople},
		{"reply", "From: max@bank.kz\nIn-Reply-To: <a@b>\nSubject: RE: проект", "max@bank.kz", "RE: проект", CategoryPeople},
		{"plain person", "From: max@bank.kz\nSubject: вопрос", "max@bank.kz", "вопрос", CategoryPeople},
	}
	for _, c := range cases {
		got, reason := classifyHeaders(mimeFixture(c.raw), c.from, c.subject)
		if got != c.want {
			t.Errorf("%s: got %s (%s), want %s", c.name, got, reason, c.want)
		}
	}
}

func TestDeliveryCategoryAndSenderCorrection(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	deliver := func(id, from, extra string) *Message {
		t.Helper()
		raw := mimeFixture("From: " + from + "\nTo: " + h.mailbox.Address + "\nMessage-ID: <" + id + "@t>\nSubject: hello\n" + extra)
		m, err := h.store.Deliver(ctx, DeliverParams{MailboxID: h.mailbox.ID, EnvelopeFrom: from, EnvelopeTo: h.mailbox.Address, Raw: raw})
		if err != nil {
			t.Fatalf("deliver: %v", err)
		}
		return m
	}
	first := deliver("n1", "digest@service.test", "List-Unsubscribe: <mailto:u@service.test>")
	if first.Category != CategoryNewsletters {
		t.Fatalf("first category = %s", first.Category)
	}
	colleague := deliver("c1", "anna@"+strings.SplitN(h.mailbox.Address, "@", 2)[1], "List-Unsubscribe: <mailto:u@x.test>")
	if colleague.Category != CategoryPeople {
		t.Fatalf("same-domain sender = %s", colleague.Category)
	}

	n, err := h.store.SetSenderCategory(ctx, h.mailbox.ID, first.ID, CategoryPeople, true)
	if err != nil || n != 1 {
		t.Fatalf("correct: %d %v", n, err)
	}
	second := deliver("n2", "Digest@Service.test", "List-Unsubscribe: <mailto:u@service.test>")
	if second.Category != CategoryPeople {
		t.Fatalf("remembered sender = %s", second.Category)
	}
	inbox, err := h.store.FilterMessages(ctx, h.mailbox.ID, "INBOX", "", 50, 0, false, false, "", CategoryNewsletters)
	if err != nil || len(inbox) != 0 {
		t.Fatalf("newsletters tab = %d %v", len(inbox), err)
	}

	// Backfill skips user choices; -all re-reads headers for the rest.
	if _, err := h.pool.Exec(ctx, `UPDATE messages SET category='people', category_reason='' WHERE id=$1`, colleague.ID); err != nil {
		t.Fatal(err)
	}
	counts, err := h.store.Reclassify(ctx, h.mailbox.ID, false, false)
	if err != nil || counts[CategoryPeople] != 1 || len(counts) != 1 {
		t.Fatalf("reclassify = %v %v", counts, err)
	}
}

func TestRuleCategoryCondition(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.store.SaveAutomation(ctx, h.mailbox.ID, Automation{Rules: []MailRule{{Name: "read ads", Enabled: true, Category: CategoryNewsletters, MarkRead: true}}}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := h.store.SaveAutomation(ctx, h.mailbox.ID, Automation{Version: 1, Rules: []MailRule{{Name: "x", Enabled: true, Category: "ads", MarkRead: true}}}); err == nil {
		t.Fatal("unknown category accepted")
	}
	for i, extra := range []string{"List-Id: <l.test>", ""} {
		raw := mimeFixture("From: a@ext.test\nTo: " + h.mailbox.Address + "\nMessage-ID: <r" + string(rune('0'+i)) + "@t>\nSubject: s\n" + extra)
		m, err := h.store.Deliver(ctx, DeliverParams{MailboxID: h.mailbox.ID, EnvelopeFrom: "a@ext.test", EnvelopeTo: h.mailbox.Address, Raw: raw})
		if err != nil {
			t.Fatal(err)
		}
		if (m.ReadAt != nil) != (i == 0) {
			t.Fatalf("message %d read=%v", i, m.ReadAt != nil)
		}
	}
}
