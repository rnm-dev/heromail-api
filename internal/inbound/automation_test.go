package inbound

import (
	"testing"
	"time"
)

func TestVacationEligibility(t *testing.T) {
	base := "From: sender@example.test\r\nTo: me@example.test\r\nSubject: Hello\r\n"
	for _, tc := range []struct {
		name, extra, envelope string
		want                  bool
	}{
		{"ordinary", "", "sender@example.test", true},
		{"null sender", "", "", false},
		{"self", "", "me@example.test", false},
		{"bounce", "", "MAILER-DAEMON@example.test", false},
		{"auto generated", "Auto-Submitted: auto-generated\r\n", "sender@example.test", false},
		{"auto replied", "Auto-Submitted: auto-replied\r\n", "sender@example.test", false},
		{"explicit no", "Auto-Submitted: no\r\n", "sender@example.test", true},
		{"duplicate auto", "Auto-Submitted: no\r\nAuto-Submitted: auto-replied\r\n", "sender@example.test", false},
		{"list", "List-Id: list.example.test\r\n", "sender@example.test", false},
		{"bulk", "Precedence: bulk\r\n", "sender@example.test", false},
		{"suppressed", "X-Auto-Response-Suppress: OOF\r\n", "sender@example.test", false},
		{"dsn", "Content-Type: multipart/report; boundary=x; report-type=delivery-status\r\n", "sender@example.test", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := vacationRecipient([]byte(base+tc.extra+"\r\ntext"), tc.envelope, "me@example.test")
			if (got != "") != tc.want {
				t.Fatalf("recipient=%q", got)
			}
		})
	}
	if got := vacationRecipient([]byte("From: sender@example.test\r\nTo: hidden@example.test\r\n\r\nbody"), "sender@example.test", "me@example.test"); got != "" {
		t.Fatal("Bcc or alias disclosed vacation")
	}
	if got := vacationRecipient([]byte(base+"Reply-To: victim@example.test\r\n\r\ntext"), "sender@example.test", "me@example.test"); got != "sender@example.test" {
		t.Fatal("used untrusted Reply-To")
	}
	now := time.Now()
	before := now.Add(-time.Hour)
	after := now.Add(time.Hour)
	if !(Vacation{Enabled: true, Start: &before, End: &after}).Active(now) || (Vacation{Enabled: true, Start: &after}).Active(now) || (Vacation{Enabled: true, End: &before}).Active(now) {
		t.Fatal("vacation boundaries")
	}
}
