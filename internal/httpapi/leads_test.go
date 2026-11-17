package httpapi

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rnm/heromail/backend/internal/account"
)

// leadHarness is the usual harness with a sales address: the shared one has
// none, and the form's endpoint needs somewhere to send. The inbox is unique
// per harness, like clientIP, so its hourly cap never spills between runs.
func leadHarness(t *testing.T, inbox string) *harness {
	t.Helper()
	h := newHarness(t)
	leadsTo := ""
	if inbox != "" {
		leadsTo = fmt.Sprintf("%s-%d@test", inbox, time.Now().UnixNano())
	}
	h.server.accounts = account.NewService(account.NewStore(h.pool), h.mail, account.Config{
		AppBaseURL: "https://app.test",
		MailFrom:   "noreply@test",
		LeadsTo:    leadsTo,
	})
	return h
}

func TestLeadIsEmailedToSalesWithReplyTo(t *testing.T) {
	h := leadHarness(t, "sales")
	h.mail.reset()

	rec := h.do(http.MethodPost, "/leads", `{"name":" Айгерим\r\nBcc: x@evil.test ","email":"lead@company.test","company":"ТОО Ромашка","domain":"Company.KZ","mailboxes":"11-50","message":"Нужна почта\nдля отдела продаж"}`, "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d, want 202: %s", rec.Code, rec.Body)
	}
	msg, ok := h.mail.last()
	if !ok {
		t.Fatal("the lead was not emailed")
	}
	if len(msg.To) != 1 || msg.To[0] != h.server.accounts.LeadsTo() {
		t.Errorf("To = %v, want the sales address", msg.To)
	}
	if got := msg.Headers["Reply-To"]; got != "lead@company.test" {
		t.Errorf("Reply-To = %q, want the lead's address", got)
	}
	if msg.Subject != "Заявка на подключение: ТОО Ромашка" {
		t.Errorf("Subject = %q", msg.Subject)
	}
	for _, want := range []string{"Имя: Айгерим Bcc: x@evil.test\n", "Домен: company.kz\n", "Ящиков: 11-50\n", "Нужна почта\nдля отдела продаж"} {
		if !strings.Contains(msg.TextBody, want) {
			t.Errorf("body lacks %q:\n%s", want, msg.TextBody)
		}
	}
}

func TestLeadValidationAndHoneypot(t *testing.T) {
	h := leadHarness(t, "sales")
	h.mail.reset()

	for name, body := range map[string]string{
		"no name":        `{"name":"  ","email":"lead@company.test"}`,
		"bad email":      `{"name":"A","email":"not-an-address"}`,
		"header in mail": `{"name":"A","email":"a@b.test\r\nBcc: x@evil.test"}`,
		"bad mailboxes":  `{"name":"A","email":"lead@company.test","mailboxes":"many"}`,
		"long message":   `{"name":"A","email":"lead@company.test","message":"` + strings.Repeat("я", 2001) + `"}`,
	} {
		if rec := h.do(http.MethodPost, "/leads", body, ""); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, rec.Code)
		}
	}
	// A bot that fills the hidden field is told all went well and sends nothing.
	if rec := h.do(http.MethodPost, "/leads", `{"name":"Bot","email":"bot@spam.test","website":"https://spam.test"}`, ""); rec.Code != http.StatusAccepted {
		t.Errorf("honeypot: status %d, want 202", rec.Code)
	}
	if n := h.mail.count(); n != 0 {
		t.Errorf("%d emails were sent for rejected and bot requests, want 0", n)
	}
}

func TestLeadWithoutSalesAddressIsUnavailable(t *testing.T) {
	h := leadHarness(t, "")
	rec := h.do(http.MethodPost, "/leads", `{"name":"A","email":"lead@company.test"}`, "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503 so the page offers the direct address", rec.Code)
	}
	if code := errorCode(t, rec); code != "mail_unavailable" {
		t.Errorf("error code = %q, want mail_unavailable", code)
	}
}

func TestLeadIsRateLimitedPerIP(t *testing.T) {
	h := leadHarness(t, "sales")
	requireLimiter(t, h)

	for i := 1; i <= 5; i++ {
		if rec := h.do(http.MethodPost, "/leads", `{"name":"A","email":"lead@company.test"}`, ""); rec.Code != http.StatusAccepted {
			t.Fatalf("request %d: status %d, want 202", i, rec.Code)
		}
	}
	if rec := h.do(http.MethodPost, "/leads", `{"name":"A","email":"lead@company.test"}`, ""); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the sixth request returned %d, want 429", rec.Code)
	}
}
