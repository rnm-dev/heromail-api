package smtp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"mime"
	"strings"
	"testing"
	"time"

	"github.com/rnm/heromail/backend/internal/provider"
)

func newTestSender(t *testing.T) (*Sender, *fakeSMTP) {
	t.Helper()

	fake := startFakeSMTP(t)
	host, port := fake.addr()
	s, err := New(Config{Host: host, Port: port, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, fake
}

func TestSendDeliversBothBodies(t *testing.T) {
	s, fake := newTestSender(t)

	msg := provider.Message{
		From:     "noreply@acme.com",
		To:       []string{"viktor@acme.com", "bob@acme.com"},
		Subject:  "Приглашение в Acme",
		TextBody: "plain version",
		HTMLBody: "<p>html version</p>",
		Headers:  map[string]string{"Reply-To": "support@acme.com"},
	}

	id, err := s.Send(context.Background(), msg)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.HasSuffix(id, "@acme.com") {
		t.Errorf("message id %q should carry the sender's domain", id)
	}

	got := fake.received()
	if len(got) != 1 {
		t.Fatalf("expected 1 message, got %d", len(got))
	}
	env := got[0]

	if env.from != "noreply@acme.com" {
		t.Errorf("envelope from = %q", env.from)
	}
	if len(env.to) != 2 || env.to[0] != "viktor@acme.com" || env.to[1] != "bob@acme.com" {
		t.Errorf("envelope to = %v", env.to)
	}

	// The returned id must be the one actually on the wire — that is the whole
	// contract for correlating later delivery events.
	if !strings.Contains(env.data, "Message-ID: <"+id+">") {
		t.Errorf("Message-ID header missing or different; want %q\n---\n%s", id, env.data)
	}

	// A non-ASCII subject has to be RFC 2047 encoded, not sent raw.
	subject := headerValue(env.data, "Subject")
	if strings.Contains(subject, "Приглашение") {
		t.Errorf("subject was sent unencoded: %q", subject)
	}
	decoded, err := new(mime.WordDecoder).DecodeHeader(subject)
	if err != nil {
		t.Fatalf("decode subject %q: %v", subject, err)
	}
	if decoded != "Приглашение в Acme" {
		t.Errorf("decoded subject = %q, want %q", decoded, "Приглашение в Acme")
	}

	if !strings.Contains(env.data, "multipart/alternative") {
		t.Errorf("expected multipart/alternative, got:\n%s", env.data)
	}
	if !strings.Contains(env.data, "text/plain") || !strings.Contains(env.data, "text/html") {
		t.Errorf("expected both body parts, got:\n%s", env.data)
	}
	if rt := headerValue(env.data, "Reply-To"); !strings.Contains(rt, "support@acme.com") {
		t.Errorf("Reply-To = %q, custom header was dropped", rt)
	}
}

func TestSendSingleBodyIsNotMultipart(t *testing.T) {
	s, fake := newTestSender(t)

	_, err := s.Send(context.Background(), provider.Message{
		From:     "noreply@acme.com",
		To:       []string{"viktor@acme.com"},
		Subject:  "text only",
		TextBody: "just text",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	data := fake.received()[0].data
	if strings.Contains(data, "multipart/alternative") {
		t.Errorf("single-body message should not be multipart:\n%s", data)
	}
	if !strings.Contains(data, "text/plain") {
		t.Errorf("expected text/plain part:\n%s", data)
	}
}

func TestSendSignsWithDKIMWhenProvided(t *testing.T) {
	s, fake := newTestSender(t)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	_, err = s.Send(context.Background(), provider.Message{
		From:     "noreply@acme.com",
		To:       []string{"viktor@acme.com"},
		Subject:  "signed",
		TextBody: "hello",
		DKIM:     &provider.DKIM{Domain: "acme.com", Selector: "hm2026", PrivateKeyDER: der},
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	data := fake.received()[0].data
	sig := headerValue(data, "DKIM-Signature")
	if sig == "" {
		t.Fatalf("no DKIM-Signature header:\n%s", data)
	}
	if !strings.Contains(sig, "d=acme.com") {
		t.Errorf("DKIM-Signature missing d=acme.com: %q", sig)
	}
	if !strings.Contains(sig, "s=hm2026") {
		t.Errorf("DKIM-Signature missing s=hm2026: %q", sig)
	}
}

func TestSendWithoutDKIMIsUnsigned(t *testing.T) {
	s, fake := newTestSender(t)

	_, err := s.Send(context.Background(), provider.Message{
		From: "noreply@acme.com", To: []string{"viktor@acme.com"}, TextBody: "hello",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if strings.Contains(fake.received()[0].data, "DKIM-Signature") {
		t.Error("a message with no DKIM key must not carry a signature")
	}
}

func TestSendRejectsAnUnparseableDKIMKey(t *testing.T) {
	s, fake := newTestSender(t)

	_, err := s.Send(context.Background(), provider.Message{
		From: "noreply@acme.com", To: []string{"viktor@acme.com"}, TextBody: "hello",
		DKIM: &provider.DKIM{Domain: "acme.com", Selector: "hm2026", PrivateKeyDER: []byte("not a key")},
	})
	if err == nil {
		t.Fatal("expected an error for an unparseable key")
	}
	if len(fake.received()) != 0 {
		t.Error("a message that fails to sign must not still go out unsigned")
	}
}

// The EHLO name is checked by receivers against the sending IP's PTR. Sending
// go-mail's default (os.Hostname(), e.g. "nid-01") announces a name that is not
// a FQDN, does not resolve, and cannot match a PTR — Gmail marks that down.
func TestSendAnnouncesTheConfiguredHELO(t *testing.T) {
	fake := startFakeSMTP(t)
	host, port := fake.addr()
	s, err := New(Config{Host: host, Port: port, Timeout: 5 * time.Second, HELO: "mail.acme.com"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := s.Send(context.Background(), provider.Message{
		From: "noreply@acme.com", To: []string{"viktor@acme.com"}, TextBody: "hi",
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if got := fake.lastHELO(); got != "mail.acme.com" {
		t.Errorf("EHLO name = %q, want mail.acme.com", got)
	}
}

func TestSendWithoutHELOFallsBackToTheHostname(t *testing.T) {
	s, fake := newTestSender(t)

	if _, err := s.Send(context.Background(), provider.Message{
		From: "noreply@acme.com", To: []string{"viktor@acme.com"}, TextBody: "hi",
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Not asserting the value — it is whatever the machine is called. Only
	// that we still greet, so an unset HELO degrades rather than breaks.
	if fake.lastHELO() == "" {
		t.Error("no EHLO name was sent at all")
	}
}

func TestSendRejectsInvalidMessages(t *testing.T) {
	s, fake := newTestSender(t)

	cases := map[string]provider.Message{
		"no recipients": {From: "a@acme.com", TextBody: "x"},
		"no bodies":     {From: "a@acme.com", To: []string{"b@acme.com"}},
		"empty from":    {To: []string{"b@acme.com"}, TextBody: "x"},
		"blank recipient": {
			From: "a@acme.com", To: []string{"  "}, TextBody: "x",
		},
		"reserved header": {
			From: "a@acme.com", To: []string{"b@acme.com"}, TextBody: "x",
			Headers: map[string]string{"Message-ID": "<forged@evil.com>"},
		},
	}

	for name, msg := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := s.Send(context.Background(), msg)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !errors.Is(err, provider.ErrInvalidMessage) {
				t.Errorf("error should wrap ErrInvalidMessage, got %v", err)
			}
		})
	}

	// Nothing invalid may reach the wire.
	if got := fake.received(); len(got) != 0 {
		t.Errorf("invalid messages were delivered: %d", len(got))
	}
}

func TestSendPropagatesDialFailure(t *testing.T) {
	// Port 1 on loopback: nothing listens, so the dial fails fast.
	s, err := New(Config{Host: "127.0.0.1", Port: 1, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = s.Send(context.Background(), provider.Message{
		From: "a@acme.com", To: []string{"b@acme.com"}, TextBody: "x",
	})
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if errors.Is(err, provider.ErrInvalidMessage) {
		t.Errorf("transport failure must not look like a caller error: %v", err)
	}
}

func TestNewValidatesConfig(t *testing.T) {
	if _, err := New(Config{Host: "", Port: 25}); err == nil {
		t.Error("empty host should be rejected")
	}
	if _, err := New(Config{Host: "mailpit", Port: 0}); err == nil {
		t.Error("zero port should be rejected")
	}
}

// headerValue pulls a single header out of a raw message, joining folded lines.
func headerValue(data, name string) string {
	lines := strings.Split(data, "\n")
	prefix := strings.ToLower(name) + ":"
	for i, line := range lines {
		if !strings.HasPrefix(strings.ToLower(line), prefix) {
			continue
		}
		value := strings.TrimSpace(line[len(prefix):])
		for _, next := range lines[i+1:] {
			if !strings.HasPrefix(next, " ") && !strings.HasPrefix(next, "\t") {
				break
			}
			value += strings.TrimRight(strings.TrimLeft(next, " \t"), "\r")
		}
		return strings.TrimRight(value, "\r")
	}
	return ""
}
