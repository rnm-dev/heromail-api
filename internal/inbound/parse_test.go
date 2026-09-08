package inbound

import (
	"strings"
	"testing"
)

func TestParseExtractsDisplayFields(t *testing.T) {
	raw := []byte(strings.ReplaceAll(`From: "Viktor Petrov" <viktor@acme.com>
To: sales@heromail.kz
Subject: =?UTF-8?B?0KHRh9GR0YIg4oSWNDI=?=
Message-ID: <abc123@acme.com>
Date: Mon, 02 Jan 2006 15:04:05 +0000
Content-Type: text/plain; charset=utf-8

Ваш счёт готов.
`, "\n", "\r\n"))

	got := parse(raw)

	// An RFC 2047 subject must be decoded, or the inbox shows "=?UTF-8?B?..."
	// instead of a subject.
	if got.Subject != "Счёт №42" {
		t.Errorf("subject = %q, want %q", got.Subject, "Счёт №42")
	}
	if got.FromAddr != "viktor@acme.com" {
		t.Errorf("from = %q", got.FromAddr)
	}
	if got.FromName != "Viktor Petrov" {
		t.Errorf("from name = %q", got.FromName)
	}
	if got.MessageID != "abc123@acme.com" {
		t.Errorf("message id = %q — the angle brackets should be stripped", got.MessageID)
	}
	if got.SentAt == nil || got.SentAt.Year() != 2006 {
		t.Errorf("sent at = %v", got.SentAt)
	}
	if !strings.Contains(got.Text, "Ваш счёт готов") {
		t.Errorf("text body = %q", got.Text)
	}
}

func TestParseKeepsBothAlternatives(t *testing.T) {
	raw := []byte(strings.ReplaceAll(`From: a@acme.com
Subject: both
Content-Type: multipart/alternative; boundary=xyz

--xyz
Content-Type: text/plain

plain version
--xyz
Content-Type: text/html

<p>html version</p>
--xyz--
`, "\n", "\r\n"))

	got := parse(raw)
	if !strings.Contains(got.Text, "plain version") {
		t.Errorf("text = %q", got.Text)
	}
	if !strings.Contains(got.HTML, "html version") {
		t.Errorf("html = %q", got.HTML)
	}
}

// An attachment part must not be mistaken for the body — otherwise a message
// whose first text part is an attached .txt shows the attachment as its
// content.
func TestParseSkipsAttachments(t *testing.T) {
	raw := []byte(strings.ReplaceAll(`From: a@acme.com
Subject: with attachment
Content-Type: multipart/mixed; boundary=xyz

--xyz
Content-Type: text/plain

the actual body
--xyz
Content-Type: text/plain; name="notes.txt"
Content-Disposition: attachment; filename="notes.txt"

attached file contents
--xyz--
`, "\n", "\r\n"))

	got := parse(raw)
	if strings.Contains(got.Text, "attached file contents") {
		t.Errorf("an attachment was used as the body: %q", got.Text)
	}
	if !strings.Contains(got.Text, "the actual body") {
		t.Errorf("text = %q", got.Text)
	}
}

// Mail we have already accepted over LMTP has to be storable whatever it looks
// like. Refusing to keep it would lose it, and malformed is what spam and
// broken senders produce.
func TestParseSurvivesGarbage(t *testing.T) {
	for name, raw := range map[string]string{
		"empty":       "",
		"no headers":  "just some text with no headers at all",
		"header only": "Subject: nothing else\r\n",
		"binary":      "\x00\x01\x02\xff\xfe",
		"broken mime": "Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nbroken",
		"bad date":    "Date: not a date\r\nFrom: <bad\r\n\r\nbody",
	} {
		t.Run(name, func(t *testing.T) {
			// The only requirement is that it returns rather than panicking.
			_ = parse([]byte(raw))
		})
	}
}

func TestSplitAddr(t *testing.T) {
	for _, tc := range []struct {
		in            string
		local, domain string
		ok            bool
	}{
		{"sales@heromail.kz", "sales", "heromail.kz", true},
		{"  Sales@Heromail.KZ  ", "sales", "heromail.kz", true},
		{"no-at-sign", "", "", false},
		{"@heromail.kz", "", "", false},
		{"sales@", "", "", false},
	} {
		local, domain, ok := splitAddr(tc.in)
		if ok != tc.ok || local != tc.local || domain != tc.domain {
			t.Errorf("splitAddr(%q) = %q, %q, %v; want %q, %q, %v",
				tc.in, local, domain, ok, tc.local, tc.domain, tc.ok)
		}
	}
}
