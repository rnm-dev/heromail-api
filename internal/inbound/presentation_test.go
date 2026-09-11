package inbound

import (
	"encoding/base64"
	"strings"
	"testing"
)

const testPNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII="

func TestPresentationNestedMediaAndReply(t *testing.T) {
	raw := "From: Sender <from@example.test>\r\nReply-To: Help <help@example.test>, other@example.test\r\nMessage-ID: <parent@example.test>\r\nReferences: <first@example.test>\r\nContent-Type: multipart/related; boundary=outer\r\n\r\n--outer\r\nContent-Type: multipart/alternative; boundary=inner\r\n\r\n--inner\r\nContent-Type: text/plain\r\n\r\nplain\r\n--inner\r\nContent-Type: text/html\r\n\r\n<img src=\"cid:picture\">\r\n--inner--\r\n--outer\r\nContent-Type: image/png\r\nContent-ID: <picture>\r\nContent-Transfer-Encoding: base64\r\n\r\n" + testPNG + "\r\n--outer--\r\n"
	p := Present([]byte(raw))
	if len(p.ReplyTo) != 2 || p.ReplyTo[0] != "help@example.test" {
		t.Fatalf("reply: %v", p.ReplyTo)
	}
	if p.InReplyTo != "<parent@example.test>" || p.References != "<first@example.test> <parent@example.test>" {
		t.Fatalf("thread: %+v", p)
	}
	if p.InlineMedia["picture"] != "data:image/png;base64,"+testPNG || p.Omitted {
		t.Fatalf("media: %+v", p)
	}
}

func TestPresentationRejectsActiveAndOversizedParts(t *testing.T) {
	for _, tc := range []struct{ name, typ, body string }{
		{"svg", "image/svg+xml", "<svg onload='alert(1)'/>"},
		{"disguised html", "image/png", "<html><script>alert(1)</script></html>"},
		{"oversize", "image/png", strings.Repeat("x", (8<<20)+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := Present([]byte("Content-Type: " + tc.typ + "\r\nContent-ID: <bad>\r\n\r\n" + tc.body))
			if len(p.InlineMedia) != 0 || !p.Omitted {
				t.Fatal("unsafe media exposed")
			}
		})
	}
}

func TestPresentationHeadersAndUnknownCharset(t *testing.T) {
	p := Present([]byte("From: from@example.test\r\nReply-To: invalid\r\nMessage-ID: <safe@example.test>\r\nReferences: garbage\r\n Bcc: attacker@example.test\r\n\r\nbody"))
	if len(p.ReplyTo) != 1 || p.ReplyTo[0] != "from@example.test" || p.References != "<safe@example.test>" {
		t.Fatalf("headers: %+v", p)
	}
	body, _ := base64.StdEncoding.DecodeString(testPNG)
	raw := "Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain; charset=unknown-charset\r\n\r\ntext\r\n--x\r\nContent-Type: image/png\r\nContent-ID: <ok>\r\n\r\n" + string(body) + "\r\n--x--\r\n"
	if len(Present([]byte(raw)).InlineMedia) != 1 {
		t.Fatal("unknown text charset hid image sibling")
	}
}
