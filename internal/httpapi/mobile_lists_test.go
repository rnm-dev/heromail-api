package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rnm/heromail/backend/internal/inbound"
)

func (h *harness) doRange(method, path, token string, headers map[string]string) *httptest.ResponseRecorder {
	h.t.Helper()
	r := httptest.NewRequest(method, path, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("X-Forwarded-For", h.clientIP)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, r)
	return rec
}

func attachmentPart(contentType, filename string, data []byte) string {
	return "--b\r\nContent-Type: " + contentType + "\r\nContent-Disposition: attachment; filename=" + filename +
		"\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString(data) + "\r\n"
}

func TestAttachmentRangeAndHeaders(t *testing.T) {
	f := newSyncFixture(t, "attachment-range")
	photo := bytes.Repeat([]byte("0123456789"), 1000) // 10 000 bytes
	raw := "From: a@example.test\r\nSubject: files\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n" +
		attachmentPart("image/heic", "IMG_0001.HEIC", photo) +
		attachmentPart("text/html", "evil.html", []byte("<script>alert(1)</script>")) + "--b--\r\n"
	m, err := f.store.Deliver(t.Context(), inbound.DeliverParams{MailboxID: f.box, Raw: []byte(raw)})
	if err != nil {
		t.Fatal(err)
	}
	r := f.h.do(http.MethodGet, f.path+"/messages/"+m.ID, "", f.token)
	var detail ReceivedMessage
	json.Unmarshal(r.Body.Bytes(), &detail)
	if detail.Attachments == nil || len(*detail.Attachments) != 2 {
		t.Fatalf("attachments: %s", r.Body)
	}
	heic, html := (*detail.Attachments)[0], (*detail.Attachments)[1]
	url := f.path + "/messages/" + m.ID + "/attachments/"

	full := f.h.doRange(http.MethodGet, url+heic.Id, f.token, nil)
	etag := full.Header().Get("ETag")
	if full.Code != http.StatusOK || !bytes.Equal(full.Body.Bytes(), photo) || full.Header().Get("Accept-Ranges") != "bytes" ||
		full.Header().Get("Content-Type") != "image/heic" || full.Header().Get("Content-Length") != "10000" || etag == "" ||
		full.Header().Get("Content-Disposition") != "attachment; filename=IMG_0001.HEIC" {
		t.Fatalf("full download: %d %v", full.Code, full.Header())
	}
	// Active content is never served as itself.
	if r := f.h.doRange(http.MethodGet, url+html.Id, f.token, nil); r.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("html attachment served as %q", r.Header().Get("Content-Type"))
	}

	for _, c := range []struct {
		name    string
		headers map[string]string
		code    int
		body    []byte
		rangeH  string
	}{
		{"first bytes", map[string]string{"Range": "bytes=0-3"}, http.StatusPartialContent, photo[:4], "bytes 0-3/10000"},
		{"resume", map[string]string{"Range": "bytes=9990-"}, http.StatusPartialContent, photo[9990:], "bytes 9990-9999/10000"},
		{"suffix", map[string]string{"Range": "bytes=-5"}, http.StatusPartialContent, photo[9995:], "bytes 9995-9999/10000"},
		{"If-Range matches", map[string]string{"Range": "bytes=10-19", "If-Range": etag}, http.StatusPartialContent, photo[10:20], "bytes 10-19/10000"},
		{"If-Range stale", map[string]string{"Range": "bytes=10-19", "If-Range": `"stale"`}, http.StatusOK, photo, ""},
		{"unsatisfiable", map[string]string{"Range": "bytes=20000-"}, http.StatusRequestedRangeNotSatisfiable, nil, "bytes */10000"},
		{"not modified", map[string]string{"If-None-Match": etag}, http.StatusNotModified, nil, ""},
	} {
		r := f.h.doRange(http.MethodGet, url+heic.Id, f.token, c.headers)
		if r.Code != c.code || r.Header().Get("Content-Range") != c.rangeH {
			t.Errorf("%s: %d %q", c.name, r.Code, r.Header().Get("Content-Range"))
			continue
		}
		if c.body != nil && !bytes.Equal(r.Body.Bytes(), c.body) {
			t.Errorf("%s: wrong bytes", c.name)
		}
	}
	// Multiple ranges come back as multipart/byteranges.
	if r := f.h.doRange(http.MethodGet, url+heic.Id, f.token, map[string]string{"Range": "bytes=0-1,100-101"}); r.Code != http.StatusPartialContent ||
		!strings.HasPrefix(r.Header().Get("Content-Type"), "multipart/byteranges") {
		t.Fatalf("multi-range: %d %q", r.Code, r.Header().Get("Content-Type"))
	}
	// HEAD answers the size without the body.
	if r := f.h.doRange(http.MethodHead, url+heic.Id, f.token, nil); r.Code != http.StatusOK || r.Body.Len() != 0 || r.Header().Get("Content-Length") != "10000" {
		t.Fatalf("HEAD: %d %d %q", r.Code, r.Body.Len(), r.Header().Get("Content-Length"))
	}
	// Ranges apply to the original .eml too, and access rules are unchanged.
	if r := f.h.doRange(http.MethodGet, f.path+"/messages/"+m.ID+"/raw", f.token, map[string]string{"Range": "bytes=0-4"}); r.Code != http.StatusPartialContent || r.Body.String() != "From:" {
		t.Fatalf("raw range: %d %q", r.Code, r.Body)
	}
	stranger, _, _ := f.h.registerUser("range-stranger")
	if r := f.h.doRange(http.MethodGet, url+heic.Id, stranger, map[string]string{"Range": "bytes=0-3"}); r.Code != http.StatusNotFound {
		t.Fatalf("stranger range: %d", r.Code)
	}
}

func TestListSnippetAndCompact(t *testing.T) {
	f := newSyncFixture(t, "list-snippet")
	ctx := context.Background()
	long := strings.Repeat("слово ", 100)
	f.store.Deliver(ctx, inbound.DeliverParams{MailboxID: f.box, Raw: []byte("Subject: plain\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n  Hello,\r\n\r\n   team " + long)})
	f.store.Deliver(ctx, inbound.DeliverParams{MailboxID: f.box, Raw: []byte("Subject: html\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" +
		"<html><head><style>p{color:red}</style><title>T</title></head><body><p>Fish &amp; chips</p><!-- hidden --><script>x()</script><b>today</b></body></html>")})

	list := func(query string) map[string]ReceivedMessage {
		r := f.h.do(http.MethodGet, f.path+"/mailboxes/"+f.box+"/messages?"+query, "", f.token)
		var out struct {
			Messages []ReceivedMessage `json:"messages"`
		}
		if r.Code != http.StatusOK {
			t.Fatalf("list: %d %s", r.Code, r.Body)
		}
		json.Unmarshal(r.Body.Bytes(), &out)
		bySubject := map[string]ReceivedMessage{}
		for _, m := range out.Messages {
			bySubject[m.Subject] = m
		}
		return bySubject
	}

	full := list("")
	plain, html := full["plain"], full["html"]
	if !strings.HasPrefix(plain.Snippet, "Hello, team слово") || !strings.HasSuffix(plain.Snippet, "…") || len([]rune(plain.Snippet)) != inbound.SnippetLength+1 {
		t.Fatalf("plain snippet: %q", plain.Snippet)
	}
	if html.Snippet != "Fish & chips today" {
		t.Fatalf("html snippet: %q", html.Snippet)
	}
	// Default stays what the web client renders from.
	if plain.Text == nil || html.Html == nil {
		t.Fatal("default list lost its bodies")
	}
	compact := list("compact=true")
	if c := compact["plain"]; c.Text != nil || c.Html != nil || c.Snippet != plain.Snippet {
		t.Fatalf("compact: %+v", c)
	}
	if c := compact["html"]; c.Html != nil || c.Snippet != html.Snippet {
		t.Fatalf("compact html: %+v", c)
	}

	// The change feed carries the snippet too, and compact drops text there.
	r := f.h.do(http.MethodGet, fmt.Sprintf("%s/mailboxes/%s/changes?cursor=%s&compact=true", f.path, f.box, inbound.EncodeCursor(f.box, 0)), "", f.token)
	var changes MailboxChanges
	json.Unmarshal(r.Body.Bytes(), &changes)
	if r.Code != http.StatusOK || len(changes.Messages) != 2 {
		t.Fatalf("changes: %d %s", r.Code, r.Body)
	}
	for _, m := range changes.Messages {
		if m.Message.Text != nil || m.Message.Html != nil || m.Message.Snippet == "" {
			t.Fatalf("compact change: %+v", m.Message)
		}
	}
}
