package inbound

import (
	"bytes"
	"io"
	"mime"
	"net/mail"
	"strings"
	"time"

	gomessage "github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset"
)

// maxBodyBytes caps how much of one text part is kept. A message that is
// mostly one enormous body is still stored in full as `raw`; this only bounds
// what gets copied into a column for display.
const maxBodyBytes = 1 << 20

// parsed is what a message yields for the columns the list view reads.
type parsed struct {
	MessageID string
	FromAddr  string
	FromName  string
	Subject   string
	SentAt    *time.Time
	Text      string
	HTML      string
}

// parse extracts display fields from a raw message.
//
// It never fails. A message we have already accepted over LMTP has to be
// storable — refusing to keep mail because its headers are malformed would
// lose it, and malformed is exactly what spam and broken senders produce. Every
// field is best-effort, and `raw` is kept whole so anything missed here can be
// recovered by reparsing later.
func parse(raw []byte) parsed {
	var out parsed

	entity, err := gomessage.Read(bytes.NewReader(raw))
	if err != nil && entity == nil {
		// Not even the headers could be read. Fall back to the stricter
		// net/mail parser for the few fields it might still manage.
		if msg, err := mail.ReadMessage(bytes.NewReader(raw)); err == nil {
			out.Subject = decodeHeader(msg.Header.Get("Subject"))
			out.MessageID = strings.Trim(msg.Header.Get("Message-ID"), "<> ")
			out.FromAddr, out.FromName = splitAddress(msg.Header.Get("From"))
			out.SentAt = parseDate(msg.Header.Get("Date"))
		}
		return out
	}

	h := entity.Header
	out.Subject = decodeHeader(h.Get("Subject"))
	out.MessageID = strings.Trim(h.Get("Message-ID"), "<> ")
	out.FromAddr, out.FromName = splitAddress(h.Get("From"))
	out.SentAt = parseDate(h.Get("Date"))

	collectBodies(entity, &out)
	return out
}

// collectBodies walks the MIME tree, keeping the first text and the first HTML
// part it finds. Nested multiparts are followed; attachments are skipped —
// they are in `raw`, and extracting them into object storage is a later step.
func collectBodies(e *gomessage.Entity, out *parsed) {
	if mr := e.MultipartReader(); mr != nil {
		for {
			part, err := mr.NextPart()
			if err != nil {
				return
			}
			collectBodies(part, out)
			if out.Text != "" && out.HTML != "" {
				return
			}
		}
	}

	mediaType, _, err := e.Header.ContentType()
	if err != nil {
		mediaType = "text/plain"
	}
	if disp, _, _ := e.Header.ContentDisposition(); disp == "attachment" {
		return
	}

	switch mediaType {
	case "text/plain":
		if out.Text == "" {
			out.Text = readLimited(e.Body)
		}
	case "text/html":
		if out.HTML == "" {
			out.HTML = readLimited(e.Body)
		}
	}
}

func readLimited(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, maxBodyBytes))
	return string(b)
}

// decodeHeader turns an RFC 2047 encoded-word header into plain text. Subjects
// arrive base64'd in whatever charset the sender chose, and showing
// "=?UTF-8?B?..." in an inbox is not showing a subject.
func decodeHeader(v string) string {
	if v == "" {
		return ""
	}
	dec := new(mime.WordDecoder)
	dec.CharsetReader = charsetReader
	if out, err := dec.DecodeHeader(v); err == nil {
		return out
	}
	return v
}

func charsetReader(charset string, input io.Reader) (io.Reader, error) {
	// go-message registers the charsets it knows through its charset import;
	// anything else is passed through rather than failing the whole header.
	return gomessage.CharsetReader(charset, input)
}

// splitAddress pulls the address and display name out of a From header.
func splitAddress(v string) (addr, name string) {
	if v == "" {
		return "", ""
	}
	if a, err := mail.ParseAddress(decodeHeader(v)); err == nil {
		return strings.ToLower(a.Address), a.Name
	}
	// Unparseable: keep the raw value as the address rather than dropping the
	// only clue about who sent this.
	return strings.TrimSpace(v), ""
}

func parseDate(v string) *time.Time {
	if v == "" {
		return nil
	}
	if t, err := mail.ParseDate(v); err == nil {
		return &t
	}
	return nil
}
