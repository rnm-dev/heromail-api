package inbound

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/mail"
	"regexp"
	"strings"

	gomessage "github.com/emersion/go-message"
)

// Presentation is derived only for an authorized detail request, never a list.
// Old messages benefit without rewriting their stored MIME or display columns.
type Presentation struct {
	ReplyTo     []string
	InlineMedia map[string]string
	Omitted     bool
	InReplyTo   string
	References  string
}

func (s *Store) Presentation(ctx context.Context, mailboxID, messageID string) (Presentation, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT raw FROM messages WHERE id=$1 AND mailbox_id=$2`, messageID, mailboxID).Scan(&raw)
	if err != nil {
		return Presentation{}, err
	}
	return Present(raw), nil
}

var messageIDPattern = regexp.MustCompile(`<[^<>\s\x00-\x1f\x7f]{1,898}>`)

func Present(raw []byte) Presentation {
	out := Presentation{ReplyTo: []string{}, InlineMedia: map[string]string{}}
	// Unknown charsets need not prevent decoding binary MIME siblings.
	e, _ := gomessage.Read(bytes.NewReader(raw))
	if e == nil {
		return out
	}
	for _, header := range []string{"Reply-To", "From"} {
		list, err := mail.ParseAddressList(decodeHeader(e.Header.Get(header)))
		if err == nil {
			for _, a := range list {
				if !strings.ContainsAny(a.Address, "\r\n") {
					out.ReplyTo = append(out.ReplyTo, a.Address)
				}
			}
		}
		if len(out.ReplyTo) > 0 {
			break
		}
	}
	ids := messageIDPattern.FindAllString(e.Header.Get("Message-ID"), -1)
	if len(ids) == 1 {
		out.InReplyTo = ids[0]
	}
	refs := messageIDPattern.FindAllString(e.Header.Get("References"), -1)
	if len(refs) == 0 {
		refs = messageIDPattern.FindAllString(e.Header.Get("In-Reply-To"), -1)
	}
	if out.InReplyTo != "" {
		refs = append(refs, out.InReplyTo)
	}
	// Bound generated headers; keep the immediate parent and the recent chain.
	for len(refs) > 0 && len(strings.Join(refs, " ")) > 900 {
		refs = refs[1:]
	}
	out.References = strings.Join(refs, " ")
	remaining, parts := 20<<20, 0
	var walk func(*gomessage.Entity, int)
	walk = func(p *gomessage.Entity, depth int) {
		parts++
		if depth > 32 || parts > 256 {
			out.Omitted = true
			return
		}
		if mr := p.MultipartReader(); mr != nil {
			defer mr.Close()
			for {
				child, err := mr.NextPart()
				if child != nil {
					walk(child, depth+1)
				}
				if err == io.EOF {
					break
				}
				if err != nil && child == nil {
					out.Omitted = true
					break
				}
				if parts > 256 {
					break
				}
			}
			return
		}
		cid := strings.Trim(p.Header.Get("Content-ID"), "<> \t")
		if cid == "" {
			return
		}
		mediaType, _, _ := p.Header.ContentType()
		switch mediaType {
		case "image/png", "image/jpeg", "image/gif", "image/webp", "audio/mpeg", "audio/ogg", "audio/wave", "audio/wav", "video/mp4", "video/webm":
		default:
			out.Omitted = true
			return
		}
		limit := min(8<<20, remaining)
		body, err := io.ReadAll(io.LimitReader(p.Body, int64(limit)+1))
		if err != nil || len(body) > limit {
			out.Omitted = true
			return
		}
		// Never promote HTML, SVG or other active documents to an inline resource.
		detected := http.DetectContentType(body)
		if strings.HasPrefix(mediaType, "image/") && detected != mediaType {
			out.Omitted = true
			return
		}
		if _, exists := out.InlineMedia[cid]; exists {
			return
		}
		remaining -= len(body)
		out.InlineMedia[cid] = "data:" + mediaType + ";base64," + base64.StdEncoding.EncodeToString(body)
	}
	walk(e, 0)
	return out
}
