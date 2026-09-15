package inbound

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
	"unicode"
)

type ReceivedAttachment struct {
	ID       string `json:"id"`
	Filename string `json:"filename"`
	Size     int64  `json:"size_bytes"`
}

// Attachment parts are decoded from the immutable source. IDs are bounded MIME
// traversal positions, never paths supplied by the sender. Only the selected
// download is retained in memory; listing counts bytes without embedding files.
func ScanAttachments(raw []byte, selected string) (items []ReceivedAttachment, data []byte, incomplete bool) {
	items = []ReceivedAttachment{}
	root, _ := mail.ReadMessage(bytes.NewReader(raw))
	if root == nil {
		return items, nil, true
	}
	parts := 0
	var walk func(textproto.MIMEHeader, io.Reader, int)
	walk = func(header textproto.MIMEHeader, body io.Reader, depth int) {
		parts++
		if parts > 256 || depth > 32 {
			incomplete = true
			return
		}
		id := fmt.Sprint(parts)
		disposition, dp, _ := mime.ParseMediaType(header.Get("Content-Disposition"))
		contentType, cp, _ := mime.ParseMediaType(header.Get("Content-Type"))
		name := dp["filename"]
		if name == "" {
			name = cp["name"]
		}
		if strings.HasPrefix(contentType, "multipart/") {
			mr := multipart.NewReader(body, cp["boundary"])
			for parts <= 256 {
				child, err := mr.NextRawPart()
				if child != nil {
					walk(child.Header, child, depth+1)
				}
				if err == io.EOF {
					break
				}
				if err != nil && child == nil {
					incomplete = true
					break
				}
			}
			return
		}
		if disposition != "attachment" && name == "" {
			return
		}
		name = decodeHeader(name)
		name = strings.Map(func(r rune) rune {
			if unicode.IsControl(r) || r == '/' || r == '\\' {
				return '_'
			}
			return r
		}, name)
		if name == "" || name == "." || name == ".." {
			name = "attachment-" + id
		}
		if len([]rune(name)) > 200 {
			name = string([]rune(name)[:200])
		}
		switch strings.ToLower(strings.TrimSpace(header.Get("Content-Transfer-Encoding"))) {
		case "base64":
			body = base64.NewDecoder(base64.StdEncoding, body)
		case "quoted-printable":
			body = quotedprintable.NewReader(body)
		case "", "7bit", "8bit", "binary":
		default:
			incomplete = true
			return
		}
		reader := io.LimitReader(body, MaxMessageBytes+1)
		var size int64
		var err error
		if id == selected {
			data, err = io.ReadAll(reader)
			size = int64(len(data))
		} else {
			size, err = io.Copy(io.Discard, reader)
		}
		if err != nil || size > MaxMessageBytes {
			incomplete = true
			return
		}
		items = append(items, ReceivedAttachment{ID: id, Filename: name, Size: size})
	}
	walk(textproto.MIMEHeader(root.Header), root.Body, 0)
	return
}

func (s *Store) Attachment(ctx context.Context, mailboxID, messageID, id string) (ReceivedAttachment, []byte, error) {
	var raw []byte
	if err := s.pool.QueryRow(ctx, `SELECT raw FROM messages WHERE id=$1 AND mailbox_id=$2`, messageID, mailboxID).Scan(&raw); err != nil {
		return ReceivedAttachment{}, nil, err
	}
	items, data, _ := ScanAttachments(raw, id)
	for _, item := range items {
		if item.ID == id {
			return item, data, nil
		}
	}
	return ReceivedAttachment{}, nil, errors.New("attachment not found")
}
