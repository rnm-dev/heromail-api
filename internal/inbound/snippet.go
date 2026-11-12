package inbound

import (
	"html"
	"regexp"
	"strings"
	"unicode/utf8"
)

// SnippetLength is how much of a message the list shows.
const SnippetLength = 200

var (
	invisibleHTML = regexp.MustCompile(`(?is)<(head|style|script|title)\b.*?</(head|style|script|title)\s*>|<!--.*?-->`)
	htmlTag       = regexp.MustCompile(`(?s)<[^>]*>`)
)

// Snippet is a short plain-text preview: the text part, or the HTML part with
// markup removed when there is no text part, whitespace collapsed and cut to
// SnippetLength characters. Only a bounded prefix of the body is examined.
func Snippet(m *Message) string {
	text := ""
	if m.TextBody != nil {
		text = prefix(*m.TextBody, 4*SnippetLength)
	}
	if strings.TrimSpace(text) == "" && m.HTMLBody != nil {
		h := prefix(*m.HTMLBody, 64<<10)
		h = invisibleHTML.ReplaceAllString(h, " ")
		text = html.UnescapeString(htmlTag.ReplaceAllString(h, " "))
	}
	text = strings.Join(strings.Fields(text), " ")
	if utf8.RuneCountInString(text) <= SnippetLength {
		return text
	}
	r := []rune(text)
	return strings.TrimSpace(string(r[:SnippetLength])) + "…"
}

// prefix cuts s to at most n bytes without splitting a UTF-8 sequence.
func prefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
