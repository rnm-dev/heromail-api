package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/ratelimit"
)

// Remote MCP server (Streamable HTTP, JSON responses only) at POST /mcp, for
// claude.ai custom connectors and other remote MCP clients. Authentication is
// an OAuth access token (oauth.go) bound to one mailbox.
//
// Tools do not reach the database themselves: each one calls the regular API
// in-process as the token's user, so every permission rule of the web client
// applies, and is additionally confined to the granted mailbox.

const mcpServerVersion = "1.0.0"

var mcpProtocolVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// toolError is a failure the assistant should see and can act on.
type toolError string

func (e toolError) Error() string { return string(e) }

// mcpCall is one tool invocation: the principal plus a way into the API.
type mcpCall struct {
	ctx       context.Context
	p         oauthPrincipal
	user      *account.User
	generated http.Handler
}

func (s *Server) mcpHandler(accounts *account.Service, generated http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := s.oauthBearer(r.Context(), r.Header.Get("Authorization"))
		if err != nil {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource", error="invalid_token"`, publicAPIURL(r)))
			writeErrorEnvelope(w, http.StatusUnauthorized, "unauthenticated", "a valid OAuth access token is required")
			return
		}
		if r.Method != http.MethodPost {
			// No server-initiated stream: every answer comes in the POST response.
			w.Header().Set("Allow", "POST")
			writeErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
			return
		}
		if s.limiter != nil && !s.limiter.AllowStrict(r.Context(), ratelimit.Rule{Name: "mcp:grant", Limit: 240, Window: time.Minute}, p.GrantID).Allowed {
			writeErrorEnvelope(w, http.StatusTooManyRequests, "rate_limited", "too many MCP requests")
			return
		}
		user, err := accounts.UserByID(r.Context(), p.UserID)
		if err != nil {
			writeErrorEnvelope(w, http.StatusUnauthorized, "unauthenticated", "account not available")
			return
		}
		var req mcpRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || req.JSONRPC != "2.0" || req.Method == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"jsonrpc": "2.0", "id": nil, "error": mcpError{-32700, "expected one JSON-RPC 2.0 message"}})
			return
		}
		if len(req.ID) == 0 {
			// Notifications (initialized, cancelled) need no answer.
			w.WriteHeader(http.StatusAccepted)
			return
		}
		call := &mcpCall{ctx: r.Context(), p: p, user: user, generated: generated}
		result, rpcErr := call.dispatch(req)
		out := map[string]any{"jsonrpc": "2.0", "id": req.ID}
		if rpcErr != nil {
			out["error"] = rpcErr
		} else {
			out["result"] = result
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func (c *mcpCall) dispatch(req mcpRequest) (any, *mcpError) {
	switch req.Method {
	case "initialize":
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		json.Unmarshal(req.Params, &params)
		version := mcpProtocolVersions[0]
		for _, v := range mcpProtocolVersions {
			if v == params.ProtocolVersion {
				version = v
			}
		}
		return map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "heromail", "title": "Heromail", "version": mcpServerVersion},
			"instructions": "Heromail mailbox " + c.p.Address + ": read, search, organize and send mail, and use its calendar. " +
				"Message ids come from list_messages/search_messages. Dates are ISO 8601.",
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": mcpTools}, nil
	case "tools/call":
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, &mcpError{-32602, "invalid params"}
		}
		tool, ok := mcpHandlers[params.Name]
		if !ok {
			return nil, &mcpError{-32602, "unknown tool " + params.Name}
		}
		args := map[string]any{}
		if len(params.Arguments) > 0 && string(params.Arguments) != "null" {
			if err := json.Unmarshal(params.Arguments, &args); err != nil {
				return nil, &mcpError{-32602, "arguments must be an object"}
			}
		}
		res, err := tool(c, args)
		if err != nil {
			var te toolError
			if !errors.As(err, &te) {
				log.Printf("mcp %s: %v", params.Name, err)
				err = toolError("internal error")
			}
			return map[string]any{"content": []any{map[string]string{"type": "text", "text": err.Error()}}, "isError": true}, nil
		}
		var text bytes.Buffer
		enc := json.NewEncoder(&text)
		enc.SetEscapeHTML(false) // "Name <a@b>" stays readable and short
		enc.Encode(res)
		return map[string]any{"content": []any{map[string]string{"type": "text", "text": strings.TrimSpace(text.String())}}}, nil
	}
	return nil, &mcpError{-32601, "method not found: " + req.Method}
}

// api calls the regular API as the token's user and decodes a JSON reply.
func (c *mcpCall) api(method, path string, query url.Values, body any, out any) error {
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	}
	target := path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	req := httptest.NewRequestWithContext(c.ctx, method, target, reader)
	req.Header.Set("Content-Type", "application/json")
	if method == http.MethodPost && strings.HasSuffix(path, "/emails") {
		req.Header.Set("Idempotency-Key", uuid.NewString())
	}
	rec := httptest.NewRecorder()
	c.generated.ServeHTTP(rec, account.WithUser(req, c.user))
	if rec.Code >= 300 {
		var envelope struct {
			Error struct{ Message string } `json:"error"`
		}
		json.Unmarshal(rec.Body.Bytes(), &envelope)
		if envelope.Error.Message == "" {
			envelope.Error.Message = http.StatusText(rec.Code)
		}
		if rec.Code >= 500 {
			return fmt.Errorf("%s %s: %d %s", method, path, rec.Code, envelope.Error.Message)
		}
		return toolError(envelope.Error.Message)
	}
	if out == nil || rec.Code == http.StatusNoContent {
		return nil
	}
	return json.Unmarshal(rec.Body.Bytes(), out)
}

func (c *mcpCall) ws(rest string) string { return "/workspaces/" + url.PathEscape(c.p.Slug) + rest }

// message loads one message and proves it belongs to the granted mailbox.
func (c *mcpCall) message(id string) (map[string]any, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, toolError("message id must be a UUID from list_messages or search_messages")
	}
	var m map[string]any
	if err := c.api(http.MethodGet, c.ws("/messages/"+id), nil, nil, &m); err != nil {
		return nil, err
	}
	if m["mailbox_id"] != c.p.MailboxID {
		return nil, toolError("message not found")
	}
	return m, nil
}

// --- argument helpers ---

func argString(args map[string]any, key string) string {
	if v, ok := args[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func argBool(args map[string]any, key string) (bool, bool) {
	v, ok := args[key].(bool)
	return v, ok
}

func argInt(args map[string]any, key string, def, min, max int) int {
	n := def
	switch v := args[key].(type) {
	case float64:
		n = int(v)
	case string:
		if i, err := strconv.Atoi(v); err == nil {
			n = i
		}
	}
	return clampInt(n, min, max)
}

func clampInt(n, lo, hi int) int {
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

// argList accepts a JSON array or a comma-separated string.
func argList(args map[string]any, key string) []string {
	var out []string
	switch v := args[key].(type) {
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
	case string:
		for _, s := range strings.Split(v, ",") {
			if strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
	}
	return out
}

// --- shaping results: small, so they cost the assistant little context ---

func briefMessage(m map[string]any) map[string]any {
	out := map[string]any{"id": m["id"], "subject": m["subject"], "date": m["received_at"], "folder": m["folder"]}
	from, _ := m["from"].(string)
	if name, _ := m["from_name"].(string); name != "" {
		from = name + " <" + from + ">"
	}
	out["from"] = from
	if s, _ := m["snippet"].(string); s != "" {
		out["snippet"] = s
	}
	if m["read_at"] == nil {
		out["unread"] = true
	}
	if b, _ := m["starred"].(bool); b {
		out["starred"] = true
	}
	if a, _ := m["attachments"].([]any); len(a) > 0 {
		out["attachments"] = len(a)
	}
	return out
}

var (
	htmlDrop   = regexp.MustCompile(`(?is)<(script|style|head)[^>]*>.*?</(script|style|head)>`)
	htmlBreak  = regexp.MustCompile(`(?i)<(br|/p|/div|/li|/tr|/h[1-6])[^>]*>`)
	htmlTag    = regexp.MustCompile(`(?s)<[^>]+>`)
	blankLines = regexp.MustCompile(`\n[ \t]*\n(\s*\n)+`)
	quoteStart = regexp.MustCompile(`(?im)^(on .{4,200} wrote:|.{4,200} пишет:|-{2,} ?(original message|forwarded message|пересылаемое письмо|исходное сообщение) ?-{2,})\s*$`)
)

func htmlToText(s string) string {
	s = htmlDrop.ReplaceAllString(s, "")
	s = htmlBreak.ReplaceAllString(s, "\n")
	s = html.UnescapeString(htmlTag.ReplaceAllString(s, ""))
	return strings.TrimSpace(blankLines.ReplaceAllString(s, "\n\n"))
}

// stripQuotes cuts the quoted history of a reply.
func stripQuotes(text string) (string, bool) {
	cut := false
	if loc := quoteStart.FindStringIndex(text); loc != nil && loc[0] > 0 {
		text, cut = text[:loc[0]], true
	}
	var kept []string
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), ">") {
			cut = true
			continue
		}
		kept = append(kept, line)
	}
	return strings.TrimSpace(strings.Join(kept, "\n")), cut
}

func briefEvent(e map[string]any) map[string]any {
	out := map[string]any{}
	for _, k := range []string{"id", "title", "start", "end", "location", "description", "organizer", "status", "occurrence"} {
		if v, ok := e[k]; ok && v != nil && v != "" {
			out[k] = v
		}
	}
	if b, _ := e["all_day"].(bool); b {
		out["all_day"] = true
	}
	if a, _ := e["attendees"].([]any); len(a) > 0 {
		out["attendees"] = a
	}
	if d, _ := out["description"].(string); len([]rune(d)) > 200 {
		out["description"] = string([]rune(d)[:200]) + "…"
	}
	return out
}

// --- tools ---

type mcpTool func(c *mcpCall, args map[string]any) (any, error)

func schema(required []string, props map[string]any) map[string]any {
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func prop(typ, description string) map[string]any { return map[string]any{"type": typ, "description": description} }

func listProp(description string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": description}
}

func tool(name, title, description string, readOnly bool, input map[string]any) map[string]any {
	return map[string]any{"name": name, "title": title, "description": description, "inputSchema": input,
		"annotations": map[string]any{"title": title, "readOnlyHint": readOnly, "openWorldHint": name == "send_email" || name == "create_event" || name == "respond_to_invite"}}
}

var mcpTools = []map[string]any{
	tool("list_messages", "List messages", "Newest first. folder: INBOX (default), Sent is not here (use list_sent), Archive, Trash, Junk, All or a custom folder name.", true, schema(nil, map[string]any{
		"folder": prop("string", "Folder name, default INBOX"), "unread_only": prop("boolean", "Only unread"), "starred_only": prop("boolean", "Only starred"),
		"limit": prop("integer", "1-50, default 20"), "offset": prop("integer", "For paging")})),
	tool("search_messages", "Search messages", "Search received mail of this mailbox. All filters optional; dates YYYY-MM-DD.", true, schema(nil, map[string]any{
		"query": prop("string", "Words in subject or body"), "from": prop("string", "Sender address or name"), "to": prop("string", "Recipient"),
		"after": prop("string", "From date, inclusive"), "before": prop("string", "To date, inclusive"), "has_attachments": prop("boolean", ""),
		"unread_only": prop("boolean", ""), "folder": prop("string", "Default INBOX; All searches every folder"), "limit": prop("integer", "1-50, default 20")})),
	tool("read_message", "Read message", "Full message: headers, text body (quoted history cut unless full=true), attachment names, calendar invitation.", true, schema([]string{"id"}, map[string]any{
		"id": prop("string", "Message id"), "full": prop("boolean", "Keep quoted history, up to 50000 chars")})),
	tool("list_sent", "List sent mail", "Messages sent from this mailbox, newest first.", true, schema(nil, map[string]any{
		"limit": prop("integer", "1-50, default 20"), "offset": prop("integer", "For paging")})),
	tool("mark_messages", "Mark messages", "Set read and/or starred on up to 50 messages.", false, schema([]string{"ids"}, map[string]any{
		"ids": listProp("Message ids"), "read": prop("boolean", "true read, false unread"), "starred": prop("boolean", "")})),
	tool("move_messages", "Move messages", "Move up to 50 messages to a folder: INBOX, Archive, Trash, Junk (spam) or a custom folder.", false, schema([]string{"ids", "folder"}, map[string]any{
		"ids": listProp("Message ids"), "folder": prop("string", "Target folder")})),
	tool("list_folders", "List folders", "Folders and labels of this mailbox.", true, schema(nil, map[string]any{})),
	tool("send_email", "Send email", "Send from this mailbox. Recipients: a@b.c or Name <a@b.c>. reply_to_message_id threads a reply (fills recipient and Re: subject when omitted).", false, schema([]string{"text"}, map[string]any{
		"to": listProp("Recipients"), "cc": listProp("Copy"), "bcc": listProp("Hidden copy"), "subject": prop("string", ""),
		"text": prop("string", "Plain-text body"), "reply_to_message_id": prop("string", "Message id being answered"), "reply_all": prop("boolean", "With reply_to_message_id: copy the other recipients")})),
	tool("find_contacts", "Find contacts", "Search the address book by name or address.", true, schema(nil, map[string]any{"query": prop("string", "Name or address part")})),
	tool("list_events", "List calendar events", "Events of this mailbox's calendar between two dates (default: today and the next 7 days).", true, schema(nil, map[string]any{
		"from": prop("string", "YYYY-MM-DD, default today"), "to": prop("string", "YYYY-MM-DD exclusive, default from+7 days")})),
	tool("create_event", "Create calendar event", "Create an event; attendees get invitations by email. Times are local to the calendar time zone, YYYY-MM-DDTHH:MM (all_day: YYYY-MM-DD).", false, schema([]string{"title", "start"}, map[string]any{
		"title": prop("string", ""), "start": prop("string", "Start"), "end": prop("string", "End; default start + duration_minutes"),
		"duration_minutes": prop("integer", "Default 60"), "all_day": prop("boolean", ""), "location": prop("string", ""), "description": prop("string", ""),
		"attendees": listProp("Invitee addresses")})),
	tool("respond_to_invite", "Answer invitation", "Answer a calendar invitation received by email.", false, schema([]string{"message_id", "response"}, map[string]any{
		"message_id": prop("string", "Id of the invitation message"), "response": map[string]any{"type": "string", "enum": []string{"accepted", "tentative", "declined"}}})),
}

var mcpHandlers map[string]mcpTool

func init() {
	mcpHandlers = map[string]mcpTool{
		"list_messages": func(c *mcpCall, a map[string]any) (any, error) {
			q := url.Values{"limit": {strconv.Itoa(argInt(a, "limit", 20, 1, 50))}, "offset": {strconv.Itoa(argInt(a, "offset", 0, 0, 100000))}, "compact": {"true"}}
			q.Set("folder", "INBOX")
			if f := argString(a, "folder"); f != "" {
				q.Set("folder", f)
			}
			if b, _ := argBool(a, "unread_only"); b {
				q.Set("unread", "true")
			}
			if b, _ := argBool(a, "starred_only"); b {
				q.Set("starred", "true")
			}
			var res struct{ Messages []map[string]any }
			if err := c.api(http.MethodGet, c.ws("/mailboxes/"+c.p.MailboxID+"/messages"), q, nil, &res); err != nil {
				return nil, err
			}
			out := make([]map[string]any, 0, len(res.Messages))
			for _, m := range res.Messages {
				out = append(out, briefMessage(m))
			}
			return map[string]any{"mailbox": c.p.Address, "folder": q.Get("folder"), "messages": out}, nil
		},
		"search_messages": func(c *mcpCall, a map[string]any) (any, error) {
			q := url.Values{"box": {c.p.MailboxID}, "limit": {strconv.Itoa(argInt(a, "limit", 20, 1, 50))}}
			for arg, param := range map[string]string{"query": "q", "from": "from", "to": "to", "after": "after", "before": "before", "folder": "folder"} {
				if v := argString(a, arg); v != "" {
					q.Set(param, v)
				}
			}
			if b, ok := argBool(a, "has_attachments"); ok && b {
				q.Set("attachments", "true")
			}
			if b, ok := argBool(a, "unread_only"); ok && b {
				q.Set("unread", "true")
			}
			var res struct {
				Messages []struct{ Message map[string]any }
				HasMore  bool `json:"has_more"`
			}
			if err := c.api(http.MethodGet, "/messages/received-search", q, nil, &res); err != nil {
				return nil, err
			}
			out := []map[string]any{}
			for _, r := range res.Messages {
				if r.Message["mailbox_id"] == c.p.MailboxID {
					out = append(out, briefMessage(r.Message))
				}
			}
			return map[string]any{"messages": out, "has_more": res.HasMore}, nil
		},
		"read_message": func(c *mcpCall, a map[string]any) (any, error) {
			m, err := c.message(argString(a, "id"))
			if err != nil {
				return nil, err
			}
			text, _ := m["text"].(string)
			if strings.TrimSpace(text) == "" {
				h, _ := m["html"].(string)
				text = htmlToText(h)
			}
			full, _ := argBool(a, "full")
			limit, note := 8000, ""
			if full {
				limit = 50000
			} else if cut, ok := stripQuotes(text); ok {
				text, note = cut, "quoted history removed; full=true keeps it"
			}
			if r := []rune(text); len(r) > limit {
				text = string(r[:limit])
				note = strings.TrimPrefix(note+"; body truncated", "; ")
			}
			out := briefMessage(m)
			delete(out, "snippet")
			for _, k := range []string{"to", "cc", "reply_to"} {
				if v, ok := m[k].([]any); ok && len(v) > 0 {
					out[k] = v
				}
			}
			out["text"] = text
			if files, _ := m["attachments"].([]any); len(files) > 0 {
				names := []string{}
				for _, f := range files {
					if fm, ok := f.(map[string]any); ok {
						names = append(names, fmt.Sprintf("%v (%v bytes)", fm["filename"], fm["size_bytes"]))
					}
				}
				out["attachments"] = names
			}
			if cal, ok := m["calendar_preview"].(map[string]any); ok {
				out["calendar_invitation"] = cal
			}
			if note != "" {
				out["note"] = note
			}
			return out, nil
		},
		"list_sent": func(c *mcpCall, a map[string]any) (any, error) {
			limit := argInt(a, "limit", 20, 1, 50)
			q := url.Values{"limit": {"100"}, "offset": {strconv.Itoa(argInt(a, "offset", 0, 0, 100000))}}
			var res struct{ Messages []map[string]any }
			if err := c.api(http.MethodGet, "/messages/sent", q, nil, &res); err != nil {
				return nil, err
			}
			out := []map[string]any{}
			for _, m := range res.Messages {
				if from, _ := m["from"].(string); !strings.EqualFold(from, c.p.Address) || len(out) >= limit {
					continue
				}
				item := map[string]any{"id": m["id"], "to": m["to"], "subject": m["subject"], "date": m["created_at"], "status": m["status"]}
				if t, _ := m["text"].(string); t != "" {
					if r := []rune(t); len(r) > 160 {
						t = string(r[:160]) + "…"
					}
					item["snippet"] = t
				}
				out = append(out, item)
			}
			return map[string]any{"messages": out}, nil
		},
		"mark_messages": func(c *mcpCall, a map[string]any) (any, error) {
			body := map[string]any{}
			if v, ok := argBool(a, "read"); ok {
				body["read"] = v
			}
			if v, ok := argBool(a, "starred"); ok {
				body["starred"] = v
			}
			if len(body) == 0 {
				return nil, toolError("pass read and/or starred")
			}
			return c.eachMessage(argList(a, "ids"), func(id string) error {
				return c.api(http.MethodPatch, c.ws("/messages/"+id+"/flags"), nil, body, nil)
			})
		},
		"move_messages": func(c *mcpCall, a map[string]any) (any, error) {
			folder := argString(a, "folder")
			if folder == "" {
				return nil, toolError("folder is required")
			}
			return c.eachMessage(argList(a, "ids"), func(id string) error {
				return c.api(http.MethodPut, c.ws("/messages/"+id+"/folder"), nil, map[string]string{"folder": folder}, nil)
			})
		},
		"list_folders": func(c *mcpCall, a map[string]any) (any, error) {
			var res struct {
				Folders []map[string]any
				Labels  []map[string]any
			}
			if err := c.api(http.MethodGet, c.ws("/mailboxes/"+c.p.MailboxID+"/organization"), nil, nil, &res); err != nil {
				return nil, err
			}
			folders := []any{"INBOX", "Archive", "Trash", "Junk"}
			seen := map[string]bool{"INBOX": true, "Archive": true, "Trash": true, "Junk": true}
			for _, f := range res.Folders {
				if name := fmt.Sprint(f["name"]); !seen[name] {
					seen[name] = true
					folders = append(folders, name)
				}
			}
			labels := []any{}
			for _, l := range res.Labels {
				labels = append(labels, l["name"])
			}
			return map[string]any{"folders": folders, "labels": labels}, nil
		},
		"send_email": func(c *mcpCall, a map[string]any) (any, error) {
			to, cc, bcc := argList(a, "to"), argList(a, "cc"), argList(a, "bcc")
			subject, text := argString(a, "subject"), argString(a, "text")
			body := map[string]any{"from": c.p.Address, "text": text}
			if replyID := argString(a, "reply_to_message_id"); replyID != "" {
				m, err := c.message(replyID)
				if err != nil {
					return nil, err
				}
				body["reply_to_message_id"] = replyID
				if len(to) == 0 {
					if rt, _ := m["reply_to"].([]any); len(rt) > 0 {
						for _, v := range rt {
							to = append(to, fmt.Sprint(v))
						}
					} else if from, _ := m["from"].(string); from != "" {
						to = []string{from}
					}
				}
				if all, _ := argBool(a, "reply_all"); all {
					for _, k := range []string{"to", "cc"} {
						list, _ := m[k].([]any)
						for _, v := range list {
							if addr := fmt.Sprint(v); !strings.Contains(strings.ToLower(addr), c.p.Address) {
								cc = append(cc, addr)
							}
						}
					}
				}
				if subject == "" {
					subject, _ = m["subject"].(string)
					if !strings.HasPrefix(strings.ToLower(subject), "re:") {
						subject = "Re: " + subject
					}
				}
			}
			if len(to) == 0 {
				return nil, toolError("at least one recipient in to is required")
			}
			body["to"], body["subject"] = to, subject
			if len(cc) > 0 {
				body["cc"] = cc
			}
			if len(bcc) > 0 {
				body["bcc"] = bcc
			}
			var res map[string]any
			if err := c.api(http.MethodPost, c.ws("/emails"), nil, body, &res); err != nil {
				return nil, err
			}
			return map[string]any{"queued": true, "id": res["id"], "from": c.p.Address, "to": to, "subject": subject}, nil
		},
		"find_contacts": func(c *mcpCall, a map[string]any) (any, error) {
			q := url.Values{}
			if v := argString(a, "query"); v != "" {
				q.Set("q", v)
			}
			var res struct{ Contacts []map[string]any }
			if err := c.api(http.MethodGet, "/contacts", q, nil, &res); err != nil {
				return nil, err
			}
			out := []map[string]any{}
			for i, ct := range res.Contacts {
				if i >= 50 {
					break
				}
				out = append(out, map[string]any{"name": ct["name"], "email": ct["email"]})
			}
			return map[string]any{"contacts": out}, nil
		},
		"list_events": func(c *mcpCall, a map[string]any) (any, error) {
			from := argString(a, "from")
			if from == "" {
				from = time.Now().Format("2006-01-02")
			}
			start, err := time.Parse("2006-01-02", from[:min(10, len(from))])
			if err != nil {
				return nil, toolError("from must be YYYY-MM-DD")
			}
			to := argString(a, "to")
			if to == "" {
				to = start.AddDate(0, 0, 7).Format("2006-01-02")
			}
			events := []map[string]any{}
			for offset := 0; offset < 500; {
				var res struct {
					Events  []map[string]any
					HasMore bool `json:"has_more"`
				}
				q := url.Values{"from": {start.Format("2006-01-02")}, "to": {to[:min(10, len(to))]}, "offset": {strconv.Itoa(offset)}}
				if err := c.api(http.MethodGet, c.ws("/calendar/events"), q, nil, &res); err != nil {
					return nil, err
				}
				for _, e := range res.Events {
					if e["status"] != "cancelled" {
						events = append(events, briefEvent(e))
					}
				}
				offset += len(res.Events)
				if !res.HasMore || len(res.Events) == 0 {
					break
				}
			}
			return map[string]any{"from": start.Format("2006-01-02"), "to_exclusive": to, "events": events}, nil
		},
		"create_event": func(c *mcpCall, a map[string]any) (any, error) {
			var cal struct{ Timezone string }
			if err := c.api(http.MethodGet, c.ws("/calendar"), nil, nil, &cal); err != nil {
				return nil, err
			}
			allDay, _ := argBool(a, "all_day")
			title, start, end := argString(a, "title"), argString(a, "start"), argString(a, "end")
			if title == "" || start == "" {
				return nil, toolError("title and start are required")
			}
			if allDay {
				d, err := time.Parse("2006-01-02", start[:min(10, len(start))])
				if err != nil {
					return nil, toolError("all-day start must be YYYY-MM-DD")
				}
				start = d.Format("2006-01-02")
				if end == "" {
					end = d.AddDate(0, 0, 1).Format("2006-01-02")
				}
			} else {
				t, err := time.Parse("2006-01-02T15:04", start[:min(16, len(start))])
				if err != nil {
					return nil, toolError("start must be YYYY-MM-DDTHH:MM")
				}
				start = t.Format("2006-01-02T15:04")
				if end == "" {
					end = t.Add(time.Duration(argInt(a, "duration_minutes", 60, 5, 24*60)) * time.Minute).Format("2006-01-02T15:04")
				}
				end = end[:min(16, len(end))]
			}
			body := map[string]any{"title": title, "description": argString(a, "description"), "location": argString(a, "location"),
				"timezone": cal.Timezone, "all_day": allDay, "start": start, "end": end, "version": 0}
			if attendees := argList(a, "attendees"); len(attendees) > 0 {
				body["attendees"], body["organizer"] = attendees, c.p.Address
			}
			var e map[string]any
			if err := c.api(http.MethodPost, c.ws("/calendar/events"), nil, body, &e); err != nil {
				return nil, err
			}
			return map[string]any{"created": briefEvent(e), "invitations_sent_to": e["attendees"]}, nil
		},
		"respond_to_invite": func(c *mcpCall, a map[string]any) (any, error) {
			id := argString(a, "message_id")
			if _, err := c.message(id); err != nil {
				return nil, err
			}
			var res map[string]any
			if err := c.api(http.MethodPost, c.ws("/messages/"+id+"/calendar-reply"), nil, map[string]string{"response": argString(a, "response")}, &res); err != nil {
				return nil, err
			}
			return map[string]any{"answered": argString(a, "response"), "event": res}, nil
		},
	}
}

// eachMessage applies fn to up to 50 messages of the granted mailbox.
func (c *mcpCall) eachMessage(ids []string, fn func(id string) error) (any, error) {
	if len(ids) == 0 || len(ids) > 50 {
		return nil, toolError("pass 1 to 50 message ids")
	}
	done, failed := []string{}, map[string]string{}
	for _, id := range ids {
		if _, err := c.message(id); err != nil {
			failed[id] = err.Error()
			continue
		}
		if err := fn(id); err != nil {
			var te toolError
			if !errors.As(err, &te) {
				log.Printf("mcp message %s: %v", id, err)
				err = toolError("internal error")
			}
			failed[id] = err.Error()
			continue
		}
		done = append(done, id)
	}
	out := map[string]any{"done": len(done)}
	if len(failed) > 0 {
		out["failed"] = failed
	}
	return out, nil
}
