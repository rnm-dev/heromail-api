package httpapi

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/google/uuid"
	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/calendar"
)

// Calendar routes an assistant key may call, acting as its issuer. The key is
// bound to one mailbox, so it is confined to that mailbox's workspace.
var assistantCalendarPath = regexp.MustCompile(`^/workspaces/([^/]+)/calendar(/events(/[0-9a-fA-F-]{36})?)?$`)

// AssistantCalendar wraps the generated handler for calendar paths called with an
// assistant key; it returns false when the request is not one, leaving it to sessions.
func (s *Server) assistantCalendar(accounts *account.Service, generated http.Handler, w http.ResponseWriter, r *http.Request) bool {
	m := assistantCalendarPath.FindStringSubmatch(r.URL.Path)
	if m == nil {
		return false
	}
	if _, _, basic := r.BasicAuth(); !basic {
		return false
	}
	p, ok := s.assistantPrincipal(w, r)
	if !ok {
		return true
	}
	var slug string
	if err := s.pool.QueryRow(r.Context(), `SELECT slug FROM workspaces WHERE id=$1`, p.WorkspaceID).Scan(&slug); err != nil || slug != m[1] {
		writeErrorEnvelope(w, http.StatusForbidden, "forbidden", "assistant key is limited to its mailbox workspace")
		return true
	}
	user, err := accounts.UserByID(r.Context(), p.UserID)
	if err != nil {
		writeErrorEnvelope(w, http.StatusUnauthorized, "unauthenticated", "invalid assistant key")
		return true
	}
	generated.ServeHTTP(w, account.WithUser(r, user))
	return true
}

// assistantMe serves GET /assistant/me: who the key acts as and where.
func (s *Server) assistantMe() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := s.assistantPrincipal(w, r)
		if !ok {
			return
		}
		var out struct {
			Address   string `json:"address"`
			Name      string `json:"name"`
			Workspace string `json:"workspace"`
		}
		err := s.pool.QueryRow(r.Context(), `SELECT lower(m.local_part||'@'||d.domain),u.name,w.slug FROM mailboxes m JOIN domains d ON d.id=m.domain_id
 JOIN workspaces w ON w.id=$2 JOIN users u ON u.id=$3 WHERE m.id=$1`, p.MailboxID, p.WorkspaceID, p.UserID).Scan(&out.Address, &out.Name, &out.Workspace)
		if err != nil {
			writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "lookup failed")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(out)
	}
}

// assistantInviteReply serves POST /assistant/invite-reply {"uid":N,"response":"accepted"}:
// answers a calendar invitation received by the key's mailbox, addressed by IMAP UID.
func (s *Server) assistantInviteReply(accounts *account.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
			return
		}
		p, ok := s.assistantPrincipal(w, r)
		if !ok {
			return
		}
		var body struct {
			UID      int64  `json:"uid"`
			Response string `json:"response"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
			writeErrorEnvelope(w, http.StatusBadRequest, "invalid_json", "expected {uid, response}")
			return
		}
		ctx := r.Context()
		var id, slug string
		if err := s.pool.QueryRow(ctx, `SELECT m.id,w.slug FROM messages m JOIN workspaces w ON w.id=$3 WHERE m.mailbox_id=$1 AND m.imap_uid=$2`, p.MailboxID, body.UID, p.WorkspaceID).Scan(&id, &slug); err != nil {
			writeErrorEnvelope(w, http.StatusNotFound, "not_found", "message not found")
			return
		}
		user, err := accounts.UserByID(ctx, p.UserID)
		if err != nil {
			writeErrorEnvelope(w, http.StatusUnauthorized, "unauthenticated", "invalid assistant key")
			return
		}
		res, err := s.ReplyMessageCalendar(account.WithUser(r, user).Context(), ReplyMessageCalendarRequestObject{
			Slug: Slug(slug), MessageId: uuid.MustParse(id), Body: &calendar.ResponseRequest{Response: body.Response}})
		if err != nil {
			writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "reply failed")
			return
		}
		res.VisitReplyMessageCalendarResponse(w)
	}
}
