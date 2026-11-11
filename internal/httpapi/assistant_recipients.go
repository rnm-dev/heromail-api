package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/rnm/heromail/backend/internal/mailauth"
)

// assistantRecipientsSQL is the address book an assistant key sees: the issuer's
// contacts, colleagues' mailboxes in the same workspace, and people this one
// mailbox received from or wrote to. An empty query matches everything.
const assistantRecipientsSQL = `
WITH me AS (
 SELECT m.id, lower(m.local_part||'@'||d.domain) addr, coalesce(m.personal_workspace_id,d.workspace_id) ws
 FROM mailboxes m JOIN domains d ON d.id=m.domain_id WHERE m.id=$2
), found AS (
 SELECT name, email::text email, 0 rank, now() seen, 'contact' source FROM contacts
 WHERE user_id=$1 AND strpos(lower(name||' '||email),lower($3))>0
 UNION ALL
 SELECT coalesce(nullif(m.name,''),nullif(u.name,''),''), lower(m.local_part||'@'||d.domain), 1, m.created_at, 'workspace'
 FROM mailboxes m JOIN domains d ON d.id=m.domain_id JOIN me ON me.ws=coalesce(m.personal_workspace_id,d.workspace_id)
 LEFT JOIN users u ON u.id=m.owner_user_id
 WHERE d.verified_at IS NOT NULL AND strpos(lower(coalesce(m.name,'')||' '||coalesce(u.name,'')||' '||m.local_part||'@'||d.domain),lower($3))>0
 UNION ALL
 SELECT coalesce(msg.from_name,''), msg.from_addr, 2, msg.received_at, 'received' FROM messages msg JOIN me ON me.id=msg.mailbox_id
 WHERE msg.from_addr LIKE '%_@_%' AND msg.folder<>'Junk' AND strpos(lower(coalesce(msg.from_name,'')||' '||msg.from_addr),lower($3))>0
 UNION ALL
 SELECT '', a, 2, e.created_at, 'sent' FROM emails e CROSS JOIN LATERAL unnest(e.to_addrs||e.cc_addrs||e.bcc_addrs) a
 WHERE lower(e.from_addr)=(SELECT addr FROM me) AND strpos(lower(a),lower($3))>0
), best AS (
 SELECT DISTINCT ON (lower(email)) name, email, rank, seen, source FROM found
 WHERE lower(email)<>(SELECT addr FROM me)
 ORDER BY lower(email), rank, (name<>'') DESC, seen DESC
)
SELECT name, email, source FROM best ORDER BY rank, seen DESC, email LIMIT $4`

// assistantPrincipal authenticates HTTP Basic (mailbox address, hm_ai_ key).
// Session tokens, API keys and account passwords are never accepted here.
func (s *Server) assistantPrincipal(w http.ResponseWriter, r *http.Request) (mailauth.Principal, bool) {
	address, key, ok := r.BasicAuth()
	address = strings.ToLower(strings.TrimSpace(address))
	ctx := r.Context()
	if ok && strings.HasPrefix(key, mailauth.AssistantKeyPrefix) && mailauth.Allow(ctx, s.limiter, "assistant", clientIP(r), address) {
		if p, ok := mailauth.Login(ctx, s.pool, address, key, mailauth.Assistant); ok {
			return p, true
		}
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="heromail-assistant"`)
	writeErrorEnvelope(w, http.StatusUnauthorized, "unauthenticated", "invalid assistant key")
	return mailauth.Principal{}, false
}

// assistantRecipients serves GET /assistant/recipients.
func (s *Server) assistantRecipients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}
	p, ok := s.assistantPrincipal(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if utf8.RuneCountInString(q) > 200 {
		writeErrorEnvelope(w, http.StatusBadRequest, "validation_failed", "query too long")
		return
	}
	rows, err := s.pool.Query(ctx, assistantRecipientsSQL, p.UserID, p.MailboxID, q, limit)
	if err != nil {
		writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "lookup failed")
		return
	}
	defer rows.Close()
	type recipient struct {
		Name   string `json:"name"`
		Email  string `json:"email"`
		Source string `json:"source"` // contact, workspace, received or sent
	}
	result := []recipient{}
	for rows.Next() {
		var item recipient
		if err := rows.Scan(&item.Name, &item.Email, &item.Source); err != nil {
			writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "lookup failed")
			return
		}
		result = append(result, item)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{"recipients": result})
}
