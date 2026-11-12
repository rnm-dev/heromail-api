package httpapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
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

// assistantKeyCacheTTL bounds how long a successful key check is reused.
const assistantKeyCacheTTL = 5 * time.Minute

type verifiedKey struct {
	hash  string
	until time.Time
}

// assistantKeyCache remembers (address, key) pairs that passed bcrypt, keyed by a
// SHA-256 of both so plaintext keys are not kept. An entry only counts while the
// stored hash is unchanged, so rotation and revocation take effect at once.
type assistantKeyCache struct {
	mu      sync.Mutex
	entries map[[32]byte]verifiedKey
}

var assistantKeys = &assistantKeyCache{entries: map[[32]byte]verifiedKey{}}

func assistantCacheKey(address, key string) [32]byte {
	return sha256.Sum256([]byte(address + "\x00" + key))
}

func (c *assistantKeyCache) verified(address, key, hash string) bool {
	id := assistantCacheKey(address, key)
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[id]
	if !ok || time.Now().After(e.until) || subtle.ConstantTimeCompare([]byte(e.hash), []byte(hash)) != 1 {
		delete(c.entries, id)
		return false
	}
	return true
}

func (c *assistantKeyCache) remember(address, key, hash string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= 10000 {
		now := time.Now()
		for id, e := range c.entries {
			if now.After(e.until) {
				delete(c.entries, id)
			}
		}
		if len(c.entries) >= 10000 {
			c.entries = map[[32]byte]verifiedKey{}
		}
	}
	c.entries[assistantCacheKey(address, key)] = verifiedKey{hash: hash, until: time.Now().Add(assistantKeyCacheTTL)}
}

// assistantPrincipal authenticates HTTP Basic (mailbox address, hm_ai_ key).
// Session tokens, API keys and account passwords are never accepted here.
func (s *Server) assistantPrincipal(w http.ResponseWriter, r *http.Request) (mailauth.Principal, bool) {
	address, key, ok := r.BasicAuth()
	address = strings.ToLower(strings.TrimSpace(address))
	ctx := r.Context()
	if ok && strings.HasPrefix(key, mailauth.AssistantKeyPrefix) {
		// A key verified recently skips bcrypt and the login limiter, so an MCP client
		// making many calls is not locked out; the fresh lookup still sees revocation.
		if p, err := mailauth.Lookup(ctx, s.pool, address, mailauth.Assistant); err == nil && assistantKeys.verified(address, key, p.Hash) {
			return p, true
		}
		if mailauth.Allow(ctx, s.limiter, "assistant", clientIP(r), address) {
			if p, ok := mailauth.Login(ctx, s.pool, address, key, mailauth.Assistant); ok {
				assistantKeys.remember(address, key, p.Hash)
				return p, true
			}
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
