package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/ratelimit"
)

// OAuth 2.1 for remote MCP connectors (claude.ai custom connectors and the
// like): metadata discovery (RFC 9728, RFC 8414), dynamic client registration
// (RFC 7591), authorization code with mandatory PKCE S256, rotating refresh
// tokens. The consent page is the web app's /oauth/authorize; it calls
// /oauth/client and /oauth/approve with the user's session.
//
// A grant is one client approved for one mailbox the user owns. It confers
// what the MCP tools do and nothing else: the tokens are not sessions and
// open no other route.

const (
	oauthCodeTTL    = 10 * time.Minute
	oauthAccessTTL  = time.Hour
	oauthRefreshTTL = 60 * 24 * time.Hour
)

func oauthRandom(prefix string) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return prefix + hex.EncodeToString(b)
}

func oauthHash(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

// publicAPIURL is the externally visible origin of this API, the OAuth issuer.
func publicAPIURL(r *http.Request) string {
	if v := strings.TrimRight(os.Getenv("PUBLIC_API_URL"), "/"); v != "" {
		return v
	}
	scheme := "https"
	if host := r.Host; strings.HasPrefix(host, "localhost") || strings.HasPrefix(host, "127.0.0.1") {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

func appBaseURL() string {
	if v := strings.TrimRight(os.Getenv("APP_BASE_URL"), "/"); v != "" {
		return v
	}
	return "https://heromail.kz"
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// oauthError uses the RFC 6749 shape, which OAuth clients parse; it is not the
// API's error envelope.
func oauthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

func (s *Server) oauthResourceMetadata(w http.ResponseWriter, r *http.Request) {
	api := publicAPIURL(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 api + "/mcp",
		"authorization_servers":    []string{api},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{"mail"},
		"resource_name":            "Heromail",
	})
}

func (s *Server) oauthServerMetadata(w http.ResponseWriter, r *http.Request) {
	api := publicAPIURL(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                api,
		"authorization_endpoint":                appBaseURL() + "/oauth/authorize",
		"token_endpoint":                        api + "/oauth/token",
		"registration_endpoint":                 api + "/oauth/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      []string{"mail"},
	})
}

func (s *Server) oauthLimited(r *http.Request, name string, limit int, window time.Duration) bool {
	if s.limiter == nil {
		return false
	}
	return !s.limiter.AllowStrict(r.Context(), ratelimit.Rule{Name: name, Limit: limit, Window: window}, clientIP(r)).Allowed
}

// validRedirectURI accepts https, or plain http to the local machine (desktop
// clients listen on a loopback port). Fragments are not allowed (RFC 6749 3.1.2).
func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" || u.Host == "" || len(raw) > 2000 {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		host := u.Hostname()
		return host == "localhost" || host == "127.0.0.1" || host == "::1"
	}
	return false
}

// oauthRegister serves POST /oauth/register (RFC 7591), public clients only.
func (s *Server) oauthRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request", "use POST")
		return
	}
	if s.oauthLimited(r, "oauth:register:ip", 30, time.Hour) {
		oauthError(w, http.StatusTooManyRequests, "invalid_request", "too many registrations")
		return
	}
	var body struct {
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&body); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "expected JSON client metadata")
		return
	}
	if len(body.RedirectURIs) == 0 || len(body.RedirectURIs) > 10 {
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "between 1 and 10 redirect_uris are required")
		return
	}
	for _, u := range body.RedirectURIs {
		if !validRedirectURI(u) {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect URIs must be https (or http to localhost) without a fragment")
			return
		}
	}
	name := strings.TrimSpace(body.ClientName)
	if name == "" {
		name = "MCP client"
	}
	if r := []rune(name); len(r) > 100 {
		name = string(r[:100])
	}
	id := oauthRandom("hmc_")[:36]
	created := time.Now()
	if _, err := s.pool.Exec(r.Context(), `INSERT INTO oauth_clients(id,name,redirect_uris,created_at) VALUES($1,$2,$3,$4)`, id, name, body.RedirectURIs, created); err != nil {
		log.Printf("oauth register: %v", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "registration failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  id,
		"client_id_issued_at":        created.Unix(),
		"client_name":                name,
		"redirect_uris":              body.RedirectURIs,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	})
}

// oauthClient checks a client and an exact registered redirect URI.
func (s *Server) oauthClient(ctx context.Context, clientID, redirectURI string) (string, bool) {
	var name string
	var uris []string
	if err := s.pool.QueryRow(ctx, `SELECT name,redirect_uris FROM oauth_clients WHERE id=$1`, clientID).Scan(&name, &uris); err != nil {
		return "", false
	}
	for _, u := range uris {
		if u == redirectURI {
			return name, true
		}
	}
	return "", false
}

// ownedMailboxSQL is the assistant-key rule: the user owns the mailbox, is a
// member of its workspace, may sign in, and the domain is verified.
const ownedMailboxSQL = ` FROM mailboxes m JOIN domains d ON d.id=m.domain_id
 JOIN workspaces w ON w.id=coalesce(m.personal_workspace_id,d.workspace_id)
 JOIN workspace_members wm ON wm.workspace_id=w.id AND wm.user_id=coalesce(m.owner_user_id,w.personal_owner_id)
 JOIN users u ON u.id=wm.user_id
 WHERE d.verified_at IS NOT NULL AND NOT u.must_change_password AND u.deleted_at IS NULL`

func (s *Server) ownsMailbox(ctx context.Context, userID, mailboxID string) bool {
	var ok bool
	err := s.pool.QueryRow(ctx, `SELECT true`+ownedMailboxSQL+` AND m.id=$1 AND u.id=$2`, mailboxID, userID).Scan(&ok)
	return err == nil && ok
}

// oauthClientInfo serves GET /oauth/client?client_id=&redirect_uri= for the consent page.
func (s *Server) oauthClientInfo(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	name, ok := s.oauthClient(r.Context(), q.Get("client_id"), q.Get("redirect_uri"))
	if !ok {
		writeErrorEnvelope(w, http.StatusBadRequest, "invalid_client", "unknown client or redirect URI")
		return
	}
	u, _ := url.Parse(q.Get("redirect_uri"))
	user, _ := account.CurrentUser(r.Context())
	rows, err := s.pool.Query(r.Context(), `SELECT m.id::text, lower(m.local_part||'@'||d.domain)`+ownedMailboxSQL+` AND u.id=$1 ORDER BY 2`, user.ID)
	if err != nil {
		writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "lookup failed")
		return
	}
	type box struct {
		ID      string `json:"id"`
		Address string `json:"address"`
	}
	boxes, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (box, error) {
		var b box
		return b, row.Scan(&b.ID, &b.Address)
	})
	if err != nil {
		writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "redirect_host": u.Host, "mailboxes": boxes})
}

// oauthApprove serves POST /oauth/approve: the signed-in user grants a client
// one mailbox. It returns where the browser goes next, with the code.
func (s *Server) oauthApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	var body struct {
		ClientID            string `json:"client_id"`
		RedirectURI         string `json:"redirect_uri"`
		CodeChallenge       string `json:"code_challenge"`
		CodeChallengeMethod string `json:"code_challenge_method"`
		State               string `json:"state"`
		MailboxID           string `json:"mailbox_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&body); err != nil {
		writeErrorEnvelope(w, http.StatusBadRequest, "invalid_json", "expected JSON")
		return
	}
	ctx := r.Context()
	if _, ok := s.oauthClient(ctx, body.ClientID, body.RedirectURI); !ok {
		writeErrorEnvelope(w, http.StatusBadRequest, "invalid_client", "unknown client or redirect URI")
		return
	}
	if body.CodeChallengeMethod != "S256" || len(body.CodeChallenge) < 43 || len(body.CodeChallenge) > 128 {
		writeErrorEnvelope(w, http.StatusBadRequest, "invalid_request", "PKCE with S256 is required")
		return
	}
	user, _ := account.CurrentUser(ctx)
	if !s.ownsMailbox(ctx, user.ID, body.MailboxID) {
		writeErrorEnvelope(w, http.StatusForbidden, "forbidden", "you can connect only a mailbox you own")
		return
	}
	code := oauthRandom("hmo_c_")
	if _, err := s.pool.Exec(ctx, `INSERT INTO oauth_codes(code_hash,client_id,user_id,mailbox_id,redirect_uri,code_challenge,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`,
		oauthHash(code), body.ClientID, user.ID, body.MailboxID, body.RedirectURI, body.CodeChallenge, time.Now().Add(oauthCodeTTL)); err != nil {
		log.Printf("oauth approve: %v", err)
		writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "approval failed")
		return
	}
	target, _ := url.Parse(body.RedirectURI)
	q := target.Query()
	q.Set("code", code)
	if body.State != "" {
		q.Set("state", body.State)
	}
	q.Set("iss", publicAPIURL(r))
	target.RawQuery = q.Encode()
	writeJSON(w, http.StatusOK, map[string]string{"redirect": target.String()})
}

// oauthToken serves POST /oauth/token.
func (s *Server) oauthToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request", "use POST")
		return
	}
	if s.oauthLimited(r, "oauth:token:ip", 120, time.Minute) {
		oauthError(w, http.StatusTooManyRequests, "invalid_request", "too many requests")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "expected a form body")
		return
	}
	ctx := r.Context()
	clientID := r.PostForm.Get("client_id")
	var grantID string
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		var client, userID, mailboxID, redirectURI, challenge string
		var expires time.Time
		err := s.pool.QueryRow(ctx, `DELETE FROM oauth_codes WHERE code_hash=$1 RETURNING client_id,user_id::text,mailbox_id::text,redirect_uri,code_challenge,expires_at`,
			oauthHash(r.PostForm.Get("code"))).Scan(&client, &userID, &mailboxID, &redirectURI, &challenge, &expires)
		if err != nil || time.Now().After(expires) || client != clientID || redirectURI != r.PostForm.Get("redirect_uri") {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired authorization code")
			return
		}
		verifier := r.PostForm.Get("code_verifier")
		sum := sha256.Sum256([]byte(verifier))
		if len(verifier) < 43 || len(verifier) > 128 || subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(challenge)) != 1 {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
		if !s.ownsMailbox(ctx, userID, mailboxID) {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "mailbox access has ended")
			return
		}
		if err := s.pool.QueryRow(ctx, `INSERT INTO oauth_grants(client_id,user_id,mailbox_id) VALUES($1,$2,$3) RETURNING id::text`, clientID, userID, mailboxID).Scan(&grantID); err != nil {
			log.Printf("oauth grant: %v", err)
			oauthError(w, http.StatusInternalServerError, "server_error", "token issue failed")
			return
		}
	case "refresh_token":
		var client, userID, mailboxID string
		var expires time.Time
		// Rotation: the presented refresh token is spent whether or not the rest succeeds.
		err := s.pool.QueryRow(ctx, `DELETE FROM oauth_tokens t USING oauth_grants g WHERE t.token_hash=$1 AND t.kind='refresh' AND g.id=t.grant_id
 RETURNING g.id::text,g.client_id,g.user_id::text,g.mailbox_id::text,t.expires_at`, oauthHash(r.PostForm.Get("refresh_token"))).Scan(&grantID, &client, &userID, &mailboxID, &expires)
		if err != nil || time.Now().After(expires) || client != clientID || !s.ownsMailbox(ctx, userID, mailboxID) {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired refresh token")
			return
		}
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "use authorization_code or refresh_token")
		return
	}
	access, refresh := oauthRandom("hmo_a_"), oauthRandom("hmo_r_")
	now := time.Now()
	_, err := s.pool.Exec(ctx, `WITH gone AS (DELETE FROM oauth_tokens WHERE grant_id=$1 AND expires_at<$6)
 INSERT INTO oauth_tokens(token_hash,grant_id,kind,expires_at) VALUES($2,$1,'access',$3),($4,$1,'refresh',$5)`,
		grantID, oauthHash(access), now.Add(oauthAccessTTL), oauthHash(refresh), now.Add(oauthRefreshTTL), now)
	if err != nil {
		log.Printf("oauth tokens: %v", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "token issue failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(oauthAccessTTL.Seconds()),
		"refresh_token": refresh,
		"scope":         "mail",
	})
}

// oauthPrincipal is who an MCP request acts as.
type oauthPrincipal struct {
	GrantID, UserID, MailboxID, WorkspaceID, Slug, Address string
}

var errOAuthToken = errors.New("invalid access token")

// oauthBearer resolves an access token, re-checking mailbox ownership each time.
func (s *Server) oauthBearer(ctx context.Context, header string) (oauthPrincipal, error) {
	token, ok := strings.CutPrefix(header, "Bearer ")
	if !ok || !strings.HasPrefix(token, "hmo_a_") {
		return oauthPrincipal{}, errOAuthToken
	}
	var p oauthPrincipal
	var lastUsed *time.Time
	err := s.pool.QueryRow(ctx, `SELECT g.id::text,u.id::text,m.id::text,w.id::text,w.slug,lower(m.local_part||'@'||d.domain),g.last_used_at`+
		strings.Replace(ownedMailboxSQL, " FROM mailboxes m", " FROM oauth_tokens t JOIN oauth_grants g ON g.id=t.grant_id JOIN mailboxes m ON m.id=g.mailbox_id", 1)+
		` AND t.token_hash=$1 AND t.kind='access' AND t.expires_at>now() AND u.id=g.user_id`, oauthHash(token)).
		Scan(&p.GrantID, &p.UserID, &p.MailboxID, &p.WorkspaceID, &p.Slug, &p.Address, &lastUsed)
	if err != nil {
		return oauthPrincipal{}, errOAuthToken
	}
	if lastUsed == nil || time.Since(*lastUsed) > 5*time.Minute {
		s.pool.Exec(ctx, `UPDATE oauth_grants SET last_used_at=now() WHERE id=$1`, p.GrantID)
	}
	return p, nil
}

// oauthGrants serves GET /oauth/grants (the user's connected apps) and
// DELETE /oauth/grants/{id} (disconnect: every token of the grant dies).
func (s *Server) oauthGrants(w http.ResponseWriter, r *http.Request) {
	user, _ := account.CurrentUser(r.Context())
	ctx := r.Context()
	if id, ok := strings.CutPrefix(r.URL.Path, "/oauth/grants/"); ok {
		if r.Method != http.MethodDelete {
			writeErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", "use DELETE")
			return
		}
		tag, err := s.pool.Exec(ctx, `DELETE FROM oauth_grants WHERE id::text=$1 AND user_id=$2`, id, user.ID)
		if err != nil || tag.RowsAffected() == 0 {
			writeErrorEnvelope(w, http.StatusNotFound, "not_found", "connection not found")
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		writeErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}
	rows, err := s.pool.Query(ctx, `SELECT g.id::text,c.name,lower(m.local_part||'@'||d.domain),g.created_at,g.last_used_at
 FROM oauth_grants g JOIN oauth_clients c ON c.id=g.client_id JOIN mailboxes m ON m.id=g.mailbox_id JOIN domains d ON d.id=m.domain_id
 WHERE g.user_id=$1 ORDER BY g.created_at DESC`, user.ID)
	if err != nil {
		writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "lookup failed")
		return
	}
	type grant struct {
		ID         string     `json:"id"`
		Client     string     `json:"client"`
		Mailbox    string     `json:"mailbox"`
		CreatedAt  time.Time  `json:"created_at"`
		LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	}
	list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (grant, error) {
		var g grant
		return g, row.Scan(&g.ID, &g.Client, &g.Mailbox, &g.CreatedAt, &g.LastUsedAt)
	})
	if err != nil {
		writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"grants": list})
}
