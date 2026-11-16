package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/rnm/heromail/backend/internal/inbound"
)

// TestMCPConnector walks the claude.ai path end to end: discovery, dynamic
// registration, consent for one owned mailbox, PKCE code exchange, MCP calls
// confined to that mailbox, refresh rotation, disconnect and lost ownership.
func TestMCPConnector(t *testing.T) {
	h := newHarness(t)
	ctx := t.Context()
	owner, ownerID, _ := h.registerUser("mcp-owner")
	ws := h.workspaceFor(owner, "mcp-test")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	domain := h.verifiedDomainFor(t, ws)
	path := "/workspaces/" + h.slugFor(ws)
	mailbox := func(local, ownerUser string) string {
		r := h.do("POST", path+"/mailboxes", fmt.Sprintf(`{"domain":%q,"local_part":%q,"owner_user_id":%q}`, domain, local, ownerUser), owner)
		if r.Code != 201 {
			t.Fatalf("mailbox %s: %d %s", local, r.Code, r.Body)
		}
		var m Mailbox
		json.Unmarshal(r.Body.Bytes(), &m)
		return m.Id.String()
	}
	mine, other := mailbox("me", ownerID), mailbox("shared", ownerID)
	store := inbound.NewStore(h.pool)
	deliver := func(box, subject, body string) string {
		var address string
		h.pool.QueryRow(ctx, `SELECT lower(m.local_part||'@'||d.domain) FROM mailboxes m JOIN domains d ON d.id=m.domain_id WHERE m.id=$1`, box).Scan(&address)
		msg, err := store.Deliver(ctx, inbound.DeliverParams{MailboxID: box, EnvelopeFrom: "boss@example.test", EnvelopeTo: address,
			Raw: []byte("From: Boss <boss@example.test>\r\nTo: " + address + "\r\nSubject: " + subject + "\r\n\r\n" + body)})
		if err != nil {
			t.Fatal(err)
		}
		return msg.ID
	}
	inboxMsg := deliver(mine, "Quarterly plan", "Please review.\r\n\r\nOn Mon, Boss wrote:\r\n> old quoted text")
	foreignMsg := deliver(other, "Not yours", "secret")

	// Discovery.
	r := h.do("POST", "/mcp", `{}`, "")
	if r.Code != 401 || !strings.Contains(r.Header().Get("WWW-Authenticate"), "/.well-known/oauth-protected-resource") {
		t.Fatalf("mcp without token: %d %v", r.Code, r.Header())
	}
	var meta map[string]any
	r = h.do("GET", "/.well-known/oauth-authorization-server", "", "")
	json.Unmarshal(r.Body.Bytes(), &meta)
	if r.Code != 200 || meta["registration_endpoint"] == nil || !strings.HasSuffix(fmt.Sprint(meta["authorization_endpoint"]), "/oauth/authorize") {
		t.Fatalf("metadata: %d %s", r.Code, r.Body)
	}

	// Registration rejects unsafe redirects, then accepts claude.ai's.
	if r = h.do("POST", "/oauth/register", `{"client_name":"x","redirect_uris":["http://evil.test/cb"]}`, ""); r.Code != 400 {
		t.Fatalf("http redirect accepted: %d", r.Code)
	}
	redirect := "https://claude.ai/api/mcp/auth_callback"
	r = h.do("POST", "/oauth/register", fmt.Sprintf(`{"client_name":"Claude","redirect_uris":[%q]}`, redirect), "")
	var client struct {
		ClientID string `json:"client_id"`
	}
	json.Unmarshal(r.Body.Bytes(), &client)
	if r.Code != 201 || client.ClientID == "" {
		t.Fatalf("register: %d %s", r.Code, r.Body)
	}

	// Consent page data, then approval with PKCE.
	q := url.Values{"client_id": {client.ClientID}, "redirect_uri": {redirect}}
	if r = h.do("GET", "/oauth/client?"+q.Encode(), "", owner); r.Code != 200 || !strings.Contains(r.Body.String(), `"Claude"`) || !strings.Contains(r.Body.String(), mine) {
		t.Fatalf("client info: %d %s", r.Code, r.Body)
	}
	if r = h.do("GET", "/oauth/client?client_id="+client.ClientID+"&redirect_uri=https://evil.test/cb", "", owner); r.Code != 400 {
		t.Fatalf("foreign redirect: %d", r.Code)
	}
	verifier := strings.Repeat("v", 50)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	approve := func(token, box string) *httptest.ResponseRecorder {
		return h.do("POST", "/oauth/approve", fmt.Sprintf(`{"client_id":%q,"redirect_uri":%q,"code_challenge":%q,"code_challenge_method":"S256","state":"st8","mailbox_id":%q}`,
			client.ClientID, redirect, challenge, box), token)
	}
	if r = approve("", mine); r.Code != 401 {
		t.Fatalf("anonymous approve: %d", r.Code)
	}
	stranger, _, _ := h.registerUser("mcp-stranger")
	if r = approve(stranger, mine); r.Code != 403 {
		t.Fatalf("stranger approve: %d", r.Code)
	}
	r = approve(owner, mine)
	var approved struct{ Redirect string }
	json.Unmarshal(r.Body.Bytes(), &approved)
	back, _ := url.Parse(approved.Redirect)
	code := back.Query().Get("code")
	if r.Code != 200 || back.Query().Get("state") != "st8" || code == "" || !strings.HasPrefix(approved.Redirect, redirect+"?") {
		t.Fatalf("approve: %d %s", r.Code, r.Body)
	}

	token := func(form url.Values) (int, map[string]any) {
		req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	exchange := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "client_id": {client.ClientID}}
	bad := url.Values{}
	for k, v := range exchange {
		bad[k] = v
	}
	bad.Set("code_verifier", strings.Repeat("w", 50))
	if status, _ := token(bad); status != 400 {
		t.Fatalf("wrong verifier accepted: %d", status)
	}
	// The failed attempt spent the code: codes are single-use.
	exchange.Set("code_verifier", verifier)
	if status, _ := token(exchange); status != 400 {
		t.Fatalf("spent code accepted: %d", status)
	}
	r = approve(owner, mine)
	json.Unmarshal(r.Body.Bytes(), &approved)
	back, _ = url.Parse(approved.Redirect)
	exchange.Set("code", back.Query().Get("code"))
	status, tokens := token(exchange)
	access, _ := tokens["access_token"].(string)
	refresh, _ := tokens["refresh_token"].(string)
	if status != 200 || access == "" || refresh == "" {
		t.Fatalf("token: %d %v", status, tokens)
	}

	rpc := func(bearer, method string, params any) (int, map[string]any) {
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
		r := h.do("POST", "/mcp", string(body), bearer)
		var out map[string]any
		json.Unmarshal(r.Body.Bytes(), &out)
		return r.Code, out
	}
	callTool := func(bearer, name string, args map[string]any) (string, bool) {
		status, out := rpc(bearer, "tools/call", map[string]any{"name": name, "arguments": args})
		if status != 200 || out["result"] == nil {
			t.Fatalf("%s: %d %v", name, status, out)
		}
		res := out["result"].(map[string]any)
		text := res["content"].([]any)[0].(map[string]any)["text"].(string)
		isErr, _ := res["isError"].(bool)
		return text, isErr
	}
	if status, out := rpc(access, "initialize", map[string]any{"protocolVersion": "2025-06-18"}); status != 200 || out["result"].(map[string]any)["protocolVersion"] != "2025-06-18" {
		t.Fatalf("initialize: %d %v", status, out)
	}
	if r = h.do("POST", "/mcp", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, access); r.Code != 202 {
		t.Fatalf("notification: %d", r.Code)
	}
	if _, out := rpc(access, "tools/list", nil); len(out["result"].(map[string]any)["tools"].([]any)) < 10 {
		t.Fatalf("tools/list: %v", out)
	}
	text, isErr := callTool(access, "list_messages", nil)
	if isErr || !strings.Contains(text, "Quarterly plan") || strings.Contains(text, "Not yours") {
		t.Fatalf("list_messages: %s", text)
	}
	text, isErr = callTool(access, "read_message", map[string]any{"id": inboxMsg})
	if isErr || !strings.Contains(text, "Please review.") || strings.Contains(text, "old quoted text") {
		t.Fatalf("read_message: %s", text)
	}
	if text, isErr = callTool(access, "read_message", map[string]any{"id": foreignMsg}); !isErr {
		t.Fatalf("foreign message readable: %s", text)
	}
	if text, isErr = callTool(access, "mark_messages", map[string]any{"ids": []string{foreignMsg}, "read": true}); isErr || !strings.Contains(text, "failed") {
		t.Fatalf("foreign flag: %s", text)
	}
	if text, isErr = callTool(access, "mark_messages", map[string]any{"ids": []string{inboxMsg}, "starred": true}); isErr || !strings.Contains(text, `"done":1`) {
		t.Fatalf("mark: %s", text)
	}
	h.mail.reset()
	text, isErr = callTool(access, "send_email", map[string]any{"reply_to_message_id": inboxMsg, "text": "Looks good."})
	if isErr || !strings.Contains(text, `"queued":true`) || !strings.Contains(text, "Re: Quarterly plan") || !strings.Contains(text, "boss@example.test") {
		t.Fatalf("send: %s", text)
	}
	if text, isErr = callTool(access, "list_events", nil); isErr {
		t.Fatalf("list_events: %s", text)
	}

	// Refresh rotates: the old refresh token is spent.
	refreshForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {client.ClientID}}
	status, rotated := token(refreshForm)
	if status != 200 || rotated["refresh_token"] == refresh {
		t.Fatalf("refresh: %d %v", status, rotated)
	}
	if status, _ = token(refreshForm); status != 400 {
		t.Fatalf("refresh reuse: %d", status)
	}
	access = rotated["access_token"].(string)

	// The user sees the connection and can disconnect it.
	r = h.do("GET", "/oauth/grants", "", owner)
	var grants struct {
		Grants []struct{ ID, Client, Mailbox string }
	}
	json.Unmarshal(r.Body.Bytes(), &grants)
	if r.Code != 200 || len(grants.Grants) == 0 || grants.Grants[0].Client != "Claude" {
		t.Fatalf("grants: %d %s", r.Code, r.Body)
	}
	// Losing ownership cuts access at once.
	if _, err := h.pool.Exec(ctx, `UPDATE mailboxes SET owner_user_id=NULL WHERE id=$1`, mine); err != nil {
		t.Fatal(err)
	}
	if status, _ := rpc(access, "ping", nil); status != 401 {
		t.Fatalf("access after ownership loss: %d", status)
	}
	h.pool.Exec(ctx, `UPDATE mailboxes SET owner_user_id=$2 WHERE id=$1`, mine, ownerID)
	if status, _ := rpc(access, "ping", nil); status != 200 {
		t.Fatalf("access restored: %d", status)
	}
	for _, g := range grants.Grants {
		if r = h.do("DELETE", "/oauth/grants/"+g.ID, "", stranger); r.Code != 404 {
			t.Fatalf("stranger disconnect: %d", r.Code)
		}
		if r = h.do("DELETE", "/oauth/grants/"+g.ID, "", owner); r.Code != http.StatusNoContent {
			t.Fatalf("disconnect: %d", r.Code)
		}
	}
	if status, _ := rpc(access, "ping", nil); status != 401 {
		t.Fatalf("access after disconnect: %d", status)
	}
}
