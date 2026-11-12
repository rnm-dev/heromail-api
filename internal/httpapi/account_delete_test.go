package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rnm/heromail/backend/internal/inbound"
)

const deleteBody = `{"password":"correct-horse-battery"}`

func (h *harness) count(query string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		h.t.Fatalf("count %q: %v", query, err)
	}
	return n
}

func TestDeleteAccountNeedsThePassword(t *testing.T) {
	h := newHarness(t)
	token, _, _ := h.registerUser("delete-reauth")
	if r := h.do(http.MethodDelete, "/auth/me", deleteBody, ""); r.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", r.Code)
	}
	if r := h.do(http.MethodDelete, "/auth/me", `{"password":""}`, token); r.Code != http.StatusBadRequest {
		t.Fatalf("empty password: %d", r.Code)
	}
	if r := h.do(http.MethodDelete, "/auth/me", `{"password":"wrong-password-123"}`, token); r.Code != http.StatusForbidden || errorCode(t, r) != "invalid_password" {
		t.Fatalf("wrong password: %d %s", r.Code, r.Body)
	}
	if r := h.do(http.MethodGet, "/auth/me", "", token); r.Code != http.StatusOK {
		t.Fatal("a refused deletion still touched the account")
	}
}

func TestDeleteAccountRefusesTheSoleOwner(t *testing.T) {
	h := newHarness(t)
	token, userID, _ := h.registerUser("delete-sole")
	ws := h.workspaceFor(token, "delete-sole")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id = $1`, ws) })
	slug := h.slugFor(ws)
	// A plain member does not count as a second owner.
	_, memberID, _ := h.registerUser("delete-sole-member")
	h.pool.Exec(context.Background(), `INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1, $2, 'admin')`, ws, memberID)

	r := h.do(http.MethodDelete, "/auth/me", deleteBody, token)
	if r.Code != http.StatusConflict || errorCode(t, r) != "sole_owner" {
		t.Fatalf("sole owner: %d %s", r.Code, r.Body)
	}
	var body struct {
		Error struct {
			Details struct {
				Workspaces []string `json:"workspaces"`
			} `json:"details"`
		} `json:"error"`
	}
	json.Unmarshal(r.Body.Bytes(), &body)
	if len(body.Error.Details.Workspaces) != 1 || body.Error.Details.Workspaces[0] != slug {
		t.Fatalf("details: %s", r.Body)
	}
	// Nothing happened: the account, its session and its workspace are intact.
	if r := h.do(http.MethodGet, "/auth/me", "", token); r.Code != http.StatusOK {
		t.Fatal("refused deletion revoked the session")
	}
	if h.count(`SELECT count(*) FROM workspace_members WHERE user_id = $1`, userID) != 1 {
		t.Fatal("refused deletion left the workspace")
	}

	// The way out is deleting the workspace first (ownership transfer is a
	// support operation); then the account goes.
	if r := h.do(http.MethodDelete, "/workspaces/"+slug, "", token); r.Code != http.StatusNoContent {
		t.Fatalf("delete workspace: %d %s", r.Code, r.Body)
	}
	if r := h.do(http.MethodDelete, "/auth/me", deleteBody, token); r.Code != http.StatusNoContent {
		t.Fatalf("after deleting the workspace: %d %s", r.Code, r.Body)
	}
	// The former member keeps their own account.
	if h.count(`SELECT count(*) FROM users WHERE id = $1 AND deleted_at IS NULL`, memberID) != 1 {
		t.Fatal("member account touched")
	}
}

func TestDeleteAccountRemovesAccessAndPersonalData(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	// The account under test is an admin of a company workspace someone else owns.
	ownerToken, _, _ := h.registerUser("delete-full-owner")
	ws := h.workspaceFor(ownerToken, "delete-full")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id = $1`, ws) })
	slug := h.slugFor(ws)
	webToken, userID, addr := h.registerUser("delete-full")
	if _, err := h.pool.Exec(ctx, `INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1, $2, 'admin')`, ws, userID); err != nil {
		t.Fatal(err)
	}

	store := inbound.NewStore(h.pool)
	domainID := mustDomainID(t, h, h.verifiedDomainFor(t, ws))
	private, err := store.CreateMailbox(ctx, domainID, "private", "Private", &userID)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := store.Deliver(ctx, inbound.DeliverParams{MailboxID: private.ID, Raw: []byte("Subject: kept\r\n\r\nbody")})
	if err != nil {
		t.Fatal(err)
	}
	shared, err := store.CreateMailbox(ctx, domainID, "team", "Team", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, otherID, _ := h.registerUser("delete-full-colleague")
	h.pool.Exec(ctx, `INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1, $2, 'member')`, ws, otherID)
	for _, q := range []string{
		`INSERT INTO mailbox_members (mailbox_id, user_id) VALUES ('` + shared.ID + `', $1)`,
		`INSERT INTO mailbox_members (mailbox_id, user_id) VALUES ('` + shared.ID + `', '` + otherID + `')`,
		`INSERT INTO mailbox_assistant_keys (mailbox_id, user_id, key_hash, key_prefix) VALUES ('` + private.ID + `', $1, 'h', 'hm_ai_x')`,
		`INSERT INTO mailbox_smtp_credentials (mailbox_id, password_hash, issued_by) VALUES ('` + shared.ID + `', 'h', $1)`,
		`INSERT INTO contacts (id, user_id, name, email) VALUES (gen_random_uuid(), $1, 'Bob', 'bob@example.test')`,
		`INSERT INTO mail_signatures (workspace_id, user_id, sender, text_body) VALUES ('` + ws + `', $1, 'private@x', 'Regards')`,
	} {
		var args []any
		if strings.Contains(q, "$1") {
			args = append(args, userID)
		}
		if _, err := h.pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	phone := h.loginAs(addr, androidClient)
	h.do(http.MethodPut, "/devices/push", pushBody(newPushToken()), phone.Token)
	h.do(http.MethodPut, "/me/notification-settings", `{"version":0,"enabled":false,"privacy":true}`, webToken)
	h.mail.reset()

	if r := h.do(http.MethodDelete, "/auth/me", deleteBody, phone.Token); r.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", r.Code, r.Body)
	}

	// Every credential is dead.
	for name, tok := range map[string]string{"web": webToken, "phone": phone.Token} {
		if r := h.do(http.MethodGet, "/auth/me", "", tok); r.Code != http.StatusUnauthorized {
			t.Fatalf("%s session survived: %d", name, r.Code)
		}
	}
	if code, _, _ := h.refresh(*phone.RefreshToken); code != http.StatusUnauthorized {
		t.Fatalf("refresh token survived: %d", code)
	}
	if r := h.do(http.MethodPost, "/auth/login", fmt.Sprintf(`{"email":%q,"password":"correct-horse-battery"}`, addr), ""); r.Code != http.StatusUnauthorized {
		t.Fatalf("login after deletion: %d", r.Code)
	}
	for table, n := range map[string]int{
		"sessions":                 h.count(`SELECT count(*) FROM sessions WHERE user_id = $1`, userID),
		"push_devices":             h.count(`SELECT count(*) FROM push_devices WHERE user_id = $1`, userID),
		"identities":               h.count(`SELECT count(*) FROM identities WHERE user_id = $1`, userID),
		"mailbox_assistant_keys":   h.count(`SELECT count(*) FROM mailbox_assistant_keys WHERE user_id = $1`, userID),
		"mailbox_smtp_credentials": h.count(`SELECT count(*) FROM mailbox_smtp_credentials WHERE issued_by = $1`, userID),
		"contacts":                 h.count(`SELECT count(*) FROM contacts WHERE user_id = $1`, userID),
		"mail_signatures":          h.count(`SELECT count(*) FROM mail_signatures WHERE user_id = $1`, userID),
		"notification_settings":    h.count(`SELECT count(*) FROM notification_settings WHERE user_id = $1`, userID),
		"mailbox_members":          h.count(`SELECT count(*) FROM mailbox_members WHERE user_id = $1`, userID),
		"workspace_members":        h.count(`SELECT count(*) FROM workspace_members WHERE user_id = $1`, userID),
		"calendars":                h.count(`SELECT count(*) FROM calendars WHERE user_id = $1`, userID),
	} {
		if n != 0 {
			t.Errorf("%s: %d rows left", table, n)
		}
	}

	// The row is anonymised, not left with personal data.
	var email, name string
	var deleted bool
	h.pool.QueryRow(ctx, `SELECT email, name, deleted_at IS NOT NULL FROM users WHERE id = $1`, userID).Scan(&email, &name, &deleted)
	if !deleted || name != "" || !strings.HasSuffix(email, "@deleted.invalid") || strings.Contains(email, addr) {
		t.Fatalf("user row: %q %q deleted=%v", email, name, deleted)
	}

	// The corporate mailbox and its mail stay with the workspace — and stay
	// private: the other owner cannot read it.
	if h.count(`SELECT count(*) FROM messages WHERE id = $1`, msg.ID) != 1 {
		t.Fatal("corporate mail deleted with the account")
	}
	if r := h.do(http.MethodGet, "/workspaces/"+slug+"/mailboxes/"+private.ID+"/messages", "", ownerToken); r.Code != http.StatusNotFound {
		t.Fatalf("private mailbox opened to the workspace owner: %d", r.Code)
	}
	// The shared mailbox keeps its other members.
	if h.count(`SELECT count(*) FROM mailbox_members WHERE mailbox_id = $1`, shared.ID) != 1 {
		t.Fatal("shared mailbox lost its other members")
	}

	// Confirmation went to the original address and names what stayed.
	sent, ok := h.mail.last()
	if !ok || len(sent.To) != 1 || sent.To[0] != addr || !strings.Contains(sent.TextBody, "private@") {
		t.Fatalf("confirmation email: %+v", sent)
	}

	// The address is free to register again, as a new account.
	r := h.do(http.MethodPost, "/auth/register", fmt.Sprintf(`{"email":%q,"password":"another-password-2026"}`, addr), "")
	if r.Code != http.StatusCreated {
		t.Fatalf("re-register: %d %s", r.Code, r.Body)
	}
	var creds Credentials
	json.Unmarshal(r.Body.Bytes(), &creds)
	if creds.User.Id.String() == userID {
		t.Fatal("re-registration revived the deleted account")
	}
	if r := h.do(http.MethodGet, "/workspaces/"+slug+"/mailboxes", "", creds.Token); r.Code != http.StatusNotFound {
		t.Fatalf("new account inherited the old workspace: %d", r.Code)
	}
}

func TestDeleteAccountDeletesPersonalWorkspace(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	operator, _, _ := h.registerUser("delete-personal-operator")
	serviceWS := h.workspaceFor(operator, "delete-personal-service")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id = $1`, serviceWS) })
	h.pool.Exec(ctx, `INSERT INTO domains (workspace_id, domain, verification_token, verified_at)
		VALUES ($1, 'heromail.kz', 'test', now()) ON CONFLICT (domain) DO NOTHING`, serviceWS)

	token, userID, _ := h.registerUser("delete-personal")
	name := fmt.Sprintf("personal%d", time.Now().UnixNano())
	var ws, box string
	if err := h.pool.QueryRow(ctx, `INSERT INTO workspaces (slug, name, personal_owner_id) VALUES ($1, $1, $2) RETURNING id`, name, userID).Scan(&ws); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id = $1`, ws) })
	h.pool.Exec(ctx, `INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1, $2, 'owner')`, ws, userID)
	if err := h.pool.QueryRow(ctx, `INSERT INTO mailboxes (domain_id, local_part, personal_workspace_id)
		SELECT id, $1, $2 FROM domains WHERE domain = 'heromail.kz' RETURNING id`, name, ws).Scan(&box); err != nil {
		t.Fatal(err)
	}
	if _, err := inbound.NewStore(h.pool).Deliver(ctx, inbound.DeliverParams{MailboxID: box, Raw: []byte("Subject: mine\r\n\r\nx")}); err != nil {
		t.Fatal(err)
	}

	// Owning only a personal workspace is not "sole owner": it goes with the account.
	if r := h.do(http.MethodDelete, "/auth/me", deleteBody, token); r.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", r.Code, r.Body)
	}
	if h.count(`SELECT count(*) FROM workspaces WHERE id = $1`, ws) != 0 ||
		h.count(`SELECT count(*) FROM mailboxes WHERE id = $1`, box) != 0 ||
		h.count(`SELECT count(*) FROM messages WHERE mailbox_id = $1`, box) != 0 {
		t.Fatal("personal workspace, mailbox or mail survived")
	}
	// The service domain hosting it is untouched.
	if h.count(`SELECT count(*) FROM domains WHERE domain = 'heromail.kz'`) != 1 {
		t.Fatal("service domain removed")
	}
}

func TestAccountDeletionPageIsPublic(t *testing.T) {
	h := newHarness(t)
	r := h.do(http.MethodGet, "/account-deletion", "", "")
	if r.Code != http.StatusOK || !strings.HasPrefix(r.Header().Get("Content-Type"), "text/html") || !strings.Contains(r.Body.String(), "Удалить аккаунт") {
		t.Fatalf("page: %d %s", r.Code, r.Header())
	}
}
