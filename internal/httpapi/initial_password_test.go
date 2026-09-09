package httpapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/emersion/go-imap"
	"github.com/rnm/heromail/backend/internal/imapservice"
	"github.com/rnm/heromail/backend/internal/inbound"
	"testing"
)

func TestInitialPasswordGate(t *testing.T) {
	h := newHarness(t)
	ctx := t.Context()
	old, userID, email := h.registerUser("initial-password")
	ws := h.workspaceFor(old, "initial-password")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	domain := h.verifiedDomainFor(t, ws)
	box, err := inbound.NewStore(h.pool).CreateMailbox(ctx, mustDomainID(t, h, domain), "employee", "Employee", &userID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.pool.Exec(ctx, `UPDATE users SET must_change_password=true WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	login := h.do("POST", "/auth/login", fmt.Sprintf(`{"email":%q,"password":"correct-horse-battery"}`, email), "")
	if login.Code != 200 {
		t.Fatal(login.Body)
	}
	var creds Credentials
	if err = json.Unmarshal(login.Body.Bytes(), &creds); err != nil {
		t.Fatal(err)
	}
	if !creds.User.MustChangePassword {
		t.Fatal("missing mandatory change flag")
	}
	for _, token := range []string{old, creds.Token} {
		for _, path := range []string{"/workspaces", "/messages/search?q=secret", "/workspaces/" + h.slugFor(ws) + "/mailboxes"} {
			r := h.do("GET", path, "", token)
			if r.Code != 403 {
				t.Fatalf("bypass %s: %d", path, r.Code)
			}
		}
	}
	if r := h.do("GET", "/auth/me", "", creds.Token); r.Code != 200 {
		t.Fatal(r.Body)
	}
	im := imapservice.New(h.pool, nil)
	if _, err = im.Login(&imap.ConnInfo{TLS: &tls.ConnectionState{}}, box.Address, "correct-horse-battery"); err == nil {
		t.Fatal("initial password allowed IMAP")
	}
	for _, body := range []string{`{"current_password":"wrong","password":"replacement-password-2026"}`, `{"current_password":"correct-horse-battery","password":"correct-horse-battery"}`, `{"current_password":"correct-horse-battery","password":"short"}`} {
		r := h.do("POST", "/auth/change-initial-password", body, creds.Token)
		if r.Code != 400 && r.Code != 403 {
			t.Fatalf("invalid password accepted: %d", r.Code)
		}
	}
	body := `{"current_password":"correct-horse-battery","password":"replacement-password-2026"}`
	if r := h.do("POST", "/auth/change-initial-password", body, h.apiKeyFor(ws)); r.Code != 401 {
		t.Fatal("API key accepted")
	}
	result := h.do("POST", "/auth/change-initial-password", body, creds.Token)
	if result.Code != 200 {
		t.Fatal(result.Body)
	}
	var fresh Credentials
	json.Unmarshal(result.Body.Bytes(), &fresh)
	if fresh.User.MustChangePassword || fresh.User.EmailVerified {
		t.Fatal("incorrect completion flags")
	}
	if r := h.do("GET", "/workspaces", "", fresh.Token); r.Code != 200 {
		t.Fatal(r.Body)
	}
	for _, token := range []string{old, creds.Token} {
		if r := h.do("GET", "/auth/me", "", token); r.Code != 401 {
			t.Fatal("old session survived")
		}
	}
	if r := h.do("POST", "/auth/login", fmt.Sprintf(`{"email":%q,"password":"correct-horse-battery"}`, email), ""); r.Code != 401 {
		t.Fatal("old password accepted")
	}
	if _, err = im.Login(&imap.ConnInfo{TLS: &tls.ConnectionState{}}, box.Address, "replacement-password-2026"); err != nil {
		t.Fatal(err)
	}
	if r := h.do("POST", "/auth/change-initial-password", body, fresh.Token); r.Code != 409 {
		t.Fatal("repeat change allowed")
	}
}
