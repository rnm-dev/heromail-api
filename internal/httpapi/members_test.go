package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

func TestOwnerMemberManagement(t *testing.T) {
	h := newHarness(t)
	owner, ownerID, _ := h.registerUser("members-owner")
	member, memberID, email := h.registerUser("members-user")
	outsider, _, _ := h.registerUser("members-outsider")
	wsID := h.workspaceFor(owner, "members")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, wsID) })
	var slug string
	if err := h.pool.QueryRow(context.Background(), `SELECT slug FROM workspaces WHERE id=$1`, wsID).Scan(&slug); err != nil {
		t.Fatal(err)
	}
	path := "/workspaces/" + slug + "/members"
	check := func(method, path, body, token string, want int) {
		t.Helper()
		r := h.do(method, path, body, token)
		if r.Code != want {
			t.Fatalf("%s %s: got %d want %d: %s", method, path, r.Code, want, r.Body)
		}
	}
	check("GET", path, "", "", 401)
	check("GET", path, "", outsider, 404)
	check("POST", path, fmt.Sprintf(`{"email":%q,"role":"owner"}`, email), owner, 400)
	check("POST", path, fmt.Sprintf(`{"email":%q,"role":"member"}`, email), owner, 201)
	check("POST", path, fmt.Sprintf(`{"email":%q,"role":"member"}`, email), owner, 409)
	check("GET", path, "", owner, 200)
	check("GET", path, "", member, 403)
	check("PATCH", path+"/"+ownerID, `{"role":"member"}`, owner, 409)
	check("DELETE", path+"/"+ownerID, "", owner, 409)
	check("PATCH", path+"/"+memberID, `{"role":"admin"}`, member, 403)
	check("PATCH", path+"/"+memberID, `{"role":"admin"}`, outsider, 404)
	check("PATCH", path+"/"+memberID, `{"role":"admin"}`, owner, 204)
	check("GET", path, "", member, 403) // Admins cannot manage users either.
	check("DELETE", path+"/"+memberID, "", member, 403)
	check("DELETE", path+"/"+memberID, "", owner, 204)
	check("GET", "/workspaces/"+slug+"/domains", "", member, 404)
	check("GET", path, "", h.apiKeyFor(wsID), 401)
	check("POST", path, `{"email":"missing@invalid.test","role":"member"}`, owner, 404)
}

func TestOwnerProvisionsWorkspaceUser(t *testing.T) {
	h := newHarness(t)
	owner, _, _ := h.registerUser("provision-owner")
	workspaceID := h.workspaceFor(owner, "provision-user")
	slug := h.slugFor(workspaceID)
	domain := h.verifiedDomainFor(t, workspaceID)
	email := "new.employee@" + domain

	rec := h.do(http.MethodPost, "/workspaces/"+slug+"/users", fmt.Sprintf(`{"name":"New Employee","email":%q}`, email), owner)
	if rec.Code != http.StatusCreated {
		t.Fatalf("provision: %d %s", rec.Code, rec.Body.String())
	}
	var result struct {
		TemporaryPassword string `json:"temporary_password"`
		User              Member `json:"user"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.TemporaryPassword == "" || result.User.Email != email || result.User.Role != RoleMember {
		t.Fatalf("unexpected response: %+v", result)
	}
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, result.User.Id) })

	login := h.do(http.MethodPost, "/auth/login", fmt.Sprintf(`{"email":%q,"password":%q}`, email, result.TemporaryPassword), "")
	if login.Code != http.StatusOK {
		t.Fatalf("temporary login: %d %s", login.Code, login.Body.String())
	}
	var creds struct {
		Token string `json:"token"`
		User  struct {
			MustChangePassword bool `json:"must_change_password"`
		} `json:"user"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &creds); err != nil {
		t.Fatal(err)
	}
	if !creds.User.MustChangePassword {
		t.Fatal("provisioned user is not forced to replace password")
	}
	if got := h.do(http.MethodGet, "/workspaces", "", creds.Token); got.Code != http.StatusForbidden {
		t.Fatalf("restricted session got %d", got.Code)
	}

	var mailboxOwner string
	if err := h.pool.QueryRow(t.Context(), `SELECT m.owner_user_id FROM mailboxes m JOIN domains d ON d.id=m.domain_id WHERE m.local_part='new.employee' AND d.domain=$1`, domain).Scan(&mailboxOwner); err != nil {
		t.Fatal(err)
	}
	if mailboxOwner != result.User.Id.String() {
		t.Fatalf("mailbox owner %s, want %s", mailboxOwner, result.User.Id)
	}

	duplicate := h.do(http.MethodPost, "/workspaces/"+slug+"/users", fmt.Sprintf(`{"name":"Again","email":%q}`, email), owner)
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate: %d %s", duplicate.Code, duplicate.Body.String())
	}
}
