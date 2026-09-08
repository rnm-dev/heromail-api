package httpapi

import (
	"context"
	"fmt"
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
