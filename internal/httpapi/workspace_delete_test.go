package httpapi

import (
	"context"
	"fmt"
	"testing"
)

func TestWorkspaceDeletionOwnerOnly(t *testing.T) {
	h := newHarness(t)
	owner, ownerID, _ := h.registerUser("delete-owner")
	admin, adminID, _ := h.registerUser("delete-admin")
	member, memberID, _ := h.registerUser("delete-member")
	outsider, _, _ := h.registerUser("delete-outsider")
	id := h.workspaceFor(owner, "delete-ws")
	otherID := h.workspaceFor(owner, "keep-ws")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id IN ($1,$2)`, id, otherID) })
	var slug string
	if err := h.pool.QueryRow(context.Background(), `SELECT slug FROM workspaces WHERE id=$1`, id).Scan(&slug); err != nil {
		t.Fatal(err)
	}
	_, err := h.pool.Exec(context.Background(), `INSERT INTO workspace_members(workspace_id,user_id,role) VALUES($1,$2,'admin'),($1,$3,'member')`, id, adminID, memberID)
	if err != nil {
		t.Fatal(err)
	}
	path := "/workspaces/" + slug
	for _, tc := range []struct {
		token  string
		status int
	}{{"", 401}, {outsider, 404}, {admin, 403}, {member, 403}, {h.apiKeyFor(id), 401}} {
		r := h.do("DELETE", path, "", tc.token)
		if r.Code != tc.status {
			t.Fatalf("delete: got %d want %d: %s", r.Code, tc.status, r.Body)
		}
	}
	domain := fmt.Sprintf("%s.test", slug)
	r := h.do("POST", path+"/domains", fmt.Sprintf(`{"domain":%q}`, domain), owner)
	if r.Code != 201 {
		t.Fatalf("add domain: %d %s", r.Code, r.Body)
	}
	// Include stored inbound data to verify the domain -> mailbox -> message cascade.
	var domainID, boxID string
	if err := h.pool.QueryRow(context.Background(), `SELECT id FROM domains WHERE workspace_id=$1`, id).Scan(&domainID); err != nil {
		t.Fatal(err)
	}
	if err := h.pool.QueryRow(context.Background(), `INSERT INTO mailboxes(domain_id,local_part) VALUES($1,'test') RETURNING id`, domainID).Scan(&boxID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(context.Background(), `INSERT INTO messages(mailbox_id,envelope_to,raw,size_bytes) VALUES($1,$2,$3,4)`, boxID, "test@"+domain, []byte("test")); err != nil {
		t.Fatal(err)
	}

	r = h.do("DELETE", path, "", owner)
	if r.Code != 204 {
		t.Fatalf("delete owner: %d %s", r.Code, r.Body)
	}
	for _, table := range []string{"workspace_members", "domains", "api_keys"} {
		var n int
		if err := h.pool.QueryRow(context.Background(), `SELECT count(*) FROM `+table+` WHERE workspace_id=$1`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("%s still has %d rows", table, n)
		}
	}
	var n int
	if err := h.pool.QueryRow(context.Background(), `SELECT count(*) FROM mailboxes WHERE id=$1`, boxID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("mailbox remains: %d %v", n, err)
	}
	if err := h.pool.QueryRow(context.Background(), `SELECT count(*) FROM messages WHERE mailbox_id=$1`, boxID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("messages remain: %d %v", n, err)
	}

	if err := h.pool.QueryRow(context.Background(), `SELECT count(*) FROM users WHERE id IN ($1,$2,$3)`, ownerID, adminID, memberID).Scan(&n); err != nil || n != 3 {
		t.Fatalf("accounts removed: %d %v", n, err)
	}
	if err := h.pool.QueryRow(context.Background(), `SELECT count(*) FROM workspaces WHERE id=$1`, otherID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("other workspace changed: %d %v", n, err)
	}
	if r = h.do("GET", path, "", owner); r.Code != 404 {
		t.Fatalf("deleted workspace visible: %d", r.Code)
	}
	if r = h.do("DELETE", path, "", owner); r.Code != 404 {
		t.Fatalf("repeat deletion: %d", r.Code)
	}
}
