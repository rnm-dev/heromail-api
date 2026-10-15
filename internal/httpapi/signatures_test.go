package httpapi

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestMailSignatures(t *testing.T) {
	h := newHarness(t)
	owner, _, _ := h.registerUser("signature-owner")
	employee, employeeID, _ := h.registerUser("signature-employee")
	ws := h.workspaceFor(owner, "signatures")
	slug := h.slugFor(ws)
	domain := h.verifiedDomainFor(t, ws)
	t.Cleanup(func() { h.pool.Exec(t.Context(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	if _, err := h.pool.Exec(t.Context(), `INSERT INTO workspace_members(workspace_id,user_id,role) VALUES($1,$2,'member')`, ws, employeeID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(t.Context(), `INSERT INTO mailboxes(domain_id,local_part,owner_user_id) SELECT id,'private',$3 FROM domains WHERE workspace_id=$1 AND domain=$2`, ws, domain, employeeID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(t.Context(), `INSERT INTO mailboxes(domain_id,local_part) SELECT id,'shared' FROM domains WHERE workspace_id=$1 AND domain=$2`, ws, domain); err != nil {
		t.Fatal(err)
	}
	path := "/workspaces/" + slug + "/mail-signatures"
	save := func(token, address, text string, version, status int) MailSignature {
		t.Helper()
		r := h.do("PUT", path, fmt.Sprintf(`{"sender":%q,"text":%q,"version":%d}`, address, text, version), token)
		if r.Code != status {
			t.Fatalf("save: %d %s", r.Code, r.Body)
		}
		var sig MailSignature
		if status == 200 {
			json.Unmarshal(r.Body.Bytes(), &sig)
		}
		return sig
	}
	for _, token := range []string{"", h.apiKeyFor(ws)} {
		if r := h.do("GET", path, "", token); r.Code != 401 {
			t.Fatalf("credential: %d", r.Code)
		}
	}
	private := "private@" + domain
	shared := "shared@" + domain
	save(owner, private, "Manager cannot use private sender", 0, 404)
	save(owner, "unknown@"+domain, "Not a mailbox", 0, 404)
	sig := save(employee, private, "С уважением, сотрудник", 0, 200)
	if sig.Version != 1 {
		t.Fatal(sig.Version)
	}
	sig = save(employee, private, "С уважением, сотрудник", 0, 200)
	if sig.Version != 1 {
		t.Fatal("lost response advanced version")
	}
	save(employee, private, "stale", 0, 409)
	save(employee, private, "Updated", 1, 200)
	save(employee, private, "concurrent", 1, 409)
	save(employee, private, "", 2, 200)
	save(owner, shared, "Owner's shared signature", 0, 200)
	save(employee, shared, "Employee's shared signature", 0, 200)
	for _, token := range []string{owner, employee} {
		r := h.do("GET", path, "", token)
		if r.Code != 200 {
			t.Fatal(r.Body)
		}
		if token == owner && strings.Contains(r.Body.String(), "Employee's") {
			t.Fatal("signature leak")
		}
		if token == employee && strings.Contains(r.Body.String(), "Owner's") {
			t.Fatal("signature leak")
		}
	}
	save(employee, shared, strings.Repeat("я", 10001), 1, 400)
	if _, err := h.pool.Exec(t.Context(), `DELETE FROM workspace_members WHERE workspace_id=$1 AND user_id=$2`, ws, employeeID); err != nil {
		t.Fatal(err)
	}
	if r := h.do("GET", path, "", employee); r.Code != 404 {
		t.Fatalf("revoked: %d", r.Code)
	}
}
