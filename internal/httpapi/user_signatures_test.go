package httpapi

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestUserSignatures(t *testing.T) {
	h := newHarness(t)
	owner, _, _ := h.registerUser("usig-owner")
	employee, employeeID, _ := h.registerUser("usig-employee")
	ws := h.workspaceFor(owner, "usig")
	slug := h.slugFor(ws)
	domain := h.verifiedDomainFor(t, ws)
	t.Cleanup(func() { h.pool.Exec(t.Context(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	if _, err := h.pool.Exec(t.Context(), `INSERT INTO workspace_members(workspace_id,user_id,role) VALUES($1,$2,'member')`, ws, employeeID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(t.Context(), `INSERT INTO mailboxes(domain_id,local_part,owner_user_id) SELECT id,'private',$3 FROM domains WHERE workspace_id=$1 AND domain=$2`, ws, domain, employeeID); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"", h.apiKeyFor(ws)} {
		if r := h.do("GET", "/signatures", "", token); r.Code != 401 {
			t.Fatalf("credential: %d", r.Code)
		}
	}
	if r := h.do("POST", "/signatures", `{"name":" ","html":"x"}`, employee); r.Code != 400 {
		t.Fatalf("empty name: %d", r.Code)
	}
	r := h.do("POST", "/signatures", `{"name":"Работа","html":"<b>Азамат</b>"}`, employee)
	if r.Code != 201 {
		t.Fatalf("create: %d %s", r.Code, r.Body)
	}
	var sig userSignature
	json.Unmarshal(r.Body.Bytes(), &sig)
	if r := h.do("PUT", "/signatures/"+sig.ID, `{"name":"Чужая","html":""}`, owner); r.Code != 404 {
		t.Fatalf("foreign edit: %d", r.Code)
	}
	if r := h.do("PUT", "/signatures/"+sig.ID, `{"name":"Основная","html":"<i>A</i>"}`, employee); r.Code != 200 {
		t.Fatalf("edit: %d", r.Code)
	}
	var list struct{ Signatures []userSignature }
	json.Unmarshal(h.do("GET", "/signatures", "", employee).Body.Bytes(), &list)
	if len(list.Signatures) != 1 || list.Signatures[0].Name != "Основная" || list.Signatures[0].HTML != "<i>A</i>" {
		t.Fatalf("list: %+v", list)
	}
	json.Unmarshal(h.do("GET", "/signatures", "", owner).Body.Bytes(), &list)
	if len(list.Signatures) != 0 {
		t.Fatal("signatures leak between users")
	}

	path := "/workspaces/" + slug + "/signature-defaults"
	private := "private@" + domain
	body := fmt.Sprintf(`{"sender":%q,"new_id":%q,"reply_id":null}`, private, sig.ID)
	if r := h.do("PUT", path, body, owner); r.Code != 404 {
		t.Fatalf("manager on private sender: %d", r.Code)
	}
	ownerSig := h.do("POST", "/signatures", `{"name":"Owner","html":"o"}`, owner)
	var foreign userSignature
	json.Unmarshal(ownerSig.Body.Bytes(), &foreign)
	if r := h.do("PUT", path, fmt.Sprintf(`{"sender":%q,"new_id":%q}`, private, foreign.ID), employee); r.Code != 404 {
		t.Fatalf("foreign signature as default: %d", r.Code)
	}
	if r := h.do("PUT", path, body, employee); r.Code != 200 {
		t.Fatalf("default: %d %s", r.Code, r.Body)
	}
	var defaults struct{ Defaults []signatureDefault }
	json.Unmarshal(h.do("GET", path, "", employee).Body.Bytes(), &defaults)
	if len(defaults.Defaults) != 1 || *defaults.Defaults[0].NewID != sig.ID || defaults.Defaults[0].ReplyID != nil {
		t.Fatalf("defaults: %+v", defaults)
	}
	if r := h.do("DELETE", "/signatures/"+sig.ID, "", employee); r.Code != 204 {
		t.Fatalf("delete: %d", r.Code)
	}
	json.Unmarshal(h.do("GET", path, "", employee).Body.Bytes(), &defaults)
	if defaults.Defaults[0].NewID != nil {
		t.Fatal("deleted signature stays default")
	}
}
