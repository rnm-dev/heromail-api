package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/rnm/heromail/backend/internal/inbound"
	"testing"
)

func TestPrivateMailboxAccess(t *testing.T) {
	h := newHarness(t)
	ctx := t.Context()
	owner, _, _ := h.registerUser("private-manager")
	employee, employeeID, _ := h.registerUser("private-employee")
	other, otherID, _ := h.registerUser("private-other")
	ws := h.workspaceFor(owner, "private-test")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	if _, err := h.pool.Exec(ctx, `INSERT INTO workspace_members(workspace_id,user_id,role) VALUES($1,$2,'member'),($1,$3,'member')`, ws, employeeID, otherID); err != nil {
		t.Fatal(err)
	}
	domain := h.verifiedDomainFor(t, ws)
	path := "/workspaces/" + h.slugFor(ws)
	r := h.do("POST", path+"/mailboxes", fmt.Sprintf(`{"domain":%q,"local_part":"employee","owner_user_id":%q}`, domain, employeeID), owner)
	if r.Code != 201 {
		t.Fatalf("create private: %d %s", r.Code, r.Body)
	}
	var box Mailbox
	if err := json.Unmarshal(r.Body.Bytes(), &box); err != nil {
		t.Fatal(err)
	}
	store := inbound.NewStore(h.pool)
	msg, err := store.Deliver(ctx, inbound.DeliverParams{MailboxID: box.Id.String(), EnvelopeFrom: "hello@example.test", EnvelopeTo: string(box.Address), Raw: []byte("From: hello@example.test\r\nSubject: Private secret\r\n\r\nprivate body")})
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{owner, other} {
		for _, route := range []string{path + "/mailboxes/" + box.Id.String() + "/messages", path + "/messages/" + msg.ID} {
			if r = h.do("GET", route, "", token); r.Code != 404 {
				t.Fatalf("private read leak: %d %s", r.Code, r.Body)
			}
		}
		if r = h.do("POST", path+"/messages/"+msg.ID, "", token); r.Code != 404 {
			t.Fatal("private read flag changed")
		}
	}
	if r = h.do("GET", path+"/messages/"+msg.ID, "", employee); r.Code != 200 {
		t.Fatalf("employee read: %d %s", r.Code, r.Body)
	}
	send := fmt.Sprintf(`{"from":%q,"to":["to@example.test"],"subject":"Private outbound secret","text":"secret body"}`, box.Address)
	if r = h.do("POST", path+"/emails", send, owner); r.Code != 400 {
		t.Fatal("manager spoofed private address")
	}
	if r = h.do("POST", "/v1/emails", send, h.apiKeyFor(ws)); r.Code != 400 {
		t.Fatal("workspace key spoofed private address")
	}
	r = h.do("POST", path+"/emails", send, employee)
	if r.Code != 202 {
		t.Fatalf("employee send: %d %s", r.Code, r.Body)
	}
	var sent struct {
		ID string `json:"id"`
	}
	json.Unmarshal(r.Body.Bytes(), &sent)
	for _, token := range []string{owner, other} {
		if r = h.do("GET", path+"/emails/"+sent.ID, "", token); r.Code != 404 {
			t.Fatal("private outbound detail leak")
		}
		r = h.do("GET", "/messages/search?q=Private%20outbound%20secret", "", token)
		if r.Code != 200 || string(r.Body.Bytes()) == "" {
			t.Fatalf("search %d", r.Code)
		}
		var matches struct {
			Messages []json.RawMessage `json:"messages"`
		}
		json.Unmarshal(r.Body.Bytes(), &matches)
		if len(matches.Messages) != 0 {
			t.Fatalf("search leak: %s", r.Body)
		}
	}
	r = h.do("PUT", path+"/mailboxes/"+box.Id.String()+"/owner", fmt.Sprintf(`{"owner_user_id":%q}`, otherID), employee)
	if r.Code != 403 {
		t.Fatal("employee reassigned mailbox")
	}
	r = h.do("PUT", path+"/mailboxes/"+box.Id.String()+"/owner", fmt.Sprintf(`{"owner_user_id":%q}`, otherID), owner)
	if r.Code != 200 {
		t.Fatalf("assign %d %s", r.Code, r.Body)
	}
	if r = h.do("GET", path+"/messages/"+msg.ID, "", employee); r.Code != 404 {
		t.Fatal("old employee retains access")
	}
	if r = h.do("GET", path+"/messages/"+msg.ID, "", other); r.Code != 200 {
		t.Fatal("new employee lacks access")
	}
	// Deleting a domain keeps retained outbound mail private.
	if _, err = h.pool.Exec(ctx, `DELETE FROM domains WHERE domain=$1`, domain); err != nil {
		t.Fatal(err)
	}
	if r = h.do("GET", path+"/emails/"+sent.ID, "", owner); r.Code != 404 {
		t.Fatalf("deleted domain exposed mail: %d %s", r.Code, r.Body)
	}
	if r = h.do("GET", path+"/emails/"+sent.ID, "", other); r.Code != 200 {
		t.Fatalf("retained owner lost mail: %d %s", r.Code, r.Body)
	}

}
