package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/rnm/heromail/backend/internal/inbound"
)

// Extra employees granted to a private mailbox read and send from it like the
// owner; everyone else, including the workspace owner, stays locked out.
func TestMailboxMembersAccess(t *testing.T) {
	h := newHarness(t)
	ctx := t.Context()
	owner, _, _ := h.registerUser("members-manager")
	employee, employeeID, _ := h.registerUser("members-employee")
	colleague, colleagueID, _ := h.registerUser("members-colleague")
	other, otherID, _ := h.registerUser("members-other")
	_, outsiderID, _ := h.registerUser("members-outsider")
	ws := h.workspaceFor(owner, "members-test")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	if _, err := h.pool.Exec(ctx, `INSERT INTO workspace_members(workspace_id,user_id,role) VALUES($1,$2,'member'),($1,$3,'member'),($1,$4,'member')`, ws, employeeID, colleagueID, otherID); err != nil {
		t.Fatal(err)
	}
	domain := h.verifiedDomainFor(t, ws)
	path := "/workspaces/" + h.slugFor(ws)
	r := h.do("POST", path+"/mailboxes", fmt.Sprintf(`{"domain":%q,"local_part":"team","owner_user_id":%q}`, domain, employeeID), owner)
	if r.Code != 201 {
		t.Fatalf("create: %d %s", r.Code, r.Body)
	}
	var box Mailbox
	json.Unmarshal(r.Body.Bytes(), &box)
	members := path + "/mailboxes/" + box.Id.String() + "/members"
	msg, err := inbound.NewStore(h.pool).Deliver(ctx, inbound.DeliverParams{MailboxID: box.Id.String(), EnvelopeFrom: "hello@example.test", EnvelopeTo: string(box.Address), Raw: []byte("From: hello@example.test\r\nSubject: Team secret\r\n\r\nbody")})
	if err != nil {
		t.Fatal(err)
	}
	read := func(token string) int { return h.do("GET", path+"/messages/"+msg.ID, "", token).Code }
	send := func(token string) int {
		return h.do("POST", path+"/emails", fmt.Sprintf(`{"from":%q,"to":["to@example.test"],"subject":"x","text":"y"}`, box.Address), token).Code
	}
	if read(colleague) != 404 || send(colleague) != 400 {
		t.Fatal("colleague had access before the grant")
	}

	for _, tc := range []struct {
		token, body string
		code        int
	}{
		{employee, fmt.Sprintf(`{"user_ids":[%q]}`, colleagueID), 403},
		{owner, fmt.Sprintf(`{"user_ids":[%q]}`, outsiderID), 400},
	} {
		if r = h.do("PUT", members, tc.body, tc.token); r.Code != tc.code {
			t.Fatalf("members %s: %d %s", tc.body, r.Code, r.Body)
		}
	}
	r = h.do("PUT", members, fmt.Sprintf(`{"user_ids":[%q,%q]}`, colleagueID, employeeID), owner)
	if r.Code != 200 {
		t.Fatalf("grant: %d %s", r.Code, r.Body)
	}
	json.Unmarshal(r.Body.Bytes(), &box)
	if box.MemberUserIds == nil || len(*box.MemberUserIds) != 1 || (*box.MemberUserIds)[0].String() != colleagueID {
		t.Fatalf("owner must not be stored as a member: %s", r.Body)
	}
	if read(colleague) != 200 || send(colleague) != 202 {
		t.Fatal("granted colleague cannot read or send")
	}
	for _, token := range []string{owner, other} {
		if read(token) != 404 || send(token) != 400 {
			t.Fatal("grant leaked to others")
		}
	}
	r = h.do("GET", "/messages/unread-counts", "", colleague)
	var counts map[string]int
	json.Unmarshal(r.Body.Bytes(), &counts)
	if counts["INBOX"] != 1 {
		t.Fatalf("unread counts ignore the grant: %s", r.Body)
	}
	// Per-mailbox counts: the chosen box only; another or unreadable box counts nothing.
	for _, tc := range []struct {
		box  string
		want int
	}{{box.Id.String(), 1}, {"00000000-0000-4000-8000-000000000000", 0}} {
		r = h.do("GET", "/messages/unread-counts?box="+tc.box, "", colleague)
		counts = map[string]int{}
		json.Unmarshal(r.Body.Bytes(), &counts)
		if r.Code != 200 || counts["INBOX"] != tc.want {
			t.Fatalf("box %s counts: %d %s", tc.box, r.Code, r.Body)
		}
	}
	if r = h.do("GET", "/messages/unread-counts?box="+box.Id.String(), "", other); r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &counts) != nil || counts["INBOX"] != 0 {
		t.Fatalf("unassigned member sees counts of a restricted box: %s", r.Body)
	}

	// Leaving the workspace removes the grant itself.
	if _, err = h.pool.Exec(ctx, `DELETE FROM workspace_members WHERE workspace_id=$1 AND user_id=$2`, ws, colleagueID); err != nil {
		t.Fatal(err)
	}
	var left int
	h.pool.QueryRow(ctx, `SELECT count(*) FROM mailbox_members WHERE mailbox_id=$1`, box.Id).Scan(&left)
	if left != 0 || read(colleague) != 404 {
		t.Fatal("grant survived leaving the workspace")
	}

	// A shared mailbox with assigned employees is limited to them; without
	// assignments it is open to the whole workspace again.
	if r = h.do("PUT", path+"/mailboxes/"+box.Id.String()+"/owner", `{"owner_user_id":null}`, owner); r.Code != 200 {
		t.Fatalf("share: %d %s", r.Code, r.Body)
	}
	if r = h.do("PUT", members, fmt.Sprintf(`{"user_ids":[%q]}`, otherID), owner); r.Code != 200 {
		t.Fatalf("assign to shared: %d %s", r.Code, r.Body)
	}
	if read(other) != 200 || send(other) != 202 {
		t.Fatal("assigned employee cannot use the shared mailbox")
	}
	for _, token := range []string{owner, employee} {
		if read(token) != 404 || send(token) != 400 {
			t.Fatal("unassigned member reached a restricted shared mailbox")
		}
	}
	if r = h.do("PUT", members, `{"user_ids":[]}`, owner); r.Code != 200 {
		t.Fatalf("clear: %d %s", r.Code, r.Body)
	}
	if read(employee) != 200 || read(owner) != 200 {
		t.Fatal("unassigned shared mailbox is not open to the workspace")
	}
}
