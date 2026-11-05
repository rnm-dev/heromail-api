package httpapi

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
)

func TestRecipientSuggestionsUseOwnMailOnly(t *testing.T) {
	h := newHarness(t)
	token, userID, _ := h.registerUser("suggest-owner")
	peer, peerID, _ := h.registerUser("suggest-peer")
	ws := h.workspaceFor(token, "suggest")
	domain := h.verifiedDomainFor(t, ws)
	if _, err := h.pool.Exec(t.Context(), `INSERT INTO workspace_members(workspace_id,user_id,role) VALUES($1,$2,'member')`, ws, peerID); err != nil {
		t.Fatal(err)
	}
	var box, peerBox string
	for owner, id := range map[string]*string{userID: &box, peerID: &peerBox} {
		if err := h.pool.QueryRow(t.Context(), `INSERT INTO mailboxes(domain_id,local_part,owner_user_id) SELECT id,$3,$2 FROM domains WHERE workspace_id=$1 RETURNING id`, ws, owner, "u"+owner[:8]).Scan(id); err != nil {
			t.Fatal(err)
		}
	}
	addMessage := func(box, from, name, folder string) {
		if _, err := h.pool.Exec(t.Context(), `INSERT INTO messages(mailbox_id,envelope_to,raw,size_bytes,from_addr,from_name,folder) VALUES($1,'x@x',$2,4,$3,$4,$5)`, box, []byte("test"), from, name, folder); err != nil {
			t.Fatal(err)
		}
	}
	addMessage(box, "alina@partner.test", "Alina Partner", "INBOX")
	addMessage(box, "alpha-spam@junk.test", "", "Junk")
	addMessage(peerBox, "alfred@secret.test", "", "INBOX")
	if _, err := h.pool.Exec(t.Context(), `INSERT INTO emails(workspace_id,from_addr,to_addrs,cc_addrs,status,text_body) SELECT $1,local_part||'@'||$2,'{alex@client.test}','{albert@cc.test}','sent','hi' FROM mailboxes WHERE id=$3`, ws, domain, box); err != nil {
		t.Fatal(err)
	}
	if r := h.do("PUT", "/contacts/"+uuid.NewString(), `{"name":"Almaz","email":"alex@client.test","version":0}`, token); r.Code != 200 {
		t.Fatal(r.Body)
	}
	suggest := func(who, q string) map[string]string {
		t.Helper()
		r := h.do("GET", "/contacts/suggestions?q="+q, "", who)
		if r.Code != 200 {
			t.Fatalf("%d %s", r.Code, r.Body)
		}
		var body struct{ Suggestions []RecipientSuggestion }
		json.Unmarshal(r.Body.Bytes(), &body)
		got := map[string]string{}
		for _, s := range body.Suggestions {
			got[s.Email] = fmt.Sprintf("%s|%s", s.Name, s.Source)
		}
		return got
	}
	got := suggest(token, "al")
	want := map[string]string{"alex@client.test": "Almaz|contact", "alina@partner.test": "Alina Partner|received", "albert@cc.test": "|sent"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if got := suggest(peer, "al"); fmt.Sprint(got) != fmt.Sprint(map[string]string{"alfred@secret.test": "|received"}) {
		t.Fatalf("peer saw %v", got)
	}
	if r := h.do("GET", "/contacts/suggestions?q=", "", token); r.Code != 400 {
		t.Fatalf("empty query: %d", r.Code)
	}
}
