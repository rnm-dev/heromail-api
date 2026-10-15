package httpapi

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestContactsPrivacyAndVersions(t *testing.T) {
	h := newHarness(t)
	token, userID, _ := h.registerUser("contact-owner")
	peer, _, _ := h.registerUser("contact-peer")
	ws := h.workspaceFor(token, "contacts")
	path := "/contacts/" + uuid.NewString()
	save := func(url, who, name, address string, version, code int) Contact {
		t.Helper()
		r := h.do("PUT", url, fmt.Sprintf(`{"name":%q,"email":%q,"version":%d}`, name, address, version), who)
		if r.Code != code {
			t.Fatalf("save: %d %s", r.Code, r.Body)
		}
		var contact Contact
		if code == 200 {
			json.Unmarshal(r.Body.Bytes(), &contact)
		}
		return contact
	}
	for _, credential := range []string{"", h.apiKeyFor(ws)} {
		for _, method := range []string{"GET", "PUT", "DELETE"} {
			url := "/contacts"
			if method != "GET" {
				url = path + "?version=1"
			}
			if r := h.do(method, url, `{"name":"x","email":"x@example.test","version":0}`, credential); r.Code != 401 {
				t.Fatalf("credential %s: %d", method, r.Code)
			}
		}
	}
	c := save(path, token, "Azamat", "AZA@example.test", 0, 200)
	if c.Version != 1 || string(c.Email) != "aza@example.test" {
		t.Fatal(c)
	}
	if c = save(path, token, "Azamat", "aza@example.test", 0, 200); c.Version != 1 {
		t.Fatal("lost-response retry incremented version")
	}
	save(path, token, "Changed", "aza@example.test", 1, 200)
	save(path, token, "Stale", "aza@example.test", 1, 409)
	save(path, peer, "Steal", "aza@example.test", 0, 404)
	if r := h.do("DELETE", path+"?version=2", "", peer); r.Code != 404 {
		t.Fatalf("peer delete: %d", r.Code)
	}
	if r := h.do("DELETE", path+"?version=1", "", token); r.Code != 409 {
		t.Fatalf("stale delete: %d", r.Code)
	}
	save("/contacts/"+uuid.NewString(), token, "Duplicate", "aza@example.test", 0, 409)
	save("/contacts/"+uuid.NewString(), peer, "Same address allowed for another account", "aza@example.test", 0, 200)
	for _, email := range []string{"not an address", "Name <name@example.test>", "a@example.test,b@example.test", "a@example.test\r\nBcc: x@example.test"} {
		save("/contacts/"+uuid.NewString(), token, "Bad", email, 0, 400)
	}
	save("/contacts/"+uuid.NewString(), token, strings.Repeat("я", 201), "other@example.test", 0, 400)
	save("/contacts/"+uuid.NewString(), token, "bad\x00name", "other@example.test", 0, 400)
	r := h.do("GET", "/contacts?q=AZA", "", token)
	var list struct {
		Contacts []Contact
		HasMore  bool `json:"has_more"`
	}
	json.Unmarshal(r.Body.Bytes(), &list)
	if r.Code != 200 || len(list.Contacts) != 1 || list.Contacts[0].Name != "Changed" {
		t.Fatalf("search: %d %s", r.Code, r.Body)
	}
	if r = h.do("GET", "/contacts?q=%25", "", token); r.Code != 200 || !strings.Contains(r.Body.String(), `"contacts":[]`) {
		t.Fatalf("literal search: %s", r.Body)
	}
	// Pagination and user isolation use DB candidates, not filtered client pages.
	for i := 0; i < 51; i++ {
		if _, err := h.pool.Exec(t.Context(), `INSERT INTO contacts(id,user_id,name,email) VALUES($1,$2,$3,$4)`, uuid.NewString(), userID, fmt.Sprintf("Page %02d", i), fmt.Sprintf("page%02d@example.test", i)); err != nil {
			t.Fatal(err)
		}
	}
	r = h.do("GET", "/contacts?q=Page", "", token)
	json.Unmarshal(r.Body.Bytes(), &list)
	if len(list.Contacts) != 50 || !list.HasMore {
		t.Fatalf("page1: %s", r.Body)
	}
	r = h.do("GET", "/contacts?q=Page&offset=50", "", token)
	json.Unmarshal(r.Body.Bytes(), &list)
	if len(list.Contacts) != 1 || list.HasMore || list.Contacts[0].Name != "Page 50" {
		t.Fatalf("page2: %s", r.Body)
	}
	r = h.do("GET", "/contacts?q=Page", "", peer)
	json.Unmarshal(r.Body.Bytes(), &list)
	if len(list.Contacts) != 0 {
		t.Fatal("private contacts leaked")
	}
	if r = h.do("DELETE", path+"?version=2", "", token); r.Code != 204 {
		t.Fatalf("delete: %d %s", r.Code, r.Body)
	}
	save(path, token, "Deleted stale", "aza@example.test", 2, 409)
}
