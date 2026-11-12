package httpapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rnm/heromail/backend/internal/calendar"
)

func TestCalendarSharing(t *testing.T) {
	h := newHarness(t)
	token, userID, _ := h.registerUser("calendar-share-owner")
	ws := h.workspaceFor(token, "calendar-share-owner")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	colleagueToken, colleagueID, colleague := h.registerUser("calendar-share-colleague")
	_, _, outsider := h.registerUser("calendar-share-outsider")
	if _, err := h.pool.Exec(t.Context(), `INSERT INTO workspace_members(workspace_id,user_id,role) VALUES($1,$2,'member')`, ws, colleagueID); err != nil {
		t.Fatal(err)
	}
	store := calendar.NewStore(h.pool)
	if _, err := store.Save(t.Context(), ws, userID, "", calendar.Input{Title: "Встреча с клиентом", Timezone: "UTC", Start: "2030-04-01T09:00", End: "2030-04-01T10:00", Organizer: "", Attendees: nil}); err != nil {
		t.Fatal(err)
	}
	slug := h.slugFor(ws)
	shared := "/workspaces/" + slug + "/calendar/shared/" + userID + "/events?from=2030-04-01&to=2030-04-02"
	if r := h.do("GET", shared, "", colleagueToken); r.Code != 404 {
		t.Fatalf("before sharing: %d", r.Code)
	}
	if r := h.do("POST", "/workspaces/"+slug+"/calendar/shares", `{"email":"`+outsider+`"}`, token); r.Code != 400 {
		t.Fatalf("outsider: %d %s", r.Code, r.Body)
	}
	r := h.do("POST", "/workspaces/"+slug+"/calendar/shares", `{"email":"`+strings.ToUpper(colleague)+`"}`, token)
	if r.Code != 200 || !strings.Contains(r.Body.String(), strings.ToLower(colleague)) {
		t.Fatalf("share: %d %s", r.Code, r.Body)
	}
	r = h.do("GET", "/workspaces/"+slug+"/calendar/shares", "", colleagueToken)
	var lists struct {
		SharedWithMe []calendar.Person `json:"shared_with_me"`
	}
	json.Unmarshal(r.Body.Bytes(), &lists)
	if len(lists.SharedWithMe) != 1 || lists.SharedWithMe[0].ID != userID {
		t.Fatalf("shared with me: %s", r.Body)
	}
	r = h.do("GET", shared, "", colleagueToken)
	if r.Code != 200 || !strings.Contains(r.Body.String(), "Встреча с клиентом") || !strings.Contains(r.Body.String(), `"role":"shared"`) {
		t.Fatalf("shared events: %d %s", r.Code, r.Body)
	}
	h.do("DELETE", "/workspaces/"+slug+"/calendar/shares/"+colleagueID, "", token)
	if r := h.do("GET", shared, "", colleagueToken); r.Code != 404 {
		t.Fatalf("after unsharing: %d", r.Code)
	}
}
