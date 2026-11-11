package httpapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rnm/heromail/backend/internal/calendar"
)

func TestCalendarBusyShowsOnlyIntervalsOfColleagues(t *testing.T) {
	h := newHarness(t)
	token, userID, _ := h.registerUser("calendar-busy")
	ws := h.workspaceFor(token, "calendar-busy")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	_, colleagueID, colleague := h.registerUser("calendar-busy-colleague")
	_, _, outsider := h.registerUser("calendar-busy-outsider")
	if _, err := h.pool.Exec(t.Context(), `INSERT INTO workspace_members(workspace_id,user_id,role) VALUES($1,$2,'member')`, ws, colleagueID); err != nil {
		t.Fatal(err)
	}
	store := calendar.NewStore(h.pool)
	for _, who := range []string{userID, colleagueID} {
		if _, err := store.Save(t.Context(), ws, who, "", calendar.Input{Title: "Secret plan", Timezone: "UTC", Start: "2030-02-04T09:00", End: "2030-02-04T10:00"}); err != nil {
			t.Fatal(err)
		}
	}
	path := "/workspaces/" + h.slugFor(ws) + "/calendar/busy?from=2030-02-04&to=2030-02-05&emails=" + colleague + "," + outsider
	if r := h.do("GET", path, "", ""); r.Code != 401 {
		t.Fatalf("anonymous: %d", r.Code)
	}
	r := h.do("GET", path, "", token)
	if r.Code != 200 || strings.Contains(r.Body.String(), "Secret") {
		t.Fatalf("busy: %d %s", r.Code, r.Body)
	}
	var out struct{ Busy map[string][]calendar.Busy }
	json.Unmarshal(r.Body.Bytes(), &out)
	if len(out.Busy[""]) != 1 || len(out.Busy[strings.ToLower(colleague)]) != 1 || out.Busy[strings.ToLower(outsider)] != nil {
		t.Fatalf("busy map: %s", r.Body)
	}
}
