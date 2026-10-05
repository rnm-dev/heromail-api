package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/rnm/heromail/backend/internal/calendar"
	"testing"
)

func TestPersonalCalendarLifecycle(t *testing.T) {
	h := newHarness(t)
	ctx := t.Context()
	owner, _, _ := h.registerUser("cal-owner")
	reader, uid, _ := h.registerUser("cal-member")
	outsider, _, _ := h.registerUser("cal-outsider")
	ws := h.workspaceFor(owner, "calendar")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	if _, err := h.pool.Exec(ctx, `INSERT INTO workspace_members(workspace_id,user_id,role) VALUES($1,$2,'member')`, ws, uid); err != nil {
		t.Fatal(err)
	}
	path := "/workspaces/" + h.slugFor(ws) + "/calendar"
	for _, token := range []string{"", h.apiKeyFor(ws), outsider} {
		if r := h.do("GET", path, "", token); r.Code == 200 {
			t.Fatal("unauthorized settings")
		}
	}
	if r := h.do("PUT", path, `{"timezone":"Asia/Almaty"}`, reader); r.Code != 200 {
		t.Fatal(r.Body)
	}
	input := calendar.Input{Title: "Night shift", Timezone: "Asia/Almaty", Start: "2026-10-05T23:30", End: "2026-10-06T01:00"}
	payload, _ := json.Marshal(input)
	r := h.do("POST", path+"/events", string(payload), reader)
	var event calendar.Event
	if r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &event) != nil {
		t.Fatalf("create %d %s", r.Code, r.Body)
	}
	if event.StartAt.UTC().Hour() != 18 || event.Version != 1 {
		t.Fatal("wrong event", event)
	}
	eventPath := path + "/events/" + event.ID
	list := path + "/events?from=2026-10-06&to=2026-10-07"
	var result struct {
		Events []calendar.Event `json:"events"`
		More   bool             `json:"has_more"`
	}
	r = h.do("GET", list, "", reader)
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &result) != nil || len(result.Events) != 1 {
		t.Fatalf("midnight overlap %d %s", r.Code, r.Body)
	}
	r = h.do("GET", list, "", owner)
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &result) != nil || len(result.Events) != 0 {
		t.Fatal("owner read private events")
	}
	input.Version = 1
	input.Title = "Changed"
	payload, _ = json.Marshal(input)
	if r = h.do("PUT", eventPath, string(payload), owner); r.Code != 404 {
		t.Fatal("owner edited private event", r.Code)
	}
	if r = h.do("DELETE", eventPath+"?version=1", "", owner); r.Code != 404 {
		t.Fatal("owner deleted private event")
	}
	if r = h.do("PUT", eventPath, string(payload), reader); r.Code != 200 {
		t.Fatal(r.Body)
	}
	if r = h.do("PUT", eventPath, string(payload), reader); r.Code != 409 {
		t.Fatal("stale update accepted")
	}
	if r = h.do("DELETE", eventPath+"?version=1", "", reader); r.Code != 409 {
		t.Fatal("stale delete accepted")
	}
	if r = h.do("DELETE", eventPath+"?version=2", "", reader); r.Code != 204 {
		t.Fatal(r.Body)
	}
	input = calendar.Input{Title: "Leave", Timezone: "Asia/Almaty", AllDay: true, Start: "2026-10-05", End: "2026-10-07"}
	payload, _ = json.Marshal(input)
	if r = h.do("POST", path+"/events", string(payload), reader); r.Code != 201 {
		t.Fatal(r.Body)
	}
	if r = h.do("GET", path+"/events?from=2026-10-07&to=2026-10-08", "", reader); r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &result) != nil || len(result.Events) != 0 {
		t.Fatal("exclusive all-day end")
	}
	if r = h.do("GET", path+"/events?from=2026-01-01&to=2027-01-01", "", reader); r.Code != 400 {
		t.Fatal("unbounded range")
	}
	// Pagination does not truncate a busy period silently.
	for i := 0; i < 201; i++ {
		if _, err := calendar.NewStore(h.pool).Save(ctx, ws, uid, "", calendar.Input{Title: fmt.Sprint(i), Timezone: "UTC", Start: "2026-10-10T09:00", End: "2026-10-10T10:00"}); err != nil {
			t.Fatal(err)
		}
	}
	paged := path + "/events?from=2026-10-10&to=2026-10-11"
	r = h.do("GET", paged, "", reader)
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &result) != nil || len(result.Events) != 200 || !result.More {
		t.Fatal("first page", r.Code)
	}
	r = h.do("GET", paged+"&offset=200", "", reader)
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &result) != nil || len(result.Events) != 1 || result.More {
		t.Fatal("last page")
	}
	if _, err := h.pool.Exec(ctx, `DELETE FROM workspace_members WHERE workspace_id=$1 AND user_id=$2`, ws, uid); err != nil {
		t.Fatal(err)
	}
	if r = h.do("GET", list, "", reader); r.Code != 404 {
		t.Fatal("removed member access")
	}
}
