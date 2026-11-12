package httpapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rnm/heromail/backend/internal/calendar"
)

func TestCalendarRooms(t *testing.T) {
	h := newHarness(t)
	token, userID, _ := h.registerUser("calendar-rooms")
	ws := h.workspaceFor(token, "calendar-rooms")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	memberToken, memberID, _ := h.registerUser("calendar-rooms-member")
	h.pool.Exec(t.Context(), `INSERT INTO workspace_members(workspace_id,user_id,role) VALUES($1,$2,'member')`, ws, memberID)
	path := "/workspaces/" + h.slugFor(ws) + "/calendar/rooms"
	if r := h.do("POST", path, `{"name":"Нельзя"}`, memberToken); r.Code != 403 {
		t.Fatalf("member creates room: %d", r.Code)
	}
	r := h.do("POST", path, `{"name":"Алатау","capacity":8}`, token)
	var out struct{ Rooms []calendar.Room }
	json.Unmarshal(r.Body.Bytes(), &out)
	if r.Code != 200 || len(out.Rooms) != 1 || out.Rooms[0].Capacity != 8 {
		t.Fatalf("create: %d %s", r.Code, r.Body)
	}
	if r := h.do("POST", path, `{"name":"алатау"}`, token); r.Code != 400 {
		t.Fatalf("duplicate: %d", r.Code)
	}
	room := out.Rooms[0].ID
	store := calendar.NewStore(h.pool)
	// A weekly booking on Mondays; a member's one-off on the third Monday collides.
	if _, err := store.Save(t.Context(), ws, userID, "", calendar.Input{Title: "Планёрка", Timezone: "Asia/Almaty", Start: "2030-05-06T10:00", End: "2030-05-06T11:00", RRule: "FREQ=WEEKLY", RoomID: room}); err != nil {
		t.Fatal(err)
	}
	_, err := store.Save(t.Context(), ws, memberID, "", calendar.Input{Title: "Собеседование", Timezone: "Asia/Almaty", Start: "2030-05-20T10:30", End: "2030-05-20T11:30", RoomID: room})
	if err == nil || !strings.Contains(err.Error(), "Алатау") || !strings.Contains(err.Error(), "10:00–11:00") {
		t.Fatalf("conflict: %v", err)
	}
	if _, err := store.Save(t.Context(), ws, memberID, "", calendar.Input{Title: "Собеседование", Timezone: "Asia/Almaty", Start: "2030-05-20T11:00", End: "2030-05-20T12:00", RoomID: room}); err != nil {
		t.Fatalf("adjacent booking: %v", err)
	}
	r = h.do("GET", "/workspaces/"+h.slugFor(ws)+"/calendar/busy?from=2030-05-20&to=2030-05-21&rooms="+room, "", memberToken)
	var busy struct{ Busy map[string][]calendar.Busy }
	json.Unmarshal(r.Body.Bytes(), &busy)
	if len(busy.Busy["room:"+room]) != 2 {
		t.Fatalf("room busy: %s", r.Body)
	}
	if r := h.do("DELETE", path+"/"+room, "", token); r.Code != 200 {
		t.Fatalf("delete: %d", r.Code)
	}
}
