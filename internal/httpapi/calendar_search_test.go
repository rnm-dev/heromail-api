package httpapi

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/rnm/heromail/backend/internal/calendar"
)

func TestCalendarSearchAndColor(t *testing.T) {
	h := newHarness(t)
	token, userID, _ := h.registerUser("calendar-search")
	ws := h.workspaceFor(token, "calendar-search")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	other, otherID, _ := h.registerUser("calendar-search-other")
	otherWS := h.workspaceFor(other, "calendar-search-other")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, otherWS) })
	store := calendar.NewStore(h.pool)
	if _, err := store.Save(t.Context(), ws, userID, "", calendar.Input{Title: "Бюджет 2027", Location: "Переговорная", Timezone: "UTC", Start: "2030-03-01T09:00", End: "2030-03-01T10:00", Color: "green"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Save(t.Context(), ws, userID, "", calendar.Input{Title: "Обед", Timezone: "UTC", Start: "2030-03-02T09:00", End: "2030-03-02T10:00", Color: "pink"}); err == nil {
		t.Fatal("unknown colour accepted")
	}
	if _, err := store.Save(t.Context(), otherWS, otherID, "", calendar.Input{Title: "Бюджет чужой", Timezone: "UTC", Start: "2030-03-01T09:00", End: "2030-03-01T10:00"}); err != nil {
		t.Fatal(err)
	}
	r := h.do("GET", "/workspaces/"+h.slugFor(ws)+"/calendar/search?q=%D0%B1%D1%8E%D0%B4%D0%B6", "", token)
	var out struct{ Events []calendar.Event }
	if err := json.Unmarshal(r.Body.Bytes(), &out); err != nil || r.Code != 200 {
		t.Fatalf("search %d %s", r.Code, r.Body)
	}
	if len(out.Events) != 1 || out.Events[0].Title != "Бюджет 2027" || out.Events[0].Color != "green" {
		t.Fatalf("results: %s", r.Body)
	}
	if r := h.do("GET", "/workspaces/"+h.slugFor(ws)+"/calendar/search?q=x", "", token); r.Code != 400 {
		t.Fatalf("short query: %d", r.Code)
	}
}
