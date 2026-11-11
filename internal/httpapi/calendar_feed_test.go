package httpapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rnm/heromail/backend/internal/calendar"
)

func TestCalendarFeed(t *testing.T) {
	h := newHarness(t)
	token, userID, _ := h.registerUser("calendar-feed")
	ws := h.workspaceFor(token, "calendar-feed")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	start := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Minute)
	if _, err := calendar.NewStore(h.pool).Save(t.Context(), ws, userID, "", calendar.Input{Title: "Feed, item", Timezone: "UTC", Start: start.Format("2006-01-02T15:04"), End: start.Add(time.Hour).Format("2006-01-02T15:04")}); err != nil {
		t.Fatal(err)
	}
	settings := "/workspaces/" + h.slugFor(ws) + "/calendar/feed"
	if r := h.do("GET", settings, "", ""); r.Code != 401 {
		t.Fatalf("anonymous settings: %d", r.Code)
	}
	r := h.do("GET", settings, "", token)
	if r.Code != 200 || !strings.Contains(r.Body.String(), `"path":null`) {
		t.Fatalf("initial: %d %s", r.Code, r.Body)
	}
	var out struct{ Path string }
	r = h.do("POST", settings, "", token)
	if err := json.Unmarshal(r.Body.Bytes(), &out); err != nil || out.Path == "" {
		t.Fatalf("rotate: %s", r.Body)
	}
	feed := h.do("GET", out.Path, "", "")
	if feed.Code != 200 || !strings.Contains(feed.Body.String(), "SUMMARY:Feed\\, item") || !strings.HasPrefix(feed.Header().Get("Content-Type"), "text/calendar") {
		t.Fatalf("feed: %d %s", feed.Code, feed.Body)
	}
	h.do("DELETE", settings, "", token)
	if feed = h.do("GET", out.Path, "", ""); feed.Code != 404 {
		t.Fatalf("revoked feed: %d", feed.Code)
	}
}
