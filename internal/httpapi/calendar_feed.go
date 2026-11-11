package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/calendar"
	"github.com/rnm/heromail/backend/internal/workspace"
)

var calendarFeedSettingsPath = regexp.MustCompile(`^/workspaces/([^/]+)/calendar/feed$`)
var calendarFeedPath = regexp.MustCompile(`^/calendar/feed/([0-9a-fA-F-]{36})\.ics$`)

// calendarFeedSettings serves GET/POST/DELETE /workspaces/{slug}/calendar/feed
// behind a session: read, (re)issue or revoke the subscription token.
func (s *Server) calendarFeedSettings(w http.ResponseWriter, r *http.Request) {
	m := calendarFeedSettingsPath.FindStringSubmatch(r.URL.Path)
	ws, _, err := s.scope(r.Context(), m[1], workspace.RoleMember)
	if err != nil {
		writeErrorEnvelope(w, http.StatusNotFound, "not_found", "workspace not found")
		return
	}
	user, _ := account.CurrentUser(r.Context())
	action := map[string]string{http.MethodGet: "", http.MethodPost: "rotate", http.MethodDelete: "disable"}
	act, ok := action[r.Method]
	if !ok {
		writeErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET, POST or DELETE")
		return
	}
	token, err := calendar.NewStore(s.pool).FeedToken(r.Context(), ws, user.ID, act)
	if err != nil {
		writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	out := struct {
		Path *string `json:"path"`
	}{}
	if token != "" {
		path := "/calendar/feed/" + token + ".ics"
		out.Path = &path
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// calendarFeed serves the public, token-addressed ICS subscription.
func (s *Server) calendarFeed(w http.ResponseWriter, r *http.Request) {
	m := calendarFeedPath.FindStringSubmatch(r.URL.Path)
	if m == nil || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		writeErrorEnvelope(w, http.StatusNotFound, "not_found", "feed not found")
		return
	}
	body, err := calendar.NewStore(s.pool).Feed(r.Context(), strings.ToLower(m[1]), time.Now())
	if errors.Is(err, calendar.ErrNotFound) {
		writeErrorEnvelope(w, http.StatusNotFound, "not_found", "feed not found")
		return
	}
	if err != nil {
		writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	w.Header().Set("Content-Type", "text/calendar; charset=utf-8")
	w.Header().Set("Cache-Control", "private, max-age=300")
	w.Header().Set("X-Robots-Tag", "noindex")
	w.Write([]byte(body))
}
