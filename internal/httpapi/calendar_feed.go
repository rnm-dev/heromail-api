package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
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

var calendarBusyPath = regexp.MustCompile(`^/workspaces/([^/]+)/calendar/busy$`)

// calendarBusy serves GET /workspaces/{slug}/calendar/busy?from=&to=&emails=a,b
// behind a session: busy intervals of the caller ("") and of colleagues.
func (s *Server) calendarBusy(w http.ResponseWriter, r *http.Request) {
	m := calendarBusyPath.FindStringSubmatch(r.URL.Path)
	if r.Method != http.MethodGet {
		writeErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}
	ws, _, err := s.scope(r.Context(), m[1], workspace.RoleMember)
	if err != nil {
		writeErrorEnvelope(w, http.StatusNotFound, "not_found", "workspace not found")
		return
	}
	user, _ := account.CurrentUser(r.Context())
	q := r.URL.Query()
	from, to := q.Get("from"), q.Get("to")
	a, err1 := time.Parse("2006-01-02", from)
	b, err2 := time.Parse("2006-01-02", to)
	if err1 != nil || err2 != nil || !b.After(a) || b.Sub(a) > 14*24*time.Hour {
		writeErrorEnvelope(w, http.StatusBadRequest, "validation_failed", "Диапазон занятости — от 1 до 14 дней")
		return
	}
	var emails []string
	for _, e := range strings.Split(q.Get("emails"), ",") {
		if e = strings.TrimSpace(e); e != "" {
			emails = append(emails, e)
		}
	}
	busy, err := calendar.NewStore(s.pool).BusyTimes(r.Context(), ws, user.ID, from, to, q.Get("exclude"), emails)
	if err == nil && q.Get("rooms") != "" {
		store := calendar.NewStore(s.pool)
		var settings calendar.Settings
		if settings, err = store.Settings(r.Context(), ws, user.ID, nil); err == nil {
			zone, _ := calendar.Zone(settings.Timezone)
			var rooms map[string][]calendar.Busy
			if rooms, err = store.RoomBusy(r.Context(), ws, strings.Split(q.Get("rooms"), ","), from, to, zone); err == nil {
				for k, v := range rooms {
					busy[k] = v
				}
			}
		}
	}
	var verr calendar.ValidationError
	if errors.As(err, &verr) {
		writeErrorEnvelope(w, http.StatusBadRequest, "validation_failed", verr.Message)
		return
	}
	if err != nil {
		writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"busy": busy})
}

var calendarCopyReminderPath = regexp.MustCompile(`^/workspaces/([^/]+)/calendar/events/([0-9a-fA-F-]{36})/reminder$`)

// calendarCopyReminder serves PUT .../calendar/events/{id}/reminder with
// {"reminder_minutes": n}: a participant's own reminder on a copied meeting.
func (s *Server) calendarCopyReminder(w http.ResponseWriter, r *http.Request) {
	m := calendarCopyReminderPath.FindStringSubmatch(r.URL.Path)
	if r.Method != http.MethodPut {
		writeErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", "use PUT")
		return
	}
	ws, _, err := s.scope(r.Context(), m[1], workspace.RoleMember)
	if err != nil {
		writeErrorEnvelope(w, http.StatusNotFound, "not_found", "workspace not found")
		return
	}
	var body struct {
		ReminderMinutes int `json:"reminder_minutes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body); err != nil {
		writeErrorEnvelope(w, http.StatusBadRequest, "invalid_json", "a JSON body is required")
		return
	}
	user, _ := account.CurrentUser(r.Context())
	err = calendar.NewStore(s.pool).SetCopyReminder(r.Context(), ws, user.ID, strings.ToLower(m[2]), body.ReminderMinutes)
	var verr calendar.ValidationError
	switch {
	case errors.As(err, &verr):
		writeErrorEnvelope(w, http.StatusBadRequest, "validation_failed", verr.Message)
	case errors.Is(err, calendar.ErrNotFound):
		writeErrorEnvelope(w, http.StatusNotFound, "not_found", "event not found")
	case err != nil:
		writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "internal server error")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

var calendarSearchPath = regexp.MustCompile(`^/workspaces/([^/]+)/calendar/search$`)

// calendarSearch serves GET /workspaces/{slug}/calendar/search?q= behind a session.
func (s *Server) calendarSearch(w http.ResponseWriter, r *http.Request) {
	m := calendarSearchPath.FindStringSubmatch(r.URL.Path)
	if r.Method != http.MethodGet {
		writeErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}
	ws, _, err := s.scope(r.Context(), m[1], workspace.RoleMember)
	if err != nil {
		writeErrorEnvelope(w, http.StatusNotFound, "not_found", "workspace not found")
		return
	}
	user, _ := account.CurrentUser(r.Context())
	events, err := calendar.NewStore(s.pool).Search(r.Context(), ws, user.ID, r.URL.Query().Get("q"))
	var verr calendar.ValidationError
	if errors.As(err, &verr) {
		writeErrorEnvelope(w, http.StatusBadRequest, "validation_failed", verr.Message)
		return
	}
	if err != nil {
		writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"events": events})
}

var calendarSharesPath = regexp.MustCompile(`^/workspaces/([^/]+)/calendar/shares(?:/([0-9a-fA-F-]{36}))?$`)
var calendarSharedEventsPath = regexp.MustCompile(`^/workspaces/([^/]+)/calendar/shared/([0-9a-fA-F-]{36})/events$`)

// calendarShares serves GET/POST /workspaces/{slug}/calendar/shares and
// DELETE .../shares/{userId}: who sees my calendar, whose I see.
func (s *Server) calendarShares(w http.ResponseWriter, r *http.Request) {
	m := calendarSharesPath.FindStringSubmatch(r.URL.Path)
	ws, _, err := s.scope(r.Context(), m[1], workspace.RoleMember)
	if err != nil {
		writeErrorEnvelope(w, http.StatusNotFound, "not_found", "workspace not found")
		return
	}
	user, _ := account.CurrentUser(r.Context())
	store := calendar.NewStore(s.pool)
	switch {
	case r.Method == http.MethodPost && m[2] == "":
		var body struct {
			Email string `json:"email"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body); err != nil {
			writeErrorEnvelope(w, http.StatusBadRequest, "invalid_json", "a JSON body is required")
			return
		}
		err = store.Share(r.Context(), ws, user.ID, body.Email)
	case r.Method == http.MethodDelete && m[2] != "":
		err = store.Unshare(r.Context(), ws, user.ID, strings.ToLower(m[2]))
	case r.Method != http.MethodGet || m[2] != "":
		writeErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET, POST or DELETE")
		return
	}
	var verr calendar.ValidationError
	if errors.As(err, &verr) {
		writeErrorEnvelope(w, http.StatusBadRequest, "validation_failed", verr.Message)
		return
	}
	granted, withMe, lerr := store.Shares(r.Context(), ws, user.ID)
	if err != nil || lerr != nil {
		writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"granted": granted, "shared_with_me": withMe})
}

// calendarSharedEvents serves GET .../calendar/shared/{userId}/events?from&to&offset.
func (s *Server) calendarSharedEvents(w http.ResponseWriter, r *http.Request) {
	m := calendarSharedEventsPath.FindStringSubmatch(r.URL.Path)
	if r.Method != http.MethodGet {
		writeErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}
	ws, _, err := s.scope(r.Context(), m[1], workspace.RoleMember)
	if err != nil {
		writeErrorEnvelope(w, http.StatusNotFound, "not_found", "workspace not found")
		return
	}
	user, _ := account.CurrentUser(r.Context())
	q := r.URL.Query()
	offset, _ := strconv.Atoi(q.Get("offset"))
	events, more, err := calendar.NewStore(s.pool).SharedEvents(r.Context(), ws, user.ID, strings.ToLower(m[2]), q.Get("from"), q.Get("to"), offset)
	var verr calendar.ValidationError
	switch {
	case errors.As(err, &verr):
		writeErrorEnvelope(w, http.StatusBadRequest, "validation_failed", verr.Message)
	case errors.Is(err, calendar.ErrNotFound):
		writeErrorEnvelope(w, http.StatusNotFound, "not_found", "calendar not shared with you")
	case err != nil:
		writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "internal server error")
	default:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"events": events, "has_more": more})
	}
}

var calendarRoomsPath = regexp.MustCompile(`^/workspaces/([^/]+)/calendar/rooms(?:/([0-9a-fA-F-]{36}))?$`)

// calendarRooms serves GET (members) and POST, DELETE /{id} (admins) of meeting rooms.
func (s *Server) calendarRooms(w http.ResponseWriter, r *http.Request) {
	m := calendarRoomsPath.FindStringSubmatch(r.URL.Path)
	role := workspace.RoleMember
	if r.Method != http.MethodGet {
		role = workspace.RoleAdmin
	}
	ws, forbidden, err := s.scope(r.Context(), m[1], role)
	if forbidden {
		writeErrorEnvelope(w, http.StatusForbidden, "forbidden", "only workspace admins manage rooms")
		return
	}
	if err != nil {
		writeErrorEnvelope(w, http.StatusNotFound, "not_found", "workspace not found")
		return
	}
	store := calendar.NewStore(s.pool)
	switch {
	case r.Method == http.MethodPost && m[2] == "":
		var body struct {
			Name     string `json:"name"`
			Capacity int    `json:"capacity"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body); err != nil {
			writeErrorEnvelope(w, http.StatusBadRequest, "invalid_json", "a JSON body is required")
			return
		}
		err = store.CreateRoom(r.Context(), ws, body.Name, body.Capacity)
	case r.Method == http.MethodDelete && m[2] != "":
		err = store.DeleteRoom(r.Context(), ws, strings.ToLower(m[2]))
	case r.Method != http.MethodGet || m[2] != "":
		writeErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET, POST or DELETE")
		return
	}
	var verr calendar.ValidationError
	switch {
	case errors.As(err, &verr):
		writeErrorEnvelope(w, http.StatusBadRequest, "validation_failed", verr.Message)
		return
	case errors.Is(err, calendar.ErrNotFound):
		writeErrorEnvelope(w, http.StatusNotFound, "not_found", "room not found")
		return
	case err != nil:
		writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	rooms, err := store.Rooms(r.Context(), ws)
	if err != nil {
		writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"rooms": rooms})
}
