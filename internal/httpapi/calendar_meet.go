package httpapi

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"
	"time"

	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/meet"
	"github.com/rnm/heromail/backend/internal/ratelimit"
	"github.com/rnm/heromail/backend/internal/workspace"
)

// meetRule caps new rooms per user; each one is a call to Google on their behalf.
var meetRule = ratelimit.Rule{Name: "calendar:meet", Limit: 60, Window: time.Hour}

var calendarMeetPath = regexp.MustCompile(`^/workspaces/([^/]+)/calendar/meet$`)

// SetMeet enables Google Meet rooms; without it the endpoint answers 503.
func (s *Server) SetMeet(c *meet.Client) { s.meet = c }

// calendarMeet serves POST /workspaces/{slug}/calendar/meet: a new Google Meet
// room hosted by the caller's Google account (or the configured fallback host).
func (s *Server) calendarMeet(w http.ResponseWriter, r *http.Request) {
	m := calendarMeetPath.FindStringSubmatch(r.URL.Path)
	if r.Method != http.MethodPost {
		writeErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	if _, _, err := s.scope(r.Context(), m[1], workspace.RoleMember); err != nil {
		writeErrorEnvelope(w, http.StatusNotFound, "not_found", "workspace not found")
		return
	}
	if s.meet == nil {
		writeErrorEnvelope(w, http.StatusServiceUnavailable, "meet_not_configured", "Google Meet не подключён")
		return
	}
	user, _ := account.CurrentUser(r.Context())
	if s.limiter != nil && !s.limiter.Allow(r.Context(), meetRule, user.ID).Allowed {
		writeErrorEnvelope(w, http.StatusTooManyRequests, "rate_limited", "Слишком много новых комнат, попробуйте позже")
		return
	}
	space, err := s.meet.CreateSpace(r.Context(), user.Email)
	if errors.Is(err, meet.ErrNoGoogleAccount) {
		writeErrorEnvelope(w, http.StatusUnprocessableEntity, "no_google_account", "Нет Google-аккаунта, от имени которого можно создать встречу")
		return
	}
	if err != nil {
		log.Printf("meet: create space: %v", err)
		writeErrorEnvelope(w, http.StatusBadGateway, "meet_failed", "Google Meet не ответил, попробуйте ещё раз")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(space)
}
