package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/calendar"
	"github.com/rnm/heromail/backend/internal/workspace"
)

type calendarResponse struct {
	code int
	body any
}

func (r calendarResponse) write(w http.ResponseWriter) error {
	w.Header().Set("Cache-Control", "private, no-store")
	if r.code != 204 {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(r.code)
	if r.code == 204 {
		return nil
	}
	return json.NewEncoder(w).Encode(r.body)
}
func (r calendarResponse) VisitGetCalendarResponse(w http.ResponseWriter) error    { return r.write(w) }
func (r calendarResponse) VisitUpdateCalendarResponse(w http.ResponseWriter) error { return r.write(w) }
func (r calendarResponse) VisitListCalendarEventsResponse(w http.ResponseWriter) error {
	return r.write(w)
}
func (r calendarResponse) VisitCreateCalendarEventResponse(w http.ResponseWriter) error {
	return r.write(w)
}
func (r calendarResponse) VisitUpdateCalendarEventResponse(w http.ResponseWriter) error {
	return r.write(w)
}
func (r calendarResponse) VisitDeleteCalendarEventResponse(w http.ResponseWriter) error {
	return r.write(w)
}
func calendarResult(code int, body any, err error) (calendarResponse, error) {
	if err == nil {
		return calendarResponse{code, body}, nil
	}
	var validation calendar.ValidationError
	if errors.As(err, &validation) {
		return calendarResponse{400, errorBody("validation_failed", err.Error())}, nil
	}
	if errors.Is(err, calendar.ErrNotFound) {
		return calendarResponse{404, errorBody("not_found", "Событие не найдено")}, nil
	}
	if errors.Is(err, calendar.ErrConflict) {
		return calendarResponse{409, errorBody("conflict", "Событие изменилось. Обновите календарь перед сохранением.")}, nil
	}
	return calendarResponse{}, err
}
func (s *Server) calendarScope(ctx context.Context, slug string) (string, string, error) {
	user, ok := account.CurrentUser(ctx)
	if !ok {
		return "", "", calendar.ErrNotFound
	}
	ws, _, err := s.scope(ctx, slug, workspace.RoleMember)
	if err != nil {
		return "", "", calendar.ErrNotFound
	}
	return ws, user.ID, nil
}
func (s *Server) GetCalendar(ctx context.Context, r GetCalendarRequestObject) (GetCalendarResponseObject, error) {
	ws, user, err := s.calendarScope(ctx, r.Slug)
	if err != nil {
		return calendarResult(0, nil, err)
	}
	out, err := calendar.NewStore(s.pool).Settings(ctx, ws, user, nil)
	return calendarResult(200, out, err)
}
func (s *Server) UpdateCalendar(ctx context.Context, r UpdateCalendarRequestObject) (UpdateCalendarResponseObject, error) {
	ws, user, err := s.calendarScope(ctx, r.Slug)
	if err != nil {
		return calendarResult(0, nil, err)
	}
	if r.Body == nil {
		return calendarResult(0, nil, calendar.ValidationError{Message: "Не указан часовой пояс"})
	}
	out, err := calendar.NewStore(s.pool).Settings(ctx, ws, user, &r.Body.Timezone)
	return calendarResult(200, out, err)
}
func (s *Server) ListCalendarEvents(ctx context.Context, r ListCalendarEventsRequestObject) (ListCalendarEventsResponseObject, error) {
	ws, user, err := s.calendarScope(ctx, r.Slug)
	if err != nil {
		return calendarResult(0, nil, err)
	}
	offset := 0
	if r.Params.Offset != nil {
		offset = *r.Params.Offset
	}
	events, more, err := calendar.NewStore(s.pool).List(ctx, ws, user, r.Params.From, r.Params.To, offset)
	return calendarResult(200, struct {
		Events []calendar.Event `json:"events"`
		More   bool             `json:"has_more"`
	}{events, more}, err)
}
func (s *Server) CreateCalendarEvent(ctx context.Context, r CreateCalendarEventRequestObject) (CreateCalendarEventResponseObject, error) {
	ws, user, err := s.calendarScope(ctx, r.Slug)
	if err != nil {
		return calendarResult(0, nil, err)
	}
	if r.Body == nil {
		return calendarResult(0, nil, calendar.ValidationError{Message: "Пустое событие"})
	}
	out, err := calendar.NewStore(s.pool).Save(ctx, ws, user, "", *r.Body)
	return calendarResult(201, out, err)
}
func (s *Server) UpdateCalendarEvent(ctx context.Context, r UpdateCalendarEventRequestObject) (UpdateCalendarEventResponseObject, error) {
	ws, user, err := s.calendarScope(ctx, r.Slug)
	if err != nil {
		return calendarResult(0, nil, err)
	}
	if r.Body == nil {
		return calendarResult(0, nil, calendar.ValidationError{Message: "Пустое событие"})
	}
	out, err := calendar.NewStore(s.pool).Save(ctx, ws, user, r.EventId.String(), *r.Body)
	return calendarResult(200, out, err)
}
func (s *Server) DeleteCalendarEvent(ctx context.Context, r DeleteCalendarEventRequestObject) (DeleteCalendarEventResponseObject, error) {
	ws, user, err := s.calendarScope(ctx, r.Slug)
	if err != nil {
		return calendarResult(0, nil, err)
	}
	err = calendar.NewStore(s.pool).Delete(ctx, ws, user, r.EventId.String(), r.Params.Version)
	return calendarResult(204, nil, err)
}
