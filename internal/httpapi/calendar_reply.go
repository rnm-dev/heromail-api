package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/calendar"
	"github.com/rnm/heromail/backend/internal/email"
	"github.com/rnm/heromail/backend/internal/inbound"
	"github.com/rnm/heromail/backend/internal/workspace"
)

func (r calendarResponse) VisitReplyMessageCalendarResponse(w http.ResponseWriter) error {
	return r.write(w)
}

var replySubject = map[string]string{"accepted": "Принято", "tentative": "Под вопросом", "declined": "Отклонено"}

// calendarPreview adds the reply state for an external REQUEST the receiving
// mailbox was invited to. Heromail-organized invites keep their own link flow.
func (s *Server) calendarPreview(ctx context.Context, msg *inbound.Message, p inbound.Presentation) (*CalendarPreview, error) {
	c := p.Calendar
	if c == nil {
		return nil, nil
	}
	out := &CalendarPreview{Method: c.Method, Uid: c.UID, Title: c.Title, Start: c.Start, End: c.End, Organizer: c.Organizer, Unsupported: c.Unsupported}
	invite, err := calendar.ParseExternalInvite(p.CalendarICS)
	if err != nil {
		return out, nil
	}
	box, err := s.inbound.MailboxByID(ctx, msg.MailboxID)
	if err != nil {
		return nil, err
	}
	if !invite.Invites(box.Address) || strings.EqualFold(invite.Organizer, box.Address) {
		return out, nil
	}
	out.Attendee = &box.Address
	state, err := calendar.NewStore(s.pool).ExternalReply(ctx, msg.ID)
	if err != nil {
		return nil, err
	}
	if state.Sent() {
		response := CalendarPreviewResponse(state.Response)
		out.Response = &response
	}
	return out, nil
}

// ReplyMessageCalendar mails an iTIP REPLY to the organizer from the mailbox
// that received the invitation. It is an explicit user action; viewing never answers.
func (s *Server) ReplyMessageCalendar(ctx context.Context, r ReplyMessageCalendarRequestObject) (ReplyMessageCalendarResponseObject, error) {
	fail := func(code int, kind, message string) (ReplyMessageCalendarResponseObject, error) {
		return calendarResponse{code, errorBody(kind, message)}, nil
	}
	ws, _, err := s.scope(ctx, string(r.Slug), workspace.RoleMember)
	if err != nil {
		return fail(404, "not_found", "workspace not found")
	}
	msg, err := s.readableMessage(ctx, ws, r.MessageId.String())
	if err != nil {
		return fail(404, "not_found", "message not found")
	}
	if r.Body == nil {
		return fail(400, "invalid_json", "a JSON body is required")
	}
	response := r.Body.Response
	if _, ok := replySubject[response]; !ok {
		return fail(400, "validation_failed", "Выберите «Да», «Возможно» или «Нет»")
	}
	p, err := s.inbound.Presentation(ctx, msg.MailboxID, msg.ID)
	if err != nil {
		return nil, err
	}
	preview, err := s.calendarPreview(ctx, msg, p)
	if err != nil {
		return nil, err
	}
	if preview == nil || preview.Attendee == nil {
		return fail(400, "validation_failed", "Это приглашение нельзя подтвердить из Heromail. Скачайте ICS-файл.")
	}
	from := *preview.Attendee
	invite, _ := calendar.ParseExternalInvite(p.CalendarICS)
	store := calendar.NewStore(s.pool)
	state, err := store.ExternalReply(ctx, msg.ID)
	if err != nil {
		return nil, err
	}
	if state.Response == response && state.Sent() {
		if err := s.saveExternalEvent(ctx, ws, msg.ID, from, response, invite); err != nil {
			return nil, err
		}
		return calendarResponse{200, preview}, nil
	}
	if err := s.domains.AllowsAddress(ctx, ws, from); err != nil {
		return fail(400, "sender_not_allowed", "verify the sender domain before sending")
	}
	if res := s.allow(ctx, ws, sendQuota()...); !res.Allowed {
		return calendarResponse{429, tooMany(res, "this workspace has reached its send limit")}, nil
	}
	// A failed earlier attempt with the same answer is retried as-is.
	next := state
	if state.Response != response {
		if next, err = store.BeginExternalReply(ctx, msg.ID, from, response, state.Revision); errors.Is(err, calendar.ErrConflict) {
			return fail(409, "conflict", "Ответ уже изменён в другой вкладке. Обновите письмо.")
		} else if err != nil {
			return nil, err
		}
	}
	ics, err := invite.Reply(from, response, next.Stamp)
	if err != nil {
		return fail(400, "validation_failed", err.Error())
	}
	title := invite.Title
	if title == "" {
		title = msg.Subject
	}
	// The revision and stored DTSTAMP make a retry of the same answer
	// idempotent while a later change of mind sends a new REPLY.
	sent, err := s.emails.Send(ctx, ws, fmt.Sprintf("calendar-reply-%s-%d", msg.ID, next.Revision), email.SendRequest{
		From:           from,
		To:             []string{invite.Organizer},
		Subject:        replySubject[response] + ": " + title,
		Text:           fmt.Sprintf("%s: %s — %s", from, strings.ToLower(replySubject[response]), title),
		InReplyTo:      p.InReplyTo,
		References:     p.References,
		CalendarICS:    ics,
		CalendarMethod: "REPLY",
	})
	switch {
	case errors.Is(err, email.ErrValidation), errors.Is(err, email.ErrFromNotAllowed):
		return fail(400, "validation_failed", err.Error())
	case err != nil:
		log.Printf("calendar reply %s: %v", msg.ID, err)
		return nil, err
	}
	if err := store.FinishExternalReply(ctx, msg.ID, next.Revision, sent.ID); err != nil {
		return nil, err
	}
	if err := s.saveExternalEvent(ctx, ws, msg.ID, from, response, invite); err != nil {
		return nil, err
	}
	answer := CalendarPreviewResponse(response)
	preview.Response = &answer
	return calendarResponse{200, preview}, nil
}

// saveExternalEvent mirrors the answer into the signed-in user's calendar.
// The REPLY is already queued, so a time that cannot be read is logged rather
// than failing the answer.
func (s *Server) saveExternalEvent(ctx context.Context, ws, messageID, from, response string, invite calendar.ExternalInvite) error {
	user, ok := account.CurrentUser(ctx)
	if !ok {
		return nil
	}
	err := calendar.NewStore(s.pool).SaveExternal(ctx, ws, user.ID, messageID, from, response, invite)
	var verr calendar.ValidationError
	if errors.As(err, &verr) {
		log.Printf("calendar reply %s: event not saved: %v", messageID, err)
		return nil
	}
	return err
}
