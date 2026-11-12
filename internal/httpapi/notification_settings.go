package httpapi

import (
	"context"
	"errors"
	"strconv"
	"strings"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/push"
)

func settingsETag(version int) *string {
	tag := `"` + strconv.Itoa(version) + `"`
	return &tag
}

func notificationSettingsToAPI(st *push.Settings) NotificationSettings {
	out := NotificationSettings{Version: st.Version, Enabled: st.Enabled, Privacy: st.Privacy,
		Mailboxes: make([]MailboxNotificationSettings, 0, len(st.Mailboxes))}
	if q := st.Quiet; q != nil {
		out.QuietHours = &QuietHours{Start: q.Start, End: q.End, Timezone: q.Timezone}
	}
	for _, m := range st.Mailboxes {
		cats := make([]MessageCategory, 0, len(m.Categories))
		for _, c := range m.Categories {
			cats = append(cats, MessageCategory(c))
		}
		out.Mailboxes = append(out.Mailboxes, MailboxNotificationSettings{
			MailboxId: mustUUID(m.MailboxID), Address: openapi_types.Email(m.Address), Workspace: m.Workspace,
			Enabled: m.Enabled, Categories: cats, StarredOnly: m.StarredOnly,
		})
	}
	return out
}

func (s *Server) GetNotificationSettings(ctx context.Context, _ GetNotificationSettingsRequestObject) (GetNotificationSettingsResponseObject, error) {
	user, ok := account.CurrentUser(ctx)
	if !ok {
		return GetNotificationSettings401JSONResponse{UnauthorizedJSONResponse(errorBody("unauthenticated", "no session"))}, nil
	}
	st, err := push.NewStore(s.pool).Settings(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	return GetNotificationSettings200JSONResponse{Body: notificationSettingsToAPI(st),
		Headers: GetNotificationSettings200ResponseHeaders{ETag: settingsETag(st.Version)}}, nil
}

func (s *Server) SaveNotificationSettings(ctx context.Context, r SaveNotificationSettingsRequestObject) (SaveNotificationSettingsResponseObject, error) {
	user, ok := account.CurrentUser(ctx)
	if !ok {
		return SaveNotificationSettings401JSONResponse{UnauthorizedJSONResponse(errorBody("unauthenticated", "no session"))}, nil
	}
	if r.Body == nil {
		return SaveNotificationSettings400JSONResponse{BadRequestJSONResponse(errorBody("invalid_json", "a JSON body is required"))}, nil
	}
	conflict := SaveNotificationSettings409JSONResponse(errorBody("version_conflict", "notification settings changed on another device"))
	if r.Params.IfMatch != nil {
		tag := strings.Trim(strings.TrimPrefix(strings.TrimSpace(*r.Params.IfMatch), "W/"), `"`)
		if tag != strconv.Itoa(r.Body.Version) {
			return conflict, nil
		}
	}
	u := push.SettingsUpdate{Version: r.Body.Version, Enabled: r.Body.Enabled, Privacy: r.Body.Privacy}
	if q := r.Body.QuietHours; q != nil {
		u.Quiet = &push.QuietHours{Start: q.Start, End: q.End, Timezone: q.Timezone}
	}
	if r.Body.Mailboxes != nil {
		for _, m := range *r.Body.Mailboxes {
			cats := make([]string, 0, len(m.Categories))
			for _, c := range m.Categories {
				cats = append(cats, string(c))
			}
			u.Mailboxes = append(u.Mailboxes, push.MailboxUpdate{MailboxID: m.MailboxId.String(),
				Enabled: m.Enabled, Categories: cats, StarredOnly: m.StarredOnly})
		}
	}
	st, err := push.NewStore(s.pool).SaveSettings(ctx, user.ID, u)
	switch {
	case errors.Is(err, push.ErrValidation):
		return SaveNotificationSettings400JSONResponse{BadRequestJSONResponse(errorBody("validation_failed", err.Error()))}, nil
	case errors.Is(err, push.ErrUnknownMailbox):
		return SaveNotificationSettings404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "mailbox not found"))}, nil
	case errors.Is(err, push.ErrVersionConflict):
		return conflict, nil
	case err != nil:
		return nil, err
	}
	return SaveNotificationSettings200JSONResponse{Body: notificationSettingsToAPI(st),
		Headers: SaveNotificationSettings200ResponseHeaders{ETag: settingsETag(st.Version)}}, nil
}
