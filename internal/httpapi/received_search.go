package httpapi

import (
	"context"
	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/inbound"
	"strings"
	"time"
	"unicode/utf8"
)

func (s *Server) SearchReceivedMessages(ctx context.Context, r SearchReceivedMessagesRequestObject) (SearchReceivedMessagesResponseObject, error) {
	user, ok := account.CurrentUser(ctx)
	if !ok {
		return SearchReceivedMessages401JSONResponse{UnauthorizedJSONResponse(errorBody("unauthenticated", "no session"))}, nil
	}
	bad := func() (SearchReceivedMessagesResponseObject, error) {
		return SearchReceivedMessages400JSONResponse{BadRequestJSONResponse(errorBody("invalid_search", "Проверьте фильтры, даты и номер страницы."))}, nil
	}
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return strings.TrimSpace(*p)
	}
	f := inbound.SearchFilter{Query: str(r.Params.Q), From: str(r.Params.From), To: str(r.Params.To), Folder: "INBOX", Limit: 50}
	if r.Params.Folder != nil {
		f.Folder = string(*r.Params.Folder)
	}
	if !inbound.IsWebFolder(f.Folder) && f.Folder != "All" {
		return bad()
	}
	if r.Params.Box != nil {
		f.Box = r.Params.Box.String()
	}
	if r.Params.Limit != nil {
		f.Limit = *r.Params.Limit
	}
	if r.Params.Offset != nil {
		f.Offset = *r.Params.Offset
	}
	if f.Limit < 1 || f.Limit > 100 || f.Offset < 0 || utf8.RuneCountInString(f.Query) > 200 || utf8.RuneCountInString(f.From) > 320 || utf8.RuneCountInString(f.To) > 320 {
		return bad()
	}
	if v := str(r.Params.After); v != "" {
		date, err := time.Parse("2006-01-02", v)
		if err != nil {
			return bad()
		}
		f.After = &date
	}
	if v := str(r.Params.Before); v != "" {
		date, err := time.Parse("2006-01-02", v)
		if err != nil {
			return bad()
		}
		date = date.AddDate(0, 0, 1)
		f.Before = &date
	}
	if f.After != nil && f.Before != nil && !f.After.Before(*f.Before) {
		return bad()
	}
	f.Attachments = r.Params.Attachments != nil && *r.Params.Attachments
	f.Unread = r.Params.Unread != nil && *r.Params.Unread
	f.Starred = r.Params.Starred != nil && *r.Params.Starred
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	matches, more, err := s.inbound.SearchReceived(ctx, user.ID, f)
	if err != nil {
		return nil, err
	}
	out := make([]ReceivedSearchResult, 0, len(matches))
	for _, m := range matches {
		out = append(out, ReceivedSearchResult{Workspace: m.Workspace, Message: receivedMessageToAPI(&m.Message)})
	}
	return SearchReceivedMessages200JSONResponse{Messages: out, HasMore: more}, nil
}
