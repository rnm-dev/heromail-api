package httpapi

import (
	"context"
	"errors"
	"log"

	"github.com/rnm/heromail/backend/internal/account"
)

// SubmitLead takes the landing form and emails it to the sales address.
func (s *Server) SubmitLead(ctx context.Context, request SubmitLeadRequestObject) (SubmitLeadResponseObject, error) {
	if request.Body == nil {
		return SubmitLead400JSONResponse{BadRequestJSONResponse(errorBody("invalid_json", "a JSON body is required"))}, nil
	}
	// People never see the field, so whoever filled it is a script. It gets the
	// same answer as a person and no mail.
	if deref(request.Body.Website) != "" {
		return SubmitLead202Response{}, nil
	}

	rc := requestContextFrom(ctx)
	if res := s.allow(ctx, rc.IP, leadPerIP); !res.Allowed {
		return SubmitLead429JSONResponse{tooMany(res, "too many requests from this address; try again later")}, nil
	}
	if res := s.allow(ctx, normaliseKey(s.accounts.LeadsTo()), leadTotal); !res.Allowed {
		return SubmitLead429JSONResponse{tooMany(res, "too many requests; write to us directly")}, nil
	}

	mailboxes := ""
	if request.Body.Mailboxes != nil {
		mailboxes = string(*request.Body.Mailboxes)
	}
	err := s.accounts.SendLead(ctx, account.Lead{
		Name:      request.Body.Name,
		Email:     string(request.Body.Email),
		Company:   deref(request.Body.Company),
		Domain:    deref(request.Body.Domain),
		Mailboxes: mailboxes,
		Message:   deref(request.Body.Message),
		IP:        rc.IP,
		UserAgent: rc.UserAgent,
	})
	switch {
	case errors.Is(err, account.ErrValidation):
		return SubmitLead400JSONResponse{BadRequestJSONResponse(errorBody("validation_failed", err.Error()))}, nil
	case err != nil:
		log.Printf("lead: %v", err)
		return SubmitLead503JSONResponse(errorBody("mail_unavailable", "the request could not be sent; write to us directly")), nil
	}
	return SubmitLead202Response{}, nil
}
