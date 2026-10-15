package httpapi

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/rnm/heromail/backend/internal/inbound"
)

func automationAPI(a inbound.Automation) (MailAutomation, error) {
	var result MailAutomation
	raw, err := json.Marshal(a)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(raw, &result)
	return result, err
}
func (s *Server) GetMailAutomation(ctx context.Context, r GetMailAutomationRequestObject) (GetMailAutomationResponseObject, error) {
	if err := s.organizationAccess(ctx, r.Slug, r.MailboxId.String()); err != nil {
		code, body := organizationFailure(err)
		return GetMailAutomationdefaultJSONResponse{StatusCode: code, Body: body}, nil
	}
	a, err := s.inbound.GetAutomation(ctx, r.MailboxId.String())
	if err != nil {
		return nil, err
	}
	out, err := automationAPI(a)
	if err != nil {
		return nil, err
	}
	return GetMailAutomation200JSONResponse(out), nil
}
func (s *Server) SaveMailAutomation(ctx context.Context, r SaveMailAutomationRequestObject) (SaveMailAutomationResponseObject, error) {
	if err := s.organizationAccess(ctx, r.Slug, r.MailboxId.String()); err != nil {
		code, body := organizationFailure(err)
		return SaveMailAutomationdefaultJSONResponse{StatusCode: code, Body: body}, nil
	}
	if r.Body == nil {
		return SaveMailAutomationdefaultJSONResponse{StatusCode: 400, Body: errorBody("invalid_settings", "Нужны настройки.")}, nil
	}
	raw, err := json.Marshal(r.Body)
	if err != nil {
		return nil, err
	}
	var a inbound.Automation
	if err = json.Unmarshal(raw, &a); err != nil {
		return nil, err
	}
	a, err = s.inbound.SaveAutomation(ctx, r.MailboxId.String(), a)
	if errors.Is(err, inbound.ErrAutomationConflict) {
		return SaveMailAutomationdefaultJSONResponse{StatusCode: 409, Body: errorBody("settings_conflict", "Настройки изменены в другой вкладке. Обновите их перед сохранением.")}, nil
	}
	if errors.Is(err, inbound.ErrAutomationValidation) {
		return SaveMailAutomationdefaultJSONResponse{StatusCode: 400, Body: errorBody("invalid_settings", err.Error())}, nil
	}
	if err != nil {
		return nil, err
	}
	a, err = s.inbound.GetAutomation(ctx, r.MailboxId.String())
	if err != nil {
		return nil, err
	}
	out, err := automationAPI(a)
	if err != nil {
		return nil, err
	}
	return SaveMailAutomation200JSONResponse(out), nil
}
