package httpapi

import (
	"context"
	"errors"
	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/ratelimit"
	"time"
)

func (s *Server) ChangeInitialPassword(ctx context.Context, r ChangeInitialPasswordRequestObject) (ChangeInitialPasswordResponseObject, error) {
	fail := func(code int, key, msg string) (ChangeInitialPasswordResponseObject, error) {
		return ChangeInitialPassworddefaultJSONResponse{StatusCode: code, Body: errorBody(key, msg)}, nil
	}
	u, ok := account.CurrentUser(ctx)
	if !ok {
		return fail(401, "unauthenticated", "Войдите в аккаунт.")
	}
	if !s.allow(ctx, u.ID, ratelimit.Rule{Name: "initial-password", Limit: 10, Window: 15 * time.Minute}).Allowed {
		return fail(429, "rate_limited", "Слишком много попыток. Повторите позже.")
	}
	if r.Body == nil {
		return fail(400, "invalid_request", "Укажите начальный и новый пароль.")
	}
	creds, err := s.accounts.ChangeInitialPassword(ctx, u.ID, r.Body.CurrentPassword, r.Body.Password, requestContextFrom(ctx))
	switch {
	case errors.Is(err, account.ErrValidation):
		return fail(400, "validation_failed", err.Error())
	case errors.Is(err, account.ErrCredentials):
		return fail(403, "invalid_password", "Неверный начальный пароль.")
	case errors.Is(err, account.ErrPasswordAlreadyChanged):
		return fail(409, "password_already_changed", "Начальный пароль уже заменён. Войдите заново.")
	case err != nil:
		return nil, err
	}
	return ChangeInitialPassword200JSONResponse(credentialsToAPI(creds)), nil
}
