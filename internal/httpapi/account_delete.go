package httpapi

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/ratelimit"
)

// deleteAccountPerUser bounds password guesses through the deletion endpoint,
// which a stolen session could otherwise use as a password oracle.
var deleteAccountPerUser = ratelimit.Rule{Name: "delete-account", Limit: 5, Window: 15 * time.Minute}

func (s *Server) DeleteAccount(ctx context.Context, r DeleteAccountRequestObject) (DeleteAccountResponseObject, error) {
	user, ok := account.CurrentUser(ctx)
	if !ok {
		return DeleteAccount401JSONResponse{UnauthorizedJSONResponse(errorBody("unauthenticated", "no session"))}, nil
	}
	if r.Body == nil || r.Body.Password == "" {
		return DeleteAccount400JSONResponse{BadRequestJSONResponse(errorBody("validation_failed", "password is required"))}, nil
	}
	if res := s.allow(ctx, user.ID, deleteAccountPerUser); !res.Allowed {
		return DeleteAccount429JSONResponse{tooMany(res, "too many attempts; try again later")}, nil
	}

	result, err := s.accounts.DeleteAccount(ctx, user.ID, r.Body.Password)
	var sole *account.SoleOwnerError
	switch {
	case errors.As(err, &sole):
		body := errorBody("sole_owner", "Вы владелец рабочих пространств. Удалите их или попросите поддержку передать владение, затем повторите.")
		body.Error.Details = map[string]any{"workspaces": sole.Workspaces}
		return DeleteAccount409JSONResponse(body), nil
	case errors.Is(err, account.ErrCredentials):
		return DeleteAccount403JSONResponse(errorBody("invalid_password", "Неверный пароль.")), nil
	case errors.Is(err, account.ErrNoPassword):
		return DeleteAccount409JSONResponse(errorBody("password_required", "У аккаунта нет пароля для подтверждения.")), nil
	case errors.Is(err, account.ErrNotFound):
		return DeleteAccount401JSONResponse{UnauthorizedJSONResponse(errorBody("unauthenticated", "no session"))}, nil
	case err != nil:
		log.Printf("delete account %s: %v", user.ID, err)
		return nil, err
	}
	log.Printf("account %s deleted: personal workspaces %v, retained mailboxes %v",
		user.ID, result.PersonalWorkspaces, result.RetainedMailboxes)
	return DeleteAccount204Response{}, nil
}

// accountDeletionPage is the public instruction page Google Play's Data
// safety form asks for. Static, no authentication.
func accountDeletionPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write([]byte(accountDeletionHTML))
}

const accountDeletionHTML = `<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Удаление аккаунта Heromail</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:720px;margin:40px auto;padding:0 16px;color:#1b1b1f}h1{font-size:26px}h2{font-size:19px;margin-top:28px}</style>
</head><body>
<h1>Удаление аккаунта Heromail</h1>
<h2>Как удалить</h2>
<ol>
<li>Откройте приложение Heromail и войдите в аккаунт.</li>
<li>Профиль → «Удалить аккаунт».</li>
<li>Подтвердите паролем. Аккаунт удаляется сразу, на почту придёт подтверждение.</li>
</ol>
<p>Нет доступа к приложению? Напишите с адреса аккаунта на <a href="mailto:hello@heromail.kz">hello@heromail.kz</a>, мы удалим аккаунт вручную.</p>
<p>Если вы единственный владелец рабочего пространства, сначала передайте владение другому участнику или удалите пространство.</p>
<h2>Что удаляется</h2>
<ul>
<li>Пароль и все способы входа, все сессии и подключённые устройства, push-токены.</li>
<li>Ключи ассистентов и выданные вами SMTP-пароли ящиков.</li>
<li>Контакты, черновики, подписи, настройки уведомлений, личные календари.</li>
<li>Личный ящик и вся его почта, если он у вас был.</li>
<li>Имя и адрес: в базе остаётся только обезличенная запись без персональных данных.</li>
</ul>
<h2>Что остаётся</h2>
<ul>
<li>Корпоративные ящики организации и их почта принадлежат организации. После удаления аккаунта они закрыты для всех, пока администратор организации не передаст или не удалит их.</li>
<li>Письма, которые вы уже отправили, остаются у получателей.</li>
</ul>
<p>English: open the Heromail app → Profile → Delete account, and confirm with your password. Your sign-in methods, sessions, devices and personal data are deleted immediately; mailboxes owned by your organisation stay with it.</p>
</body></html>
`
