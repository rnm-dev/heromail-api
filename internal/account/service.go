package account

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"

	"github.com/rnm/heromail/backend/internal/provider"
)

var (
	ErrValidation   = errors.New("validation failed")
	ErrCredentials  = errors.New("invalid email or password")
	ErrInvalidToken = errors.New("invalid or expired token")
)

const (
	sessionTTL      = 30 * 24 * time.Hour
	verificationTTL = 24 * time.Hour
	// A reset link is a credential that takes over the account, so it lives far
	// shorter than a verification link, which only confirms an address.
	passwordResetTTL = time.Hour
)

// Config carries what the service needs from the environment.
type Config struct {
	// AppBaseURL is the frontend origin, used to build links in emails.
	AppBaseURL string
	// MailFrom is the envelope sender for system mail.
	MailFrom string
}

// Service holds the account rules. It depends on provider.Sender rather than
// SMTP, so tests substitute a fake transport.
type Service struct {
	store    *Store
	sender   provider.Sender
	cfg      Config
	validate *validator.Validate
}

func NewService(store *Store, sender provider.Sender, cfg Config) *Service {
	if cfg.AppBaseURL == "" {
		cfg.AppBaseURL = "http://localhost:8061"
	}
	if cfg.MailFrom == "" {
		cfg.MailFrom = "noreply@heromail.local"
	}
	return &Service{
		store:    store,
		sender:   sender,
		cfg:      cfg,
		validate: validator.New(validator.WithRequiredStructEnabled()),
	}
}

type RegisterRequest struct {
	Email    string `json:"email"    validate:"required,email,max=254"`
	Password string `json:"password" validate:"required"`
	Name     string `json:"name"     validate:"max=200"`
}

type LoginRequest struct {
	Email    string `json:"email"    validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// Credentials is what a successful sign-in hands back, matching the shape the
// frontend was built against.
type Credentials struct {
	Token     string    `json:"token"`
	User      *User     `json:"user"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// RequestContext is the browser detail worth recording on a session.
type RequestContext struct {
	UserAgent string
	IP        string
}

// Register creates the account, issues a session, and emails a verification
// link.
//
// The user is signed in immediately, before verifying. Blocking sign-in on a
// click in an inbox strands anyone whose mail is slow or filtered; the flag
// lives on the user, and the endpoints that genuinely need a proven address
// can require it.
func (s *Service) Register(ctx context.Context, req RegisterRequest, rc RequestContext) (*Credentials, error) {
	if err := s.validate.Struct(req); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrValidation, describeValidation(err))
	}

	email := normaliseEmail(req.Email)

	hash, err := hashPassword(req.Password)
	if err != nil {
		if errors.Is(err, ErrWeakPassword) {
			return nil, fmt.Errorf("%w: %s", ErrValidation, err.Error())
		}
		return nil, err
	}

	user, err := s.store.CreateWithPassword(ctx, email, strings.TrimSpace(req.Name), hash)
	if err != nil {
		return nil, err
	}

	s.sendVerificationEmail(ctx, user)

	return s.startSession(ctx, user, rc)
}

// Login verifies a password and starts a session.
func (s *Service) Login(ctx context.Context, req LoginRequest, rc RequestContext) (*Credentials, error) {
	if err := s.validate.Struct(req); err != nil {
		// Deliberately not detailed: a "no such email" shape would be an
		// account-existence oracle.
		return nil, ErrCredentials
	}

	user, hash, err := s.store.PasswordIdentity(ctx, normaliseEmail(req.Email))
	if errors.Is(err, ErrNotFound) {
		// Spend the same time as a real comparison would.
		burnPasswordTime()
		return nil, ErrCredentials
	}
	if err != nil {
		return nil, err
	}
	if !verifyPassword(hash, req.Password) {
		return nil, ErrCredentials
	}

	s.store.TouchIdentityLogin(ctx, ProviderPassword, normaliseEmail(req.Email))
	return s.startSession(ctx, user, rc)
}

// SignInWithIdentity is the single entry point for every external provider.
// An OIDC or SAML callback verifies the assertion, fills an ExternalIdentity,
// and calls this — nothing else in the stack needs to know which provider it
// was.
//
// Matching on a verified email address links the new provider to the existing
// account. An unverified address is never matched: otherwise anyone able to
// assert "I am ceo@acme.com" at some IdP would take over that account.
func (s *Service) SignInWithIdentity(ctx context.Context, ext ExternalIdentity, rc RequestContext) (*Credentials, error) {
	if ext.Provider == ProviderPassword {
		return nil, fmt.Errorf("%w: password is not an external provider", ErrValidation)
	}
	if strings.TrimSpace(ext.Subject) == "" {
		return nil, fmt.Errorf("%w: provider subject is empty", ErrValidation)
	}

	user, err := s.store.UserByExternalIdentity(ctx, ext.Provider, ext.Subject)
	switch {
	case err == nil:
		s.store.TouchIdentityLogin(ctx, ext.Provider, ext.Subject)
		return s.startSession(ctx, user, rc)
	case !errors.Is(err, ErrNotFound):
		return nil, err
	}

	if ext.EmailVerified && ext.Email != "" {
		existing, err := s.store.UserByEmail(ctx, normaliseEmail(ext.Email))
		if err == nil {
			if err := s.store.LinkIdentity(ctx, existing.ID, ext); err != nil {
				return nil, err
			}
			return s.startSession(ctx, existing, rc)
		}
		if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
	}

	ext.Email = normaliseEmail(ext.Email)
	created, err := s.store.CreateUserWithIdentity(ctx, ext)
	if err != nil {
		return nil, err
	}
	return s.startSession(ctx, created, rc)
}

// VerifyEmail consumes a token and marks the address proven.
func (s *Service) VerifyEmail(ctx context.Context, token string) (*User, error) {
	userID, err := s.store.ConsumeToken(ctx, PurposeEmailVerification, hashToken(token))
	if errors.Is(err, ErrNotFound) {
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}
	if err := s.store.MarkEmailVerified(ctx, userID); err != nil {
		return nil, err
	}
	return s.store.UserByID(ctx, userID)
}

// ResendVerification re-sends the link. It reports success even for unknown
// addresses, so it cannot be used to enumerate accounts.
func (s *Service) ResendVerification(ctx context.Context, email string) {
	user, err := s.store.UserByEmail(ctx, normaliseEmail(email))
	if err != nil || user.EmailVerified() {
		return
	}
	s.sendVerificationEmail(ctx, user)
}

// RequestPasswordReset emails a reset link. Like ResendVerification it is
// deliberately silent: the caller learns nothing about whether the address
// exists, or whether it has a password at all.
func (s *Service) RequestPasswordReset(ctx context.Context, email string) {
	user, err := s.store.UserByEmail(ctx, normaliseEmail(email))
	if err != nil {
		return
	}

	hasPassword, err := s.store.HasPasswordIdentity(ctx, user.ID)
	if err != nil || !hasPassword {
		// SSO-only accounts have nothing to reset.
		return
	}

	token, hash, err := newToken()
	if err != nil {
		log.Printf("account: generate reset token for %s: %v", user.ID, err)
		return
	}
	if err := s.store.IssueToken(ctx, user.ID, PurposePasswordReset, hash, passwordResetTTL); err != nil {
		log.Printf("account: store reset token for %s: %v", user.ID, err)
		return
	}

	link := fmt.Sprintf("%s/reset-password?token=%s",
		strings.TrimRight(s.cfg.AppBaseURL, "/"), url.QueryEscape(token))

	_, err = s.sender.Send(ctx, provider.Message{
		From:    s.cfg.MailFrom,
		To:      []string{user.Email},
		Subject: "Сброс пароля",
		TextBody: fmt.Sprintf(
			"Здравствуйте!\n\nЧтобы задать новый пароль, перейдите по ссылке:\n%s\n\n"+
				"Ссылка действует 1 час и сработает один раз. После смены пароля все "+
				"активные сессии будут завершены.\n\n"+
				"Если вы не запрашивали сброс, просто проигнорируйте это письмо — "+
				"пароль останется прежним.\n",
			link),
		HTMLBody: fmt.Sprintf(
			`<p>Здравствуйте!</p><p>Чтобы задать новый пароль, перейдите по ссылке:</p>`+
				`<p><a href="%s">Задать новый пароль</a></p>`+
				`<p>Ссылка действует 1 час и сработает один раз. После смены пароля все `+
				`активные сессии будут завершены.</p>`+
				`<p>Если вы не запрашивали сброс, просто проигнорируйте это письмо — `+
				`пароль останется прежним.</p>`,
			link),
	})
	if err != nil {
		log.Printf("account: send reset email to %s: %v", user.ID, err)
	}
}

// ResetPassword consumes a reset token, sets the new password and ends every
// existing session.
//
// Revoking the other sessions is the point of the feature: a reset is what
// someone does when they think the account is compromised, and leaving the
// attacker signed in would make it theatre. The browser doing the reset gets a
// fresh session back so it is not logged out of its own action.
func (s *Service) ResetPassword(ctx context.Context, token, newPassword string, rc RequestContext) (*Credentials, error) {
	hash, err := hashPassword(newPassword)
	if err != nil {
		if errors.Is(err, ErrWeakPassword) {
			return nil, fmt.Errorf("%w: %s", ErrValidation, err.Error())
		}
		return nil, err
	}

	// Consume first: a weak password should not burn the token, but everything
	// past this point must be single-use.
	userID, err := s.store.ConsumeToken(ctx, PurposePasswordReset, hashToken(token))
	if errors.Is(err, ErrNotFound) {
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}

	if err := s.store.UpdatePassword(ctx, userID, hash); err != nil {
		return nil, fmt.Errorf("update password: %w", err)
	}
	if err := s.store.RevokeAllSessions(ctx, userID); err != nil {
		return nil, fmt.Errorf("revoke sessions: %w", err)
	}

	// Reading the link proves control of the address, so an unverified account
	// becomes verified here — the same proof the verification flow asks for.
	if err := s.store.MarkEmailVerified(ctx, userID); err != nil {
		log.Printf("account: mark verified after reset for %s: %v", userID, err)
	}

	user, err := s.store.UserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return s.startSession(ctx, user, rc)
}

func (s *Service) Logout(ctx context.Context, token string) error {
	return s.store.RevokeSession(ctx, hashToken(token))
}

func (s *Service) UserByID(ctx context.Context, id string) (*User, error) {
	return s.store.UserByID(ctx, id)
}

func (s *Service) startSession(ctx context.Context, user *User, rc RequestContext) (*Credentials, error) {
	token, hash, err := newToken()
	if err != nil {
		return nil, err
	}
	sess, err := s.store.CreateSession(ctx, user.ID, hash, rc.UserAgent, rc.IP, sessionTTL)
	if err != nil {
		return nil, err
	}
	return &Credentials{Token: token, User: user, ExpiresAt: sess.ExpiresAt}, nil
}

// sendVerificationEmail is best-effort: a mail outage must not prevent the
// account from existing. The user can always ask for another link.
func (s *Service) sendVerificationEmail(ctx context.Context, user *User) {
	token, hash, err := newToken()
	if err != nil {
		log.Printf("account: generate verification token for %s: %v", user.ID, err)
		return
	}
	if err := s.store.IssueToken(ctx, user.ID, PurposeEmailVerification, hash, verificationTTL); err != nil {
		log.Printf("account: store verification token for %s: %v", user.ID, err)
		return
	}

	link := fmt.Sprintf("%s/verify-email?token=%s",
		strings.TrimRight(s.cfg.AppBaseURL, "/"), url.QueryEscape(token))

	_, err = s.sender.Send(ctx, provider.Message{
		From:    s.cfg.MailFrom,
		To:      []string{user.Email},
		Subject: "Подтвердите адрес электронной почты",
		TextBody: fmt.Sprintf(
			"Здравствуйте!\n\nПодтвердите адрес, перейдя по ссылке:\n%s\n\n"+
				"Ссылка действует 24 часа. Если вы не регистрировались, просто проигнорируйте это письмо.\n",
			link),
		HTMLBody: fmt.Sprintf(
			`<p>Здравствуйте!</p><p>Подтвердите адрес, перейдя по ссылке:</p>`+
				`<p><a href="%s">Подтвердить адрес</a></p>`+
				`<p>Ссылка действует 24 часа. Если вы не регистрировались, просто проигнорируйте это письмо.</p>`,
			link),
	})
	if err != nil {
		log.Printf("account: send verification email to %s: %v", user.ID, err)
	}
}

func normaliseEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func describeValidation(err error) string {
	var fieldErrs validator.ValidationErrors
	if !errors.As(err, &fieldErrs) {
		return err.Error()
	}
	msg := ""
	for i, fe := range fieldErrs {
		if i > 0 {
			msg += "; "
		}
		switch fe.Tag() {
		case "required":
			msg += fmt.Sprintf("%s is required", fe.Field())
		case "email":
			msg += fmt.Sprintf("%s must be a valid email address", fe.Field())
		default:
			msg += fmt.Sprintf("%s violates %s=%s", fe.Field(), fe.Tag(), fe.Param())
		}
	}
	return msg
}
