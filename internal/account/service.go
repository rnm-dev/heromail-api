package account

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"

	"github.com/rnm/heromail/backend/internal/provider"
)

var (
	ErrValidation   = errors.New("validation failed")
	ErrCredentials  = errors.New("invalid email or password")
	ErrInvalidToken = errors.New("invalid or expired token")
	// ErrCodeLocked means too many wrong codes were entered and the code is
	// refused for a while — including the right one.
	ErrCodeLocked = errors.New("too many attempts")
)

const (
	sessionTTL = 30 * 24 * time.Hour

	// A one-time code lives minutes, not hours. It is short enough to type
	// straight out of an open inbox, and a window that stays open for a day
	// would give a guesser a day of tries against 6 digits.
	verificationTTL = 15 * time.Minute

	// A reset link is a credential that takes over the account, so it lives far
	// shorter than a verification link, which only confirms an address.
	passwordResetTTL = time.Hour

	// maxOTPAttempts caps guesses against one code. Seven is generous for
	// someone copying digits out of an email and still leaves an attacker
	// needing ~140k codes to expect one hit, against a code that dies in 15
	// minutes anyway.
	maxOTPAttempts = 7

	// otpLockout is how long the code is refused once the cap is hit. Long
	// enough that automated guessing is pointless, short enough that a person
	// who fat-fingered it is not locked out of their own signup for the day.
	otpLockout = 15 * time.Minute
)

// Config carries what the service needs from the environment.
type Config struct {
	// AppBaseURL is the frontend origin, used to build links in emails.
	AppBaseURL string
	// MailFrom is the envelope sender for system mail.
	MailFrom string
}

// SystemSigner resolves the DKIM key for the domain our own mail is sent from.
//
// It is an interface, not *maildomain.Service, for the same reason the sender
// is: this package is tested without a database, and a signer is optional —
// nil means send unsigned, which is what dev and every test do.
type SystemSigner interface {
	SystemSigningKey(ctx context.Context, domain string) (selector string, privateKeyDER []byte, err error)
}

// Service holds the account rules. It depends on provider.Sender rather than
// SMTP, so tests substitute a fake transport.
type Service struct {
	store    *Store
	sender   provider.Sender
	signer   SystemSigner
	cfg      Config
	validate *validator.Validate
}

// WithSigner attaches DKIM signing for system mail. Separate from the
// constructor because it is genuinely optional: without it verification codes
// still send, just unsigned.
func (s *Service) WithSigner(signer SystemSigner) *Service {
	s.signer = signer
	return s
}

// signMailFrom resolves the DKIM key for the MAIL_FROM domain, or nil if this
// deployment has no signer, no such domain, or the domain is unverified.
//
// A failure here never blocks the mail. System mail carries verification codes
// and reset links — refusing to send one because a signature could not be
// produced would lock people out of their accounts to protect a deliverability
// improvement, which is the wrong trade.
func (s *Service) signMailFrom(ctx context.Context) *provider.DKIM {
	if s.signer == nil {
		return nil
	}
	at := strings.LastIndex(s.cfg.MailFrom, "@")
	if at < 0 || at+1 >= len(s.cfg.MailFrom) {
		return nil
	}
	domain := s.cfg.MailFrom[at+1:]

	selector, der, err := s.signer.SystemSigningKey(ctx, domain)
	if err != nil {
		log.Printf("account: no DKIM key for %s, sending unsigned: %v", domain, err)
		return nil
	}
	return &provider.DKIM{Domain: domain, Selector: selector, PrivateKeyDER: der}
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

var personalNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,28}[a-z0-9]$`)

func validatePersonalName(name string) error {
	if !personalNamePattern.MatchString(name) || strings.Contains(name, "..") {
		return fmt.Errorf("%w: use 3–30 Latin letters, digits, dots, underscores or hyphens", ErrValidation)
	}
	for _, reserved := range []string{"admin", "administrator", "support", "postmaster", "abuse", "security", "noreply", "no-reply", "mailer-daemon", "root", "info", "sales", "billing", "help", "contact", "hostmaster", "webmaster"} {
		if name == reserved {
			return fmt.Errorf("%w: this address is reserved", ErrValidation)
		}
	}
	return nil
}

type RegisterRequest struct {
	PersonalName string `json:"personal_name"`
	Email        string `json:"email"    validate:"required,email,max=254"`
	Password     string `json:"password" validate:"required"`
	Name         string `json:"name"     validate:"max=200"`
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

	req.PersonalName = strings.ToLower(strings.TrimSpace(req.PersonalName))
	if req.PersonalName != "" {
		if err := validatePersonalName(req.PersonalName); err != nil {
			return nil, err
		}
	}
	email := normaliseEmail(req.Email)
	if strings.HasSuffix(email, "@heromail.kz") {
		return nil, fmt.Errorf("%w: укажите внешнюю почту для входа и восстановления", ErrValidation)
	}

	hash, err := hashPassword(req.Password)
	if err != nil {
		if errors.Is(err, ErrWeakPassword) {
			return nil, fmt.Errorf("%w: %s", ErrValidation, err.Error())
		}
		return nil, err
	}

	user, err := s.store.CreateWithPassword(ctx, email, strings.TrimSpace(req.Name), hash, req.PersonalName)
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

// VerifyEmail checks a one-time code and marks the address proven.
//
// Unlike a link, a code is presented alongside the address it belongs to: the
// attempt has to be attributed to a specific account in order to be counted
// against that account's budget.
//
// An unknown address and a wrong code are reported identically
// (ErrInvalidToken). Saying "no pending code for this address" would turn the
// endpoint into an account-enumeration oracle, which is the same reason
// resend-verification answers 202 for everyone.
func (s *Service) VerifyEmail(ctx context.Context, email, code string) (*User, error) {
	user, err := s.store.UserByEmail(ctx, normaliseEmail(email))
	if errors.Is(err, ErrNotFound) {
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}

	res, err := s.store.ConsumeOTP(ctx, user.ID, PurposeEmailVerification,
		hashOTP(user.ID, code), maxOTPAttempts, otpLockout)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}

	switch {
	case res.LockedUntil != nil:
		return nil, fmt.Errorf("%w: try again in %s", ErrCodeLocked,
			time.Until(*res.LockedUntil).Round(time.Minute))
	case !res.OK:
		return nil, fmt.Errorf("%w: %d attempts left", ErrInvalidToken, res.Remaining)
	}

	if err := s.store.MarkEmailVerified(ctx, user.ID); err != nil {
		return nil, err
	}
	return s.store.UserByID(ctx, user.ID)
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
		DKIM:    s.signMailFrom(ctx),
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
	code, err := newOTP()
	if err != nil {
		log.Printf("account: generate verification code for %s: %v", user.ID, err)
		return
	}
	// Issuing replaces any live code, so an earlier email stops working and
	// its attempt counter goes with it. That is what keeps "request another
	// code" from being a way to reset the budget on the *same* code while
	// still letting a stuck user start over.
	if err := s.store.IssueToken(ctx, user.ID, PurposeEmailVerification,
		hashOTP(user.ID, code), verificationTTL); err != nil {
		log.Printf("account: store verification code for %s: %v", user.ID, err)
		return
	}

	minutes := int(verificationTTL.Minutes())

	_, err = s.sender.Send(ctx, provider.Message{
		DKIM:    s.signMailFrom(ctx),
		From:    s.cfg.MailFrom,
		To:      []string{user.Email},
		Subject: "Код подтверждения: " + code,
		// The sender is a real mailbox now, so the message invites a reply
		// instead of telling people not to send one. "Ignore this" is still the
		// correct advice for someone who did not sign up — nothing happens
		// without the code — but it should not be the only option offered.
		TextBody: fmt.Sprintf(
			"Здравствуйте!\n\nВаш код подтверждения: %s\n\n"+
				"Код действует %d минут.\n\n"+
				"Если вы не регистрировались, письмо можно проигнорировать — без кода "+
				"никто не получит доступ к аккаунту. Если это повторяется, ответьте на "+
				"это письмо, мы разберёмся.\n",
			code, minutes),
		HTMLBody: fmt.Sprintf(
			`<p>Здравствуйте!</p><p>Ваш код подтверждения:</p>`+
				`<p style="font-size:28px;font-weight:700;letter-spacing:4px">%s</p>`+
				`<p>Код действует %d минут.</p>`+
				`<p>Если вы не регистрировались, письмо можно проигнорировать — без кода `+
				`никто не получит доступ к аккаунту. Если это повторяется, ответьте на это `+
				`письмо, мы разберёмся.</p>`,
			code, minutes),
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
