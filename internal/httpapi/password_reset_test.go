package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// resetLink triggers a reset for addr and returns the token from the email.
func (h *harness) resetLink(t *testing.T, addr string) string {
	t.Helper()

	rec := h.do(http.MethodPost, "/auth/forgot-password", fmt.Sprintf(`{"email":%q}`, addr), "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("forgot-password: %d %s", rec.Code, rec.Body)
	}

	msg, ok := h.mail.last()
	if !ok {
		t.Fatal("no reset email was sent")
	}
	if !strings.Contains(msg.TextBody, "/reset-password?token=") {
		t.Fatalf("email does not carry a reset link:\n%s", msg.TextBody)
	}
	return extractToken(t, msg.TextBody)
}

func TestPasswordResetEndsEveryOtherSession(t *testing.T) {
	h := newHarness(t)
	oldSession, _, addr := h.registerUser("reset")

	// A second signed-in browser — think of it as the attacker's.
	second := decodeSessionToken(t, h.do(http.MethodPost, "/auth/login",
		fmt.Sprintf(`{"email":%q,"password":"correct-horse-battery"}`, addr), ""))
	if rec := h.do(http.MethodGet, "/auth/me", "", second); rec.Code != http.StatusOK {
		t.Fatalf("second session did not start: %d", rec.Code)
	}

	token := h.resetLink(t, addr)

	rec := h.do(http.MethodPost, "/auth/reset-password",
		fmt.Sprintf(`{"token":%q,"password":"brand-new-passphrase"}`, token), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body)
	}
	fresh := decodeSessionToken(t, rec)

	// Both pre-existing sessions must be gone — that is the whole point.
	for label, tok := range map[string]string{"original": oldSession, "other browser": second} {
		t.Run(label+" session revoked", func(t *testing.T) {
			if got := h.do(http.MethodGet, "/auth/me", "", tok); got.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401 — a reset that leaves sessions alive is theatre", got.Code)
			}
		})
	}

	// The browser that performed the reset stays signed in.
	if got := h.do(http.MethodGet, "/auth/me", "", fresh); got.Code != http.StatusOK {
		t.Errorf("the resetting browser was logged out (%d)", got.Code)
	}

	// The new password works and the old one does not.
	if got := h.do(http.MethodPost, "/auth/login",
		fmt.Sprintf(`{"email":%q,"password":"brand-new-passphrase"}`, addr), ""); got.Code != http.StatusOK {
		t.Errorf("new password rejected (%d)", got.Code)
	}
	if got := h.do(http.MethodPost, "/auth/login",
		fmt.Sprintf(`{"email":%q,"password":"correct-horse-battery"}`, addr), ""); got.Code != http.StatusUnauthorized {
		t.Errorf("the old password still works (%d)", got.Code)
	}
}

func TestPasswordResetTokenIsSingleUseAndShortLived(t *testing.T) {
	h := newHarness(t)
	_, userID, addr := h.registerUser("reset-once")

	token := h.resetLink(t, addr)
	if rec := h.do(http.MethodPost, "/auth/reset-password",
		fmt.Sprintf(`{"token":%q,"password":"brand-new-passphrase"}`, token), ""); rec.Code != http.StatusOK {
		t.Fatalf("first reset: %d %s", rec.Code, rec.Body)
	}

	again := h.do(http.MethodPost, "/auth/reset-password",
		fmt.Sprintf(`{"token":%q,"password":"another-passphrase-x"}`, token), "")
	if again.Code != http.StatusBadRequest {
		t.Errorf("a consumed token was accepted again (%d)", again.Code)
	}
	if code := errorCode(t, again); code != "invalid_token" {
		t.Errorf("error code = %q, want invalid_token", code)
	}

	if rec := h.do(http.MethodPost, "/auth/reset-password",
		`{"token":"nonsense","password":"brand-new-passphrase"}`, ""); rec.Code != http.StatusBadRequest {
		t.Errorf("a bogus token was accepted (%d)", rec.Code)
	}

	// The link must expire well before a verification link does.
	var ttl time.Duration
	var expires, created time.Time
	err := h.pool.QueryRow(context.Background(),
		`SELECT expires_at, created_at FROM user_tokens
		 WHERE user_id = $1 AND purpose = 'password_reset'
		 ORDER BY created_at DESC LIMIT 1`, userID).Scan(&expires, &created)
	if err != nil {
		t.Fatalf("read token row: %v", err)
	}
	ttl = expires.Sub(created)
	if ttl > 2*time.Hour {
		t.Errorf("reset token lives %v; a link that takes over an account should be short", ttl)
	}
}

func TestIssuingANewResetLinkInvalidatesThePrevious(t *testing.T) {
	h := newHarness(t)
	_, _, addr := h.registerUser("reset-reissue")

	first := h.resetLink(t, addr)
	second := h.resetLink(t, addr)
	if first == second {
		t.Fatal("the second request reused the same token")
	}

	if rec := h.do(http.MethodPost, "/auth/reset-password",
		fmt.Sprintf(`{"token":%q,"password":"brand-new-passphrase"}`, first), ""); rec.Code != http.StatusBadRequest {
		t.Errorf("the superseded link still works (%d)", rec.Code)
	}
	if rec := h.do(http.MethodPost, "/auth/reset-password",
		fmt.Sprintf(`{"token":%q,"password":"brand-new-passphrase"}`, second), ""); rec.Code != http.StatusOK {
		t.Errorf("the newest link does not work (%d)", rec.Code)
	}
}

func TestForgotPasswordDoesNotLeakAccounts(t *testing.T) {
	h := newHarness(t)
	_, _, addr := h.registerUser("reset-leak")

	known := h.do(http.MethodPost, "/auth/forgot-password", fmt.Sprintf(`{"email":%q}`, addr), "")
	unknown := h.do(http.MethodPost, "/auth/forgot-password", `{"email":"nobody@acme.test"}`, "")

	if known.Code != http.StatusAccepted || unknown.Code != http.StatusAccepted {
		t.Errorf("statuses = %d/%d, want 202/202", known.Code, unknown.Code)
	}
	if known.Body.String() != unknown.Body.String() {
		t.Errorf("bodies differ, which is an account oracle: %q vs %q", known.Body, unknown.Body)
	}

	// Nothing must have been sent for the unknown address.
	h.mail.reset()
	h.do(http.MethodPost, "/auth/forgot-password", `{"email":"nobody@acme.test"}`, "")
	if h.mail.count() != 0 {
		t.Errorf("%d messages sent for an unregistered address", h.mail.count())
	}
}

func TestResetRejectsWeakPasswordWithoutBurningTheToken(t *testing.T) {
	h := newHarness(t)
	_, _, addr := h.registerUser("reset-weak")
	token := h.resetLink(t, addr)

	weak := h.do(http.MethodPost, "/auth/reset-password",
		fmt.Sprintf(`{"token":%q,"password":"short"}`, token), "")
	if weak.Code != http.StatusBadRequest {
		t.Fatalf("weak password accepted (%d)", weak.Code)
	}
	if code := errorCode(t, weak); code != "validation_failed" {
		t.Errorf("error code = %q, want validation_failed", code)
	}

	// The token survives a rejected password, so the user can retry with a
	// better one instead of requesting a fresh link.
	if rec := h.do(http.MethodPost, "/auth/reset-password",
		fmt.Sprintf(`{"token":%q,"password":"brand-new-passphrase"}`, token), ""); rec.Code != http.StatusOK {
		t.Errorf("the token was consumed by a rejected password (%d %s)", rec.Code, rec.Body)
	}
}

func TestResetVerifiesTheAddress(t *testing.T) {
	h := newHarness(t)
	token, _, addr := h.registerUser("reset-verifies")

	// Registration leaves the address unverified.
	var me struct {
		User struct {
			EmailVerified bool `json:"email_verified"`
		} `json:"user"`
	}
	json.Unmarshal(h.do(http.MethodGet, "/auth/me", "", token).Body.Bytes(), &me)
	if me.User.EmailVerified {
		t.Fatal("precondition failed: the address is already verified")
	}

	link := h.resetLink(t, addr)
	rec := h.do(http.MethodPost, "/auth/reset-password",
		fmt.Sprintf(`{"token":%q,"password":"brand-new-passphrase"}`, link), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body)
	}

	// Reading the link proved control of the mailbox.
	var creds struct {
		User struct {
			EmailVerified bool `json:"email_verified"`
		} `json:"user"`
	}
	json.Unmarshal(rec.Body.Bytes(), &creds)
	if !creds.User.EmailVerified {
		t.Error("the address is still unverified after a reset link was used")
	}
}

// decodeSessionToken pulls the session token out of a credentials response.
func decodeSessionToken(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()

	var creds struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &creds); err != nil {
		t.Fatalf("decode credentials: %v (body: %s)", err, rec.Body)
	}
	if creds.Token == "" {
		t.Fatalf("no session token in response: %s", rec.Body)
	}
	return creds.Token
}
