package httpapi

import (
	"fmt"
	"net/http"
	"strconv"
	"testing"
)

// wrongCode returns a six-digit code that is not the right one, so a test can
// spend attempts without accidentally succeeding.
func wrongCode(correct string, n int) string {
	c, _ := strconv.Atoi(correct)
	return fmt.Sprintf("%06d", (c+n+1)%1_000_000)
}

// pendingCode registers a user and returns their address and current code.
func pendingCode(t *testing.T, h *harness, name string) (addr, code string) {
	t.Helper()
	_, _, addr = h.registerUser(name)
	msg, ok := h.mail.last()
	if !ok {
		t.Fatal("no verification email was sent")
	}
	return addr, extractOTP(t, msg.TextBody)
}

func TestVerifyLocksAfterSevenWrongCodes(t *testing.T) {
	h := newHarness(t)
	addr, code := pendingCode(t, h, "otp-lock")

	// Six wrong guesses are refused but do not lock.
	for i := 0; i < 6; i++ {
		body := fmt.Sprintf(`{"email":%q,"code":%q}`, addr, wrongCode(code, i))
		if rec := h.do(http.MethodPost, "/auth/verify-email", body, ""); rec.Code != http.StatusBadRequest {
			t.Fatalf("attempt %d: status %d, want 400; body %s", i+1, rec.Code, rec.Body)
		}
	}

	// The seventh trips the lock.
	body := fmt.Sprintf(`{"email":%q,"code":%q}`, addr, wrongCode(code, 6))
	rec := h.do(http.MethodPost, "/auth/verify-email", body, "")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("seventh attempt: status %d, want 429; body %s", rec.Code, rec.Body)
	}
	if got := errorCode(t, rec); got != "code_locked" {
		t.Errorf("error code = %q, want code_locked", got)
	}
	if ra := rec.Header().Get("Retry-After"); ra == "" {
		t.Error("no Retry-After on a lockout")
	}

	// And the correct code is refused too. If it were accepted, the lock would
	// tell an attacker exactly which guess had been right.
	correct := fmt.Sprintf(`{"email":%q,"code":%q}`, addr, code)
	if rec := h.do(http.MethodPost, "/auth/verify-email", correct, ""); rec.Code != http.StatusTooManyRequests {
		t.Errorf("the correct code bypassed the lock (%d)", rec.Code)
	}
}

func TestVerifyAcceptsTheCorrectCodeBeforeTheCap(t *testing.T) {
	h := newHarness(t)
	addr, code := pendingCode(t, h, "otp-ok")

	// Burn a few attempts, then succeed: a wrong guess must not poison a
	// later correct one.
	for i := 0; i < 3; i++ {
		h.do(http.MethodPost, "/auth/verify-email",
			fmt.Sprintf(`{"email":%q,"code":%q}`, addr, wrongCode(code, i)), "")
	}

	body := fmt.Sprintf(`{"email":%q,"code":%q}`, addr, code)
	if rec := h.do(http.MethodPost, "/auth/verify-email", body, ""); rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; body %s", rec.Code, rec.Body)
	}
}

// The attempt budget belongs to one account, not to the endpoint: one user
// exhausting theirs must not lock anybody else out of signing up.
func TestOneUsersLockoutDoesNotAffectAnother(t *testing.T) {
	h := newHarness(t)
	addrA, codeA := pendingCode(t, h, "otp-a")

	for i := 0; i < 7; i++ {
		h.do(http.MethodPost, "/auth/verify-email",
			fmt.Sprintf(`{"email":%q,"code":%q}`, addrA, wrongCode(codeA, i)), "")
	}

	addrB, codeB := pendingCode(t, h, "otp-b")
	body := fmt.Sprintf(`{"email":%q,"code":%q}`, addrB, codeB)
	if rec := h.do(http.MethodPost, "/auth/verify-email", body, ""); rec.Code != http.StatusOK {
		t.Fatalf("second user got %d, want 200; body %s", rec.Code, rec.Body)
	}
}

// Requesting a new code replaces the old one, which both invalidates the
// previous email and hands back a fresh attempt budget — the intended escape
// hatch for someone who mistyped their way into a lock.
func TestResendIssuesANewCodeAndClearsTheOldOne(t *testing.T) {
	h := newHarness(t)
	addr, first := pendingCode(t, h, "otp-resend")

	if rec := h.do(http.MethodPost, "/auth/resend-verification",
		fmt.Sprintf(`{"email":%q}`, addr), ""); rec.Code != http.StatusAccepted {
		t.Fatalf("resend: status %d, body %s", rec.Code, rec.Body)
	}

	msg, _ := h.mail.last()
	second := extractOTP(t, msg.TextBody)
	if second == first {
		t.Fatal("resend returned the same code; the old one was not replaced")
	}

	// The superseded code must be dead.
	if rec := h.do(http.MethodPost, "/auth/verify-email",
		fmt.Sprintf(`{"email":%q,"code":%q}`, addr, first), ""); rec.Code != http.StatusBadRequest {
		t.Errorf("the previous code still works (%d)", rec.Code)
	}
	// The new one works.
	if rec := h.do(http.MethodPost, "/auth/verify-email",
		fmt.Sprintf(`{"email":%q,"code":%q}`, addr, second), ""); rec.Code != http.StatusOK {
		t.Errorf("the new code was refused (%d)", rec.Code)
	}
}

// An address with nothing pending and a wrong code must be indistinguishable,
// or the endpoint becomes a way to discover who is registered.
func TestVerifyDoesNotLeakWhetherAnAddressExists(t *testing.T) {
	h := newHarness(t)
	addr, code := pendingCode(t, h, "otp-enum")

	known := h.do(http.MethodPost, "/auth/verify-email",
		fmt.Sprintf(`{"email":%q,"code":%q}`, addr, wrongCode(code, 0)), "")
	unknown := h.do(http.MethodPost, "/auth/verify-email",
		`{"email":"nobody-at-all@heromail.test","code":"000000"}`, "")

	if known.Code != unknown.Code {
		t.Errorf("statuses differ: known %d vs unknown %d", known.Code, unknown.Code)
	}
	if errorCode(t, known) != errorCode(t, unknown) {
		t.Errorf("error codes differ: %q vs %q", errorCode(t, known), errorCode(t, unknown))
	}
}
