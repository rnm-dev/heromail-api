package httpapi

import (
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// These need the real limiter, so they need Redis. newHarness builds one when
// REDIS_ADDR is set and leaves it nil otherwise, which is why every other test
// in this package is unaffected by limits.
func requireLimiter(t *testing.T, h *harness) {
	t.Helper()
	if h.limiter == nil {
		t.Skip("REDIS_ADDR is not set; skipping rate limit tests")
	}
}

func TestForgotPasswordIsRateLimitedPerAddress(t *testing.T) {
	h := newHarness(t)
	requireLimiter(t, h)

	_, _, addr := h.registerUser("limit-reset")

	// The rule allows 3 an hour. The fourth must be refused.
	for i := 1; i <= 3; i++ {
		rec := h.do(http.MethodPost, "/auth/forgot-password", fmt.Sprintf(`{"email":%q}`, addr), "")
		if rec.Code != http.StatusAccepted {
			t.Fatalf("request %d: status %d, want 202", i, rec.Code)
		}
	}

	rec := h.do(http.MethodPost, "/auth/forgot-password", fmt.Sprintf(`{"email":%q}`, addr), "")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the fourth request returned %d, want 429 — otherwise we are a mailbox-flooding tool", rec.Code)
	}
	if code := errorCode(t, rec); code != "rate_limited" {
		t.Errorf("error code = %q, want rate_limited", code)
	}

	// Retry-After has to be usable, not decorative.
	raw := rec.Header().Get("Retry-After")
	secs, err := strconv.Atoi(raw)
	if err != nil || secs < 1 {
		t.Errorf("Retry-After = %q, want a positive number of seconds", raw)
	}
	if secs > int((2 * time.Hour).Seconds()) {
		t.Errorf("Retry-After = %ds, longer than the window", secs)
	}

	// The counter is per address: a different one is unaffected.
	_, _, other := h.registerUser("limit-reset-other")
	if rec := h.do(http.MethodPost, "/auth/forgot-password", fmt.Sprintf(`{"email":%q}`, other), ""); rec.Code != http.StatusAccepted {
		t.Errorf("a different address was refused (%d); the limit is not per address", rec.Code)
	}
}

func TestForgotPasswordLimitIsCaseInsensitive(t *testing.T) {
	h := newHarness(t)
	requireLimiter(t, h)

	_, _, addr := h.registerUser("limit-case")
	upper := upperLocal(addr)

	// Mixing case must not hand out a fresh budget.
	for i := 0; i < 3; i++ {
		h.do(http.MethodPost, "/auth/forgot-password", fmt.Sprintf(`{"email":%q}`, addr), "")
	}
	if rec := h.do(http.MethodPost, "/auth/forgot-password", fmt.Sprintf(`{"email":%q}`, upper), ""); rec.Code != http.StatusTooManyRequests {
		t.Errorf("changing the case reset the counter (%d)", rec.Code)
	}
}

func TestLoginIsRateLimitedPerAddress(t *testing.T) {
	h := newHarness(t)
	requireLimiter(t, h)

	_, _, addr := h.registerUser("limit-login")

	// 10 an hour per address. Wrong passwords count.
	var last int
	for i := 0; i < 11; i++ {
		rec := h.do(http.MethodPost, "/auth/login",
			fmt.Sprintf(`{"email":%q,"password":"definitely-wrong-here"}`, addr), "")
		last = rec.Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("after 11 attempts the status is %d, want 429 — password guessing is unthrottled", last)
	}

	// And the throttle applies to the correct password too: an attacker must
	// not be able to confirm a guess after burning the budget.
	rec := h.do(http.MethodPost, "/auth/login",
		fmt.Sprintf(`{"email":%q,"password":"correct-horse-battery"}`, addr), "")
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("the correct password bypassed the limit (%d)", rec.Code)
	}
}

func TestSendIsRateLimitedPerWorkspace(t *testing.T) {
	h := newHarness(t)
	requireLimiter(t, h)

	token, _, _ := h.registerUser("limit-send")
	workspaceID := h.workspaceFor(token, "limit-send")
	key := h.apiKeyFor(workspaceID)

	// The per-minute rule is read from the environment on every call, so the
	// test can lower it instead of sending sixty messages.
	t.Setenv("SEND_LIMIT_PER_MINUTE", "3")

	const body = `{"from":"noreply@acme.com","to":["viktor@acme.com"],"text":"hello"}`
	for i := 1; i <= 3; i++ {
		if rec := h.do(http.MethodPost, "/v1/emails", body, key); rec.Code != http.StatusAccepted {
			t.Fatalf("message %d: status %d, want 202", i, rec.Code)
		}
	}

	rec := h.do(http.MethodPost, "/v1/emails", body, key)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the fourth message returned %d, want 429 — one tenant can exhaust shared sending IPs", rec.Code)
	}
	if code := errorCode(t, rec); code != "rate_limited" {
		t.Errorf("error code = %q, want rate_limited", code)
	}

	// A different workspace has its own budget: one noisy tenant must not
	// silence the others.
	otherToken, _, _ := h.registerUser("limit-send-other")
	otherWorkspace := h.workspaceFor(otherToken, "limit-send-other")
	otherKey := h.apiKeyFor(otherWorkspace)
	if rec := h.do(http.MethodPost, "/v1/emails", body, otherKey); rec.Code != http.StatusAccepted {
		t.Errorf("another workspace was refused (%d); the quota is not per workspace", rec.Code)
	}
}

// upperLocal uppercases the local part of an address.
func upperLocal(addr string) string {
	for i, r := range addr {
		if r == '@' {
			return upper(addr[:i]) + addr[i:]
		}
	}
	return upper(addr)
}

func upper(s string) string {
	out := []rune(s)
	for i, r := range out {
		if r >= 'a' && r <= 'z' {
			out[i] = r - 32
		}
	}
	return string(out)
}
