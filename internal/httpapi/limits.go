package httpapi

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rnm/heromail/backend/internal/ratelimit"
)

// The limits. Two families with different jobs:
//
//   - auth limits slow down credential guessing and stop someone using our
//     mail as a weapon against a third party's inbox,
//   - the send quota caps what one workspace can push through shared sending
//     IPs, which is the multi-tenant hazard: one abusive tenant burns the
//     reputation everyone else depends on.
//
// The numbers are deliberately loose enough that a real person never meets
// them and tight enough that a script does.
var (
	// Per email address: a human mistyping their password a few times is fine.
	loginPerEmail = ratelimit.Rule{Name: "login:email", Limit: 10, Window: 15 * time.Minute}
	// Per source address, to catch spraying across many accounts.
	loginPerIP = ratelimit.Rule{Name: "login:ip", Limit: 50, Window: 15 * time.Minute}

	// Mail-sending endpoints are limited per address rather than per IP: the
	// harm is to the mailbox owner, and the attacker's IP is free to change.
	resetPerEmail  = ratelimit.Rule{Name: "reset:email", Limit: 3, Window: time.Hour}
	verifyPerEmail = ratelimit.Rule{Name: "verify:email", Limit: 3, Window: time.Hour}

	// Submitting codes, as opposed to requesting them. The hard cap is the
	// attempts column on the token row — this only stops someone cycling
	// "request a new code, spend its 7 guesses, repeat" at machine speed.
	// Deliberately looser than 7: it must not fire before the row counter,
	// whose lockout is the one that carries a useful message.
	verifyAttemptPerEmail = ratelimit.Rule{Name: "verify-attempt:email", Limit: 30, Window: time.Hour}

	registerPerIP = ratelimit.Rule{Name: "register:ip", Limit: 10, Window: time.Hour}
)

// sendQuota is the per-workspace send limit, in messages. Both windows apply:
// the minute cap absorbs a runaway loop, the day cap bounds the damage a
// determined abuser can do before anyone looks.
func sendQuota() []ratelimit.Rule {
	return []ratelimit.Rule{
		{Name: "send:minute", Limit: envInt("SEND_LIMIT_PER_MINUTE", 60), Window: time.Minute},
		{Name: "send:day", Limit: envInt("SEND_LIMIT_PER_DAY", 5000), Window: 24 * time.Hour},
	}
}

// uploadQuota is the per-workspace attachment upload limit. Looser than the
// send limit since one message can reference several uploads, but the same
// multi-tenant hazard applies: shared storage and bandwidth, not just IPs.
func uploadQuota() []ratelimit.Rule {
	return []ratelimit.Rule{
		{Name: "upload:minute", Limit: envInt("ATTACHMENT_UPLOAD_LIMIT_PER_MINUTE", 30), Window: time.Minute},
	}
}

func envInt(name string, fallback int) int {
	if raw := os.Getenv(name); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

// allow is a small wrapper so operations read as one line. A nil limiter (in
// tests that do not care) allows everything.
func (s *Server) allow(ctx context.Context, key string, rules ...ratelimit.Rule) ratelimit.Result {
	if s.limiter == nil {
		return ratelimit.Result{Allowed: true}
	}
	return s.limiter.AllowAll(ctx, key, rules...)
}

// retryAfterSeconds renders the header value, rounding up so a client that
// waits exactly that long is past the window rather than one tick short.
func retryAfterSeconds(d time.Duration) int {
	secs := int(d.Seconds())
	if float64(secs) < d.Seconds() {
		secs++
	}
	if secs < 1 {
		secs = 1
	}
	return secs
}

// normaliseKey lowercases and trims an address so "Bob@acme.com" and
// "bob@acme.com " share one counter — otherwise changing the case of a letter
// would hand an attacker a fresh budget.
func normaliseKey(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
