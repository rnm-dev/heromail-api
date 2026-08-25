// Package ratelimit counts actions per key in Redis.
//
// It exists for two different jobs that happen to need the same mechanism:
// slowing down credential guessing and mailbox flooding on the auth endpoints,
// and capping how much a single workspace can send.
package ratelimit

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
)

// Rule is one limit: at most Limit actions per Window.
type Rule struct {
	Name   string
	Limit  int
	Window time.Duration
}

// Result says whether the action may proceed.
type Result struct {
	Allowed bool
	// RetryAfter is how long until the window resets. Zero when allowed.
	RetryAfter time.Duration
	// Remaining is how many actions are left in the current window.
	Remaining int
}

// Limiter is a fixed-window counter.
//
// Fixed windows are approximate at the boundary: a caller can spend one full
// window's budget at the end of one window and another at the start of the
// next, so the true worst case is 2×Limit over a short span. For "slow down
// password guessing" and "cap a tenant's volume" that is fine, and it costs one
// round trip instead of the bookkeeping a sliding window needs. If a limit ever
// has to be exact, this is the place to swap in a sliding log.
type Limiter struct {
	client *redis.Client
}

func New(redisAddr string) *Limiter {
	return &Limiter{client: redis.NewClient(&redis.Options{Addr: redisAddr})}
}

func (l *Limiter) Close() error { return l.client.Close() }

// Allow counts one action against the rule and reports whether it may proceed.
//
// On a Redis failure it **allows** the action and logs. Failing closed would
// mean a Redis blip locks every user out of signing in, which is a worse
// outcome than briefly not enforcing a limit.
func (l *Limiter) Allow(ctx context.Context, rule Rule, key string) Result {
	redisKey := fmt.Sprintf("ratelimit:%s:%s:%d", rule.Name, key, time.Now().UnixNano()/int64(rule.Window))

	pipe := l.client.TxPipeline()
	incr := pipe.Incr(ctx, redisKey)
	pipe.Expire(ctx, redisKey, rule.Window)
	if _, err := pipe.Exec(ctx); err != nil {
		log.Printf("ratelimit: %s for %q: %v (allowing)", rule.Name, key, err)
		return Result{Allowed: true, Remaining: rule.Limit}
	}

	count := int(incr.Val())
	if count > rule.Limit {
		ttl, err := l.client.TTL(ctx, redisKey).Result()
		if err != nil || ttl < 0 {
			ttl = rule.Window
		}
		return Result{Allowed: false, RetryAfter: ttl}
	}
	return Result{Allowed: true, Remaining: rule.Limit - count}
}

// AllowAll applies several rules to the same key and returns the first refusal.
// Every rule is counted even when an earlier one already refused, so a caller
// hammering a per-minute limit still burns their daily budget.
func (l *Limiter) AllowAll(ctx context.Context, key string, rules ...Rule) Result {
	worst := Result{Allowed: true}
	for _, rule := range rules {
		got := l.Allow(ctx, rule, key)
		if !got.Allowed && (worst.Allowed || got.RetryAfter > worst.RetryAfter) {
			worst = got
		}
	}
	return worst
}
