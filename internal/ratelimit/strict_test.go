package ratelimit

import (
	"github.com/google/uuid"
	"os"
	"testing"
	"time"
)

func TestSMTPStrictLimiterFailsClosed(t *testing.T) {
	l := New("127.0.0.1:1")
	defer l.Close()
	if l.AllowStrict(t.Context(), Rule{Name: "unavailable", Limit: 10, Window: time.Minute}, "fixture").Allowed {
		t.Fatal("SMTP accepted when quota storage unavailable")
	}
}

func TestSMTPQuotaSharesAPICounter(t *testing.T) {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		t.Skip("Redis required")
	}
	l := New(addr)
	defer l.Close()
	rule := Rule{Name: "send:minute", Limit: 1, Window: time.Minute}
	key := uuid.NewString()
	if !l.Allow(t.Context(), rule, key).Allowed {
		t.Fatal("first API send refused")
	}
	if l.AllowStrict(t.Context(), rule, key).Allowed {
		t.Fatal("SMTP bypassed API workspace quota")
	}
}
