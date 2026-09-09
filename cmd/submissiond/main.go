package main

import (
	"context"
	"crypto/tls"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rnm/heromail/backend/internal/maildomain"
	"github.com/rnm/heromail/backend/internal/ratelimit"
	"github.com/rnm/heromail/backend/internal/secrets"
	"github.com/rnm/heromail/backend/internal/submission"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
func number(key string, fallback int) int {
	v, e := strconv.Atoi(os.Getenv(key))
	if e != nil || v <= 0 {
		return fallback
	}
	return v
}
func main() {
	cert, key := os.Getenv("SUBMISSION_TLS_CERT"), os.Getenv("SUBMISSION_TLS_KEY")
	if _, err := tls.LoadX509KeyPair(cert, key); err != nil {
		log.Fatal(err)
	}
	if os.Getenv("REDIS_ADDR") == "" || os.Getenv("SUBMISSION_RELAY") == "" {
		log.Fatal("REDIS_ADDR and trusted SUBMISSION_RELAY required")
	}
	pool, err := pgxpool.New(context.Background(), os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()
	sealer, err := secrets.NewFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	limiter := ratelimit.New(os.Getenv("REDIS_ADDR"))
	defer limiter.Close()
	b := &submission.Backend{Pool: pool, Limiter: limiter, Sign: submission.DKIM(maildomain.NewService(maildomain.NewStore(pool), nil, sealer, maildomain.Config{})), Relay: submission.SMTPRelay(os.Getenv("SUBMISSION_RELAY"), env("SMTP_HELO", "hs.rnm.dev")), Minute: number("SEND_LIMIT_PER_MINUTE", 60), Day: number("SEND_LIMIT_PER_DAY", 5000)}
	starttls := submission.Server(b, env("SUBMISSION_ADDR", "127.0.0.1:1587"), cert, key)
	implicit := submission.Server(b, env("SUBMISSIONS_ADDR", "127.0.0.1:1465"), cert, key)
	failures := make(chan error, 2)
	go func() { failures <- starttls.ListenAndServe() }()
	go func() { failures <- implicit.ListenAndServeTLS() }()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	log.Printf("SMTP submission listening on %s (STARTTLS) and %s (TLS)", starttls.Addr, implicit.Addr)
	select {
	case err := <-failures:
		log.Printf("submission listener stopped: %v", err)
		starttls.Close()
		implicit.Close()
		os.Exit(1)
	case <-stop:
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	starttls.Shutdown(ctx)
	implicit.Shutdown(ctx)
}
