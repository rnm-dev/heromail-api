package main

import (
	"context"
	"crypto/tls"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rnm/heromail/backend/internal/imapservice"
	"github.com/rnm/heromail/backend/internal/ratelimit"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	addr := os.Getenv("IMAP_ADDR")
	if addr == "" {
		addr = "127.0.0.1:1993"
	}
	cert, key := os.Getenv("IMAP_TLS_CERT"), os.Getenv("IMAP_TLS_KEY")
	if _, err := tls.LoadX509KeyPair(cert, key); err != nil {
		log.Fatal("IMAP TLS certificate/key required: ", err)
	}
	pool, err := pgxpool.New(context.Background(), os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()
	var limiter *ratelimit.Limiter
	if host := os.Getenv("REDIS_ADDR"); host != "" {
		limiter = ratelimit.New(host)
		defer limiter.Close()
	}
	srv := imapservice.Server(imapservice.New(pool, limiter), addr, cert, key)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-stop; srv.Close() }()
	log.Print("IMAPS listening on ", addr)
	if err := srv.ListenAndServeTLS(); err != nil {
		log.Print(err)
	}
}
