// Command lmtpd receives mail from the local MTA.
//
// Postfix owns port 25 and everything that goes with facing the internet —
// TLS, queueing, spam checks. Once a message has passed all of that it is
// handed here over LMTP on loopback, and this process only has to decide
// whether we have a mailbox for it and store it.
//
// It is a third process rather than part of the API for the same reason the
// worker is: a burst of inbound mail must not make HTTP requests queue behind
// message parsing.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rnm/heromail/backend/internal/inbound"
)

func main() {
	ctx := context.Background()

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL is not set")
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer pool.Close()

	// Loopback by default, and it should stay that way: this speaks LMTP with
	// no authentication, so anything that can reach it can deliver mail to any
	// mailbox. Inside Compose the listener has to bind the container's own
	// address for Postfix on the host to reach it, which is what LMTP_ADDR is
	// for — never a public interface.
	addr := os.Getenv("LMTP_ADDR")
	if addr == "" {
		addr = "127.0.0.1:2525"
	}

	srv := inbound.NewServer(inbound.NewStore(pool), addr)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		log.Print("shutting down, finishing in-flight deliveries")
		srv.Close()
	}()

	log.Printf("lmtpd listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("lmtpd: %v", err)
	}
}
