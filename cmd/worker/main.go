// Command worker consumes the send queue.
//
// It is a separate process from the API on purpose: delivery is slow and
// bursty, and a backlog of retries should never make HTTP requests queue behind
// it. Scale the two independently.
package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rnm/heromail/backend/internal/email"
	"github.com/rnm/heromail/backend/internal/maildomain"
	smtpprovider "github.com/rnm/heromail/backend/internal/provider/smtp"
	"github.com/rnm/heromail/backend/internal/secrets"
	"github.com/rnm/heromail/backend/internal/storage"
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

	sender, err := smtpprovider.NewFromEnv()
	if err != nil {
		log.Fatalf("smtp provider: %v", err)
	}

	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "redis:6379"
	}

	concurrency := 10
	if raw := os.Getenv("WORKER_CONCURRENCY"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			concurrency = n
		}
	}

	srv := asynq.NewServer(
		asynq.RedisClientOpt{Addr: redisAddr},
		asynq.Config{
			Concurrency: concurrency,
			// Errors are already recorded on the email row by the handler;
			// this is just so a failing worker is visible in the logs.
			ErrorHandler: asynq.ErrorHandlerFunc(func(_ context.Context, task *asynq.Task, err error) {
				log.Printf("task %s failed: %v", task.Type(), err)
			}),
		},
	)

	// Same nil-means-unconfigured contract as the API: a message with no
	// attachments delivers fine either way; one that has them fails with a
	// clear "storage is not configured" error until S3_BUCKET is set.
	var blobs storage.Store
	if s3, err := storage.NewFromEnv(ctx); err != nil {
		if !errors.Is(err, storage.ErrNotConfigured) {
			log.Fatalf("storage: %v", err)
		}
		log.Print("storage: S3_BUCKET is not set, messages with attachments will retry until it is")
	} else {
		blobs = s3
	}

	// Same key the API decrypts DKIM private keys with. Required, not
	// optional: a worker that could silently sign nothing because it could
	// not decrypt keys would be a much worse failure than refusing to start.
	sealer, err := secrets.NewFromEnv()
	if err != nil {
		log.Fatalf("secrets: %v", err)
	}
	// nil resolver: only SigningKeyForDomain is used here, which never
	// touches DNS. Config is irrelevant for the same reason — it only
	// affects the SPF/DMARC record text a settings page renders.
	domains := maildomain.NewService(maildomain.NewStore(pool), nil, sealer, maildomain.Config{})

	worker := email.NewWorker(email.NewStore(pool), sender, blobs, domains)

	mux := asynq.NewServeMux()
	mux.HandleFunc(email.TypeSend, worker.HandleSend)

	// Shut down on a signal so in-flight deliveries finish instead of being
	// killed mid-conversation with a mail server.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		log.Print("shutting down, waiting for in-flight tasks")
		srv.Shutdown()
	}()

	log.Printf("worker started, concurrency %d, redis %s", concurrency, redisAddr)
	if err := srv.Run(mux); err != nil {
		log.Fatalf("worker: %v", err)
	}
}
