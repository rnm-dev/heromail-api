package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"

	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/auth"
	"github.com/rnm/heromail/backend/internal/email"
	"github.com/rnm/heromail/backend/internal/httpapi"
	"github.com/rnm/heromail/backend/internal/inbound"
	"github.com/rnm/heromail/backend/internal/maildomain"
	smtpprovider "github.com/rnm/heromail/backend/internal/provider/smtp"
	"github.com/rnm/heromail/backend/internal/ratelimit"
	"github.com/rnm/heromail/backend/internal/secrets"
	"github.com/rnm/heromail/backend/internal/storage"
	"github.com/rnm/heromail/backend/internal/workspace"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	ctx := context.Background()
	pool, err := connectDB(ctx)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer pool.Close()

	if err := migrate(ctx, pool); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	sender, err := smtpprovider.NewFromEnv()
	if err != nil {
		log.Fatalf("smtp provider: %v", err)
	}

	accounts := account.NewService(account.NewStore(pool), sender, account.Config{
		AppBaseURL: os.Getenv("APP_BASE_URL"),
		MailFrom:   os.Getenv("MAIL_FROM"),
	})
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "redis:6379"
	}
	enqueuer := email.NewEnqueuer(redisAddr)
	defer enqueuer.Close()

	limiter := ratelimit.New(redisAddr)
	defer limiter.Close()

	// Attachments live in S3-compatible object storage. blobs stays a nil
	// interface until S3_BUCKET is set — the API still starts and sends mail
	// without attachments, it just answers uploads with 503 until a bucket
	// exists. Declared as the interface, not *storage.S3Store: assigning a
	// nil *S3Store to an interface variable would make it non-nil (a typed
	// nil), and s.blobs == nil checks downstream would stop working.
	var blobs storage.Store
	if s3, err := storage.NewFromEnv(ctx); err != nil {
		if !errors.Is(err, storage.ErrNotConfigured) {
			log.Fatalf("storage: %v", err)
		}
		log.Print("storage: S3_BUCKET is not set, attachment uploads will answer 503")
	} else {
		blobs = s3
	}

	// The API only queues; delivery happens in cmd/worker.
	emails := email.NewService(email.NewStore(pool), enqueuer, blobs)
	workspaces := workspace.NewService(workspace.NewStore(pool))

	// DKIM private keys are encrypted before they reach the database, so the
	// key has to exist before any domain can be claimed. Failing loudly at
	// boot beats discovering it on the first customer signup.
	sealer, err := secrets.NewFromEnv()
	if err != nil {
		log.Fatalf("secrets: %v", err)
	}
	// nil resolver: the package falls back to the system resolver.
	domains := maildomain.NewService(maildomain.NewStore(pool), nil, sealer, maildomain.Config{
		SPFInclude:    os.Getenv("SPF_INCLUDE"),
		DMARCReportTo: os.Getenv("DMARC_REPORT_TO"),
	})

	// System mail signs with the MAIL_FROM domain's key, if that domain has been
	// claimed and verified here. Attached after the fact because the domain
	// service needs the sealer, which needs SECRET_KEY — and accounts has to
	// exist before any of that to keep the failure order readable.
	accounts.WithSigner(domains)

	// The routes themselves are generated from api/openapi.yaml; this is only
	// the wiring of services into that generated surface.
	handler := httpapi.Router(
		httpapi.NewServer(pool, accounts, emails, workspaces, domains, inbound.NewStore(pool), limiter),
		auth.New(pool),
		accounts,
	)

	log.Printf("listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}
