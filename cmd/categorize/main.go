// Command categorize sorts stored received mail into smart inbox categories.
// New deliveries are classified by lmtpd; this backfills older messages.
//
//	categorize [-mailbox UUID] [-all] [-dry-run]
//
// Without -all only never-classified rows change. User corrections are kept.
package main

import (
	"context"
	"flag"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rnm/heromail/backend/internal/inbound"
)

func main() {
	mailbox := flag.String("mailbox", "", "limit to one mailbox id")
	all := flag.Bool("all", false, "reclassify already classified messages too")
	dryRun := flag.Bool("dry-run", false, "report counts without writing")
	flag.Parse()

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

	counts, err := inbound.NewStore(pool).Reclassify(ctx, *mailbox, *all, *dryRun)
	if err != nil {
		log.Fatalf("categorize: %v", err)
	}
	log.Printf("people=%d notifications=%d newsletters=%d dry_run=%t",
		counts[inbound.CategoryPeople], counts[inbound.CategoryNotifications], counts[inbound.CategoryNewsletters], *dryRun)
}
