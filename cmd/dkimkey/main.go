// Command dkimkey writes a domain's active DKIM private key to a file, so a
// host that cannot reach Postgres can still sign as that domain.
//
//	go run ./cmd/dkimkey -domain heromail.kz -out /tmp/key.der
//
// The output is the raw PKCS#8 DER, decrypted. It is key material: write it
// somewhere private, use it, delete it.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rnm/heromail/backend/internal/maildomain"
	"github.com/rnm/heromail/backend/internal/secrets"
)

func main() {
	domain := flag.String("domain", "", "domain name (required)")
	out := flag.String("out", "", "file to write the DER key to (required)")
	flag.Parse()

	if *domain == "" || *out == "" {
		log.Fatal("-domain and -out are required")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer pool.Close()

	sealer, err := secrets.NewFromEnv()
	if err != nil {
		log.Fatalf("secrets: %v", err)
	}

	var domainID string
	if err := pool.QueryRow(ctx,
		`SELECT id FROM domains WHERE domain = $1`, *domain).Scan(&domainID); err != nil {
		log.Fatalf("look up %s: %v", *domain, err)
	}

	svc := maildomain.NewService(maildomain.NewStore(pool), nil, sealer, maildomain.Config{})
	selector, der, err := svc.SigningKey(ctx, domainID)
	if err != nil {
		log.Fatalf("signing key: %v", err)
	}

	// 0600: this is a private key, not a config file.
	if err := os.WriteFile(*out, der, 0o600); err != nil {
		log.Fatalf("write %s: %v", *out, err)
	}
	fmt.Printf("selector=%s bytes=%d -> %s\n", selector, len(der), *out)
}
