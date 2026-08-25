// Command issue-api-key mints an API key for a workspace.
//
// It runs on the box, against DATABASE_URL, and prints the key exactly once.
// Issuing over HTTP would need its own credential to protect the endpoint —
// a second auth system built to bootstrap the first.
//
//	docker compose exec backend go run ./cmd/issue-api-key -workspace acme -name "CI"
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rnm/heromail/backend/internal/apikey"
)

func main() {
	slug := flag.String("workspace", "", "workspace slug to issue the key for (required)")
	name := flag.String("name", "", "human label for the key, e.g. \"CI\" (required)")
	flag.Parse()

	if err := run(*slug, *name); err != nil {
		fmt.Fprintf(os.Stderr, "issue-api-key: %v\n", err)
		os.Exit(1)
	}
}

func run(slug, name string) error {
	if slug == "" || name == "" {
		flag.Usage()
		return errors.New("both -workspace and -name are required")
	}

	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return errors.New("DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer pool.Close()

	var workspaceID string
	err = pool.QueryRow(ctx, `SELECT id FROM workspaces WHERE slug = $1`, slug).Scan(&workspaceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("no workspace with slug %q", slug)
	}
	if err != nil {
		return fmt.Errorf("look up workspace: %w", err)
	}

	key, prefix, hash, err := apikey.New()
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	var keyID string
	err = pool.QueryRow(ctx, `
		INSERT INTO api_keys (workspace_id, name, key_hash, key_prefix)
		VALUES ($1, $2, $3, $4)
		RETURNING id`,
		workspaceID, name, hash, prefix,
	).Scan(&keyID)
	if err != nil {
		return fmt.Errorf("insert key: %w", err)
	}

	fmt.Printf("Workspace : %s (%s)\n", slug, workspaceID)
	fmt.Printf("Key ID    : %s\n", keyID)
	fmt.Printf("Name      : %s\n", name)
	fmt.Printf("Prefix    : %s\n", prefix)
	fmt.Printf("\nAPI key (shown once, not recoverable):\n\n    %s\n\n", key)
	return nil
}
