// Command calendar-backfill copies external invitations answered before
// accepted meetings were mirrored into calendars. It places each one in the
// calendar of the receiving mailbox's owner; later answers keep it current.
//
//	calendar-backfill [-dry-run]
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rnm/heromail/backend/internal/calendar"
	"github.com/rnm/heromail/backend/internal/inbound"
)

func main() {
	dryRun := flag.Bool("dry-run", false, "list what would be copied")
	flag.Parse()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer pool.Close()
	rows, err := pool.Query(ctx, `SELECT r.message_id::text,r.attendee,r.response,m.mailbox_id::text,d.workspace_id::text,b.owner_user_id::text
		FROM calendar_external_replies r JOIN messages m ON m.id=r.message_id JOIN mailboxes b ON b.id=m.mailbox_id JOIN domains d ON d.id=b.domain_id
		WHERE r.email_id IS NOT NULL AND r.response<>'declined' AND b.owner_user_id IS NOT NULL ORDER BY r.updated_at`)
	if err != nil {
		log.Fatal(err)
	}
	type item struct{ msg, attendee, response, mailbox, ws, user string }
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.msg, &it.attendee, &it.response, &it.mailbox, &it.ws, &it.user); err != nil {
			log.Fatal(err)
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
	mail, store := inbound.NewStore(pool), calendar.NewStore(pool)
	for _, it := range items {
		p, err := mail.Presentation(ctx, it.mailbox, it.msg)
		if err != nil {
			log.Printf("%s: %v", it.msg, err)
			continue
		}
		invite, err := calendar.ParseExternalInvite(p.CalendarICS)
		if err != nil {
			log.Printf("%s: %v", it.msg, err)
			continue
		}
		in, start, _, err := invite.Times(time.UTC)
		log.Printf("%s %s %q %s %s err=%v", it.msg, it.response, invite.Title, start.Format("2006-01-02 15:04Z"), in.Timezone, err)
		if *dryRun {
			continue
		}
		if err := store.SaveExternal(ctx, it.ws, it.user, it.msg, it.attendee, it.response, invite); err != nil {
			log.Printf("%s: save: %v", it.msg, err)
		}
	}
}
