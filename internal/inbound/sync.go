package inbound

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrCursorExpired means a sync cursor can no longer be served: it is
// malformed, belongs to another mailbox, is ahead of the mailbox (a restored
// database), or predates pruned tombstones. The client does a full resync.
var ErrCursorExpired = errors.New("cursor expired")

// TombstoneRetention is how long deletions stay replayable. A device offline
// for longer gets 410 and resyncs from scratch.
const TombstoneRetention = 30 * 24 * time.Hour

// ChangedMessage is a message's current state at the time of the change.
type ChangedMessage struct {
	Message
	LabelIDs []string
	Seq      int64
}

// ChangeSet is one page of a mailbox's changes since a cursor.
type ChangeSet struct {
	Messages []ChangedMessage
	// Deleted lists message ids removed since the cursor.
	Deleted             []string
	NextCursor          string
	HasMore             bool
	OrganizationChanged bool
	// Unread is the current unread count per folder, so the badges need no
	// second request.
	Unread map[string]int
}

const cursorVersion = "1"

// EncodeCursor is opaque to clients; it binds the sequence to the mailbox so a
// cursor from one mailbox is never applied to another.
func EncodeCursor(mailboxID string, seq int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(cursorVersion + ":" + mailboxID + ":" + strconv.FormatInt(seq, 10)))
}

func decodeCursor(mailboxID, cursor string) (int64, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, ErrCursorExpired
	}
	parts := strings.Split(string(raw), ":")
	if len(parts) != 3 || parts[0] != cursorVersion || !strings.EqualFold(parts[1], mailboxID) {
		return 0, ErrCursorExpired
	}
	seq, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || seq < 0 {
		return 0, ErrCursorExpired
	}
	return seq, nil
}

// Changes returns up to limit changes after cursor, oldest first. An empty
// cursor answers only with the current position: the client takes it before
// its full listing and syncs from there, so nothing falls between the two.
func (s *Store) Changes(ctx context.Context, mailboxID, cursor string, limit int) (*ChangeSet, error) {
	var head, orgSeq, minSeq int64
	err := s.pool.QueryRow(ctx,
		`SELECT seq, organization_seq, min_seq FROM mailbox_sync WHERE mailbox_id = $1`, mailboxID).
		Scan(&head, &orgSeq, &minSeq)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	out := &ChangeSet{Messages: []ChangedMessage{}, Deleted: []string{}}
	if out.Unread, err = s.unreadByFolder(ctx, mailboxID); err != nil {
		return nil, err
	}
	if cursor == "" {
		out.NextCursor = EncodeCursor(mailboxID, head)
		out.OrganizationChanged = true
		return out, nil
	}
	since, err := decodeCursor(mailboxID, cursor)
	if err != nil {
		return nil, err
	}
	if since > head || since < minSeq {
		return nil, ErrCursorExpired
	}
	out.OrganizationChanged = orgSeq > since

	// Bounded by head, which was read first: everything numbered up to head is
	// committed (numbers are taken at commit under the counter's row lock),
	// and anything newer is left for the next call rather than half-read.
	rows, err := s.pool.Query(ctx, `
		SELECT`+messageColumns+`, msg.change_seq,
		       coalesce((SELECT array_agg(ml.label_id::text ORDER BY ml.label_id)
		                 FROM message_labels ml WHERE ml.message_id = msg.id), '{}')
		FROM messages msg
		WHERE msg.mailbox_id = $1 AND msg.change_seq > $2 AND msg.change_seq <= $3
		ORDER BY msg.change_seq LIMIT $4`, mailboxID, since, head, limit+1)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var c ChangedMessage
		m, err := scanMessageExtra(rows, &c.Seq, &c.LabelIDs)
		if err != nil {
			rows.Close()
			return nil, err
		}
		c.Message = *m
		out.Messages = append(out.Messages, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	type tomb struct {
		id  string
		seq int64
	}
	var tombs []tomb
	rows, err = s.pool.Query(ctx, `
		SELECT message_id::text, change_seq FROM message_tombstones
		WHERE mailbox_id = $1 AND change_seq > $2 AND change_seq <= $3
		ORDER BY change_seq LIMIT $4`, mailboxID, since, head, limit+1)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var t tomb
		if err := rows.Scan(&t.id, &t.seq); err != nil {
			rows.Close()
			return nil, err
		}
		tombs = append(tombs, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Merge the two streams by seq and cut at limit. The cut point is the
	// next cursor; anything past it is served by the next page.
	seqs := make([]int64, 0, len(out.Messages)+len(tombs))
	for _, m := range out.Messages {
		seqs = append(seqs, m.Seq)
	}
	for _, t := range tombs {
		seqs = append(seqs, t.seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	next := head
	if len(seqs) > limit {
		out.HasMore = true
		next = seqs[limit-1]
	}
	kept := out.Messages[:0]
	for _, m := range out.Messages {
		if m.Seq <= next {
			kept = append(kept, m)
		}
	}
	out.Messages = kept
	for _, t := range tombs {
		if t.seq <= next {
			out.Deleted = append(out.Deleted, t.id)
		}
	}
	out.NextCursor = EncodeCursor(mailboxID, next)
	return out, nil
}

func (s *Store) unreadByFolder(ctx context.Context, mailboxID string) (map[string]int, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT folder, count(*) FROM messages WHERE mailbox_id = $1 AND read_at IS NULL GROUP BY folder`, mailboxID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var folder string
		var n int
		if err := rows.Scan(&folder, &n); err != nil {
			return nil, err
		}
		out[folder] = n
	}
	return out, rows.Err()
}

// PruneTombstones drops deletions older than retention and raises each
// affected mailbox's min_seq past them, so a cursor that would have needed
// one answers 410 instead of silently missing the deletion.
func (s *Store) PruneTombstones(ctx context.Context, retention time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		WITH gone AS (
		    DELETE FROM message_tombstones
		    WHERE deleted_at < now() - $1::interval AND change_seq > 0
		    RETURNING mailbox_id, change_seq
		), top AS (
		    SELECT mailbox_id, max(change_seq) AS seq FROM gone GROUP BY mailbox_id
		)
		UPDATE mailbox_sync m SET min_seq = greatest(m.min_seq, top.seq)
		FROM top WHERE m.mailbox_id = top.mailbox_id`, retention.String())
	if err != nil {
		return 0, fmt.Errorf("prune tombstones: %w", err)
	}
	return tag.RowsAffected(), nil
}

// RunTombstonePruner prunes hourly until ctx ends. Run by cmd/worker.
func (s *Store) RunTombstonePruner(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if n, err := s.PruneTombstones(ctx, TombstoneRetention); err != nil {
			log.Printf("sync: %v", err)
		} else if n > 0 {
			log.Printf("sync: pruned tombstones in %d mailboxes", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
