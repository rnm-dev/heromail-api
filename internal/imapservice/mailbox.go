package imapservice

import (
	"bytes"
	"context"
	"errors"
	"github.com/emersion/go-imap/server"
	"github.com/emersion/go-message"
	"github.com/jackc/pgx/v5"
	"slices"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/backend/backendutil"
	"github.com/emersion/go-imap/backend/memory"
)

type Mailbox struct {
	readOnly bool
	conn     server.Conn
	snapshot []memory.Message
	u        *User
	name     string
}

func (m *Mailbox) Name() string { return m.name }
func (m *Mailbox) Info() (*imap.MailboxInfo, error) {
	info := &imap.MailboxInfo{Name: m.name, Delimiter: ""}
	if m.name == "Junk" {
		info.Attributes = []string{`\Junk`}
	}
	return info, nil
}
func (m *Mailbox) Check() error {
	ctx, c := context.WithTimeout(context.Background(), 10*time.Second)
	defer c()
	return m.u.check(ctx)
}
func (m *Mailbox) currentRecords(ctx context.Context) ([]memory.Message, error) {
	if err := m.u.check(ctx); err != nil {
		return nil, err
	}
	return m.loadRecords(ctx, m.u.b.pool)
}

type recordQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func (m *Mailbox) loadRecords(ctx context.Context, q recordQuerier) ([]memory.Message, error) {
	rows, err := q.Query(ctx, `SELECT imap_uid,received_at,size_bytes,imap_flags,read_at IS NOT NULL FROM messages WHERE mailbox_id=$1 AND folder=$2 ORDER BY imap_uid`, m.u.box, m.name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []memory.Message{}
	for rows.Next() {
		var item memory.Message
		var seen bool
		if err := rows.Scan(&item.Uid, &item.Date, &item.Size, &item.Flags, &seen); err != nil {
			return nil, err
		}
		if seen {
			item.Flags = append(item.Flags, imap.SeenFlag)
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// Keep sequence numbers stable until an explicit NOOP/IDLE synchronization.
func (m *Mailbox) records(ctx context.Context) ([]memory.Message, error) {
	rows, err := m.currentRecords(ctx)
	if err != nil || m.snapshot == nil {
		return rows, err
	}
	current := map[uint32]memory.Message{}
	for _, r := range rows {
		current[r.Uid] = r
	}
	out := slices.Clone(m.snapshot)
	for i, r := range out {
		if fresh, ok := current[r.Uid]; ok {
			out[i] = fresh
		}
	}
	return out, nil
}
func (m *Mailbox) Status(items []imap.StatusItem) (*imap.MailboxStatus, error) {
	ctx, c := context.WithTimeout(context.Background(), 10*time.Second)
	defer c()
	if err := m.u.check(ctx); err != nil {
		return nil, err
	}
	// The same lock as delivery prevents advertising UIDNEXT beyond an
	// allocated but not yet committed message in this mailbox.
	tx, err := m.u.b.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, m.u.box); err != nil {
		return nil, err
	}
	records, err := m.loadRecords(ctx, tx)
	if err != nil {
		return nil, err
	}
	status := imap.NewMailboxStatus(m.name, items)
	status.Flags = []string{imap.SeenFlag, imap.AnsweredFlag, imap.FlaggedFlag, imap.DeletedFlag, imap.DraftFlag}
	status.PermanentFlags = append(slices.Clone(status.Flags), `\*`)
	status.Messages = uint32(len(records))
	for i, item := range records {
		if !slices.Contains(item.Flags, imap.SeenFlag) {
			status.Unseen++
			if status.UnseenSeqNum == 0 {
				status.UnseenSeqNum = uint32(i + 1)
			}
		}
	}
	err = tx.QueryRow(ctx, `SELECT uidvalidity,(SELECT last_value+1 FROM imap_uid_seq) FROM imap_folders WHERE mailbox_id=$1 AND name=$2`, m.u.box, m.name).Scan(&status.UidValidity, &status.UidNext)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	if m.conn == nil {
		m.snapshot = records
	}
	return status, nil
}
func (m *Mailbox) SetSubscribed(subscribed bool) error {
	ctx, c := context.WithTimeout(context.Background(), 10*time.Second)
	defer c()
	if err := m.u.check(ctx); err != nil {
		return err
	}
	_, err := m.u.b.pool.Exec(ctx, `UPDATE imap_folders SET subscribed=$3 WHERE mailbox_id=$1 AND name=$2`, m.u.box, m.name, subscribed)
	return err
}
func inSet(set *imap.SeqSet, id, max uint32) bool {
	for _, r := range set.Set {
		a, b := r.Start, r.Stop
		if a == 0 {
			a = max
		}
		if b == 0 {
			b = max
		}
		if a > b {
			a, b = b, a
		}
		if id >= a && id <= b {
			return true
		}
	}
	return false
}
func selected(set *imap.SeqSet, uid bool, i int, rows []memory.Message) bool {
	max := uint32(len(rows))
	id := uint32(i + 1)
	if uid {
		id = rows[i].Uid
		if len(rows) > 0 {
			max = rows[len(rows)-1].Uid
		}
	}
	return inSet(set, id, max)
}
func (m *Mailbox) raw(ctx context.Context, item *memory.Message) error {
	return m.u.b.pool.QueryRow(ctx, `SELECT raw FROM messages WHERE mailbox_id=$1 AND folder=$2 AND imap_uid=$3`, m.u.box, m.name, item.Uid).Scan(&item.Body)
}
func (m *Mailbox) ListMessages(uid bool, set *imap.SeqSet, items []imap.FetchItem, ch chan<- *imap.Message) error {
	defer close(ch)
	ctx, c := context.WithTimeout(context.Background(), 2*time.Minute)
	defer c()
	rows, err := m.records(ctx)
	if err != nil {
		return err
	}
	needsRaw, markSeen := false, false
	for _, item := range items {
		switch item {
		case imap.FetchUid, imap.FetchFlags, imap.FetchInternalDate, imap.FetchRFC822Size:
		default:
			needsRaw = true
		}
		if section, e := imap.ParseBodySectionName(item); e == nil && !section.Peek {
			markSeen = true
		}
	}
	for i, record := range rows {
		if !selected(set, uid, i, rows) {
			continue
		}
		if needsRaw {
			if err := m.raw(ctx, &record); err != nil {
				return err
			}
		}
		if markSeen && !m.readOnly && !slices.Contains(record.Flags, imap.SeenFlag) {
			record.Flags = append(record.Flags, imap.SeenFlag)
			if err := m.flags(ctx, record.Uid, imap.AddFlags, []string{imap.SeenFlag}); err != nil {
				return err
			}
		}
		// Whole-message fetches preserve even malformed source bytes verbatim.
		normal := []imap.FetchItem{}
		whole := []*imap.BodySectionName{}
		for _, item := range items {
			section, e := imap.ParseBodySectionName(item)
			if e == nil && len(section.Path) == 0 && section.Specifier == imap.EntireSpecifier {
				whole = append(whole, section)
			} else {
				normal = append(normal, item)
			}
		}
		fetched, err := record.Fetch(uint32(i+1), normal)
		if err == nil {
			for _, section := range whole {
				fetched.Body[section] = bytes.NewReader(section.ExtractPartial(record.Body))
				fetched.Items[section.FetchItem()] = nil
			}
		}
		if err != nil {
			return err
		}
		if uid {
			fetched.Uid = record.Uid
		}
		select {
		case ch <- fetched:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}
func (m *Mailbox) SearchMessages(uid bool, criteria *imap.SearchCriteria) ([]uint32, error) {
	ctx, c := context.WithTimeout(context.Background(), 2*time.Minute)
	defer c()
	rows, err := m.records(ctx)
	if err != nil {
		return nil, err
	}
	out := []uint32{}
	for i, record := range rows {
		if err := m.raw(ctx, &record); err != nil {
			return nil, err
		}
		entity, parseErr := message.Read(bytes.NewReader(record.Body))
		if entity == nil {
			return nil, parseErr
		}
		match, err := backendutil.Match(entity, uint32(i+1), record.Uid, record.Date, record.Flags, criteria)
		if err != nil {
			return nil, err
		}
		if match {
			id := uint32(i + 1)
			if uid {
				id = record.Uid
			}
			out = append(out, id)
		}
	}
	return out, nil
}
func (m *Mailbox) flags(ctx context.Context, uid uint32, op imap.FlagsOp, flags []string) error {
	tx, err := m.u.b.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var current []string
	var seen bool
	if err := tx.QueryRow(ctx, `SELECT imap_flags,read_at IS NOT NULL FROM messages WHERE mailbox_id=$1 AND folder=$2 AND imap_uid=$3 FOR UPDATE`, m.u.box, m.name, uid).Scan(&current, &seen); err != nil {
		return err
	}
	if seen {
		current = append(current, imap.SeenFlag)
	}
	updated := backendutil.UpdateFlags(current, op, flags)
	var readAt any
	clean := []string{}
	for _, f := range updated {
		if f == imap.SeenFlag {
			readAt = time.Now()
		} else if f != imap.RecentFlag {
			clean = append(clean, f)
		}
	}
	_, err = tx.Exec(ctx, `UPDATE messages SET imap_flags=$4,read_at=$5 WHERE mailbox_id=$1 AND folder=$2 AND imap_uid=$3`, m.u.box, m.name, uid, clean, readAt)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (m *Mailbox) UpdateMessagesFlags(uid bool, set *imap.SeqSet, op imap.FlagsOp, flags []string) error {
	ctx, c := context.WithTimeout(context.Background(), 30*time.Second)
	defer c()
	rows, err := m.records(ctx)
	if err != nil {
		return err
	}
	for i, record := range rows {
		if selected(set, uid, i, rows) {
			if err := m.flags(ctx, record.Uid, op, flags); err != nil {
				return err
			}
		}
	}
	return nil
}
func (m *Mailbox) CreateMessage(flags []string, date time.Time, body imap.Literal) error {
	ctx, c := context.WithTimeout(context.Background(), 2*time.Minute)
	defer c()
	return m.u.append(ctx, m.name, flags, date, body)
}
func (m *Mailbox) CopyMessages(uid bool, set *imap.SeqSet, dest string) error {
	ctx, c := context.WithTimeout(context.Background(), 2*time.Minute)
	defer c()
	target, err := m.u.GetMailbox(dest)
	if err != nil {
		return err
	}
	rows, err := m.records(ctx)
	if err != nil {
		return err
	}
	for i, record := range rows {
		if selected(set, uid, i, rows) {
			if err := m.raw(ctx, &record); err != nil {
				return err
			}
			if err := m.u.append(ctx, target.Name(), record.Flags, record.Date, bytes.NewReader(record.Body)); err != nil {
				return err
			}
		}
	}
	return nil
}
func (m *Mailbox) Expunge() error {
	if m.readOnly {
		return nil
	}
	ctx, c := context.WithTimeout(context.Background(), 30*time.Second)
	defer c()
	if err := m.u.check(ctx); err != nil {
		return err
	}
	rows, err := m.records(ctx)
	if err != nil {
		return err
	}
	ids := []uint32{}
	kept := []memory.Message{}
	for _, r := range rows {
		if slices.Contains(r.Flags, imap.DeletedFlag) {
			ids = append(ids, r.Uid)
		} else {
			kept = append(kept, r)
		}
	}
	_, err = m.u.b.pool.Exec(ctx, `DELETE FROM messages WHERE mailbox_id=$1 AND folder=$2 AND imap_uid=ANY($3::bigint[])`, m.u.box, m.name, ids)
	if err == nil && m.snapshot != nil {
		m.snapshot = kept
	}
	return err
}

// MOVE assigns fresh UIDs at the destination and removes source rows atomically.
func (m *Mailbox) MoveMessages(uid bool, set *imap.SeqSet, dest string) error {
	if m.readOnly {
		return errors.New("mailbox is read-only")
	}
	dest = canonical(dest)
	if dest == m.name {
		return errors.New("source and destination are identical")
	}
	if _, err := m.u.GetMailbox(dest); err != nil {
		return err
	}
	ctx, c := context.WithTimeout(context.Background(), 30*time.Second)
	defer c()
	rows, err := m.records(ctx)
	if err != nil {
		return err
	}
	ids := []uint32{}
	for i, r := range rows {
		if selected(set, uid, i, rows) {
			ids = append(ids, r.Uid)
		}
	}
	tx, err := m.u.b.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, m.u.box); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO messages(mailbox_id,folder,envelope_from,envelope_to,message_id,from_addr,from_name,subject,sent_at,text_body,html_body,raw,size_bytes,read_at,received_at,imap_flags,smtp_delivery)
 SELECT mailbox_id,$3,envelope_from,envelope_to,message_id,from_addr,from_name,subject,sent_at,text_body,html_body,raw,size_bytes,read_at,received_at,imap_flags,false FROM messages WHERE mailbox_id=$1 AND folder=$2 AND imap_uid=ANY($4::bigint[]) ORDER BY imap_uid`, m.u.box, m.name, dest, ids); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM messages WHERE mailbox_id=$1 AND folder=$2 AND imap_uid=ANY($3::bigint[])`, m.u.box, m.name, ids); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	return m.Poll()
}
