package inbound

import (
	"context"
	"slices"
	"time"
)

func (s *Store) AppendIMAP(ctx context.Context, box, folder string, raw []byte, flags []string, date time.Time) error {
	f := parse(raw)
	if date.IsZero() {
		date = time.Now()
	}
	var seen any
	if slices.Contains(flags, `\Seen`) {
		seen = time.Now()
	}
	clean := []string{}
	for _, flag := range flags {
		if flag != `\Seen` && flag != `\Recent` {
			clean = append(clean, flag)
		}
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO messages(mailbox_id,folder,envelope_from,envelope_to,message_id,from_addr,from_name,subject,sent_at,text_body,html_body,raw,size_bytes,read_at,received_at,imap_flags,smtp_delivery)
 VALUES($1,$2,$3,'',nullif($4,''),nullif($3,''),nullif($5,''),$6,$7,nullif($8,''),nullif($9,''),$10,$11,$12,$13,$14,false)`, box, folder, f.FromAddr, f.MessageID, f.FromName, f.Subject, f.SentAt, f.Text, f.HTML, raw, len(raw), seen, date, clean)
	return err
}
