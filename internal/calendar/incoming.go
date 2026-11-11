package calendar

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var partstatResponse = map[string]string{"ACCEPTED": "accepted", "TENTATIVE": "tentative", "DECLINED": "declined"}

// ApplyIncoming lets delivered iTIP mail update calendars without a click:
// a REPLY sets an attendee's answer on the receiving organizer's event, and an
// external CANCEL or newer REQUEST updates a copy the recipient already accepted.
// The sender must be the attendee (REPLY) or the organizer (CANCEL/REQUEST), and
// an older SEQUENCE never overrides newer state. Unrelated mail is a no-op.
func ApplyIncoming(ctx context.Context, tx pgx.Tx, recipient, from string, ics []byte) error {
	invite, err := ParseITIP(ics)
	if err != nil {
		return nil
	}
	recipient, from = strings.ToLower(recipient), strings.ToLower(from)
	seq, _ := strconv.Atoi(invite.Sequence)
	switch invite.Method {
	case "REPLY":
		response, ok := partstatResponse[invite.Partstat[from]]
		if !ok || invite.Organizer != recipient {
			return nil
		}
		_, err = tx.Exec(ctx, `UPDATE calendar_attendees a SET response=$4,responded_at=now(),response_version=a.response_version+1
			FROM calendar_events e WHERE e.id=a.event_id AND e.uid=$1 AND e.organizer_email=$2 AND e.status='confirmed' AND e.sequence<=$5
			AND a.email=$3 AND a.response<>$4`, invite.UID, recipient, from, response, seq)
		return err
	case "CANCEL":
		if invite.Organizer != from {
			return nil
		}
		_, err = tx.Exec(ctx, `DELETE FROM calendar_external_events WHERE uid=$1 AND attendee=$2 AND organizer_email=$3 AND sequence<=$4`, invite.UID, recipient, from, seq)
		return err
	case "REQUEST":
		if invite.Organizer != from || invite.start == "" {
			return nil
		}
		rows, err := tx.Query(ctx, `SELECT x.id,c.timezone FROM calendar_external_events x JOIN calendars c ON c.id=x.calendar_id
			WHERE x.uid=$1 AND x.attendee=$2 AND x.organizer_email=$3 AND x.sequence<$4`, invite.UID, recipient, from, seq)
		if err != nil {
			return err
		}
		type copyRow struct{ id, zone string }
		var copies []copyRow
		for rows.Next() {
			var c copyRow
			if err = rows.Scan(&c.id, &c.zone); err != nil {
				rows.Close()
				return err
			}
			copies = append(copies, c)
		}
		rows.Close()
		for _, c := range copies {
			fallback, zerr := Zone(c.zone)
			if zerr != nil {
				fallback = time.UTC
			}
			in, start, end, terr := invite.Times(fallback)
			if terr != nil {
				return nil
			}
			var startAt, endAt, startDate, endDate any
			if in.AllDay {
				startDate, endDate = in.Start, in.End
			} else {
				startAt, endAt = start, end
			}
			if _, err = tx.Exec(ctx, `UPDATE calendar_external_events SET sequence=$2,title=$3,description=$4,location=$5,timezone=$6,all_day=$7,
				start_at=$8,end_at=$9,start_date=$10::date,end_date=$11::date,updated_at=now() WHERE id=$1`,
				c.id, seq, in.Title, in.Description, in.Location, in.Timezone, in.AllDay, startAt, endAt, startDate, endDate); err != nil {
				return err
			}
		}
	}
	return nil
}
