package imapservice

import (
	"context"
	"slices"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/backend/memory"
	"github.com/emersion/go-imap/server"
)

// Poll sends changes to this selected connection, avoiding broadcasts with
// sequence numbers from another client's view of the mailbox.
func (m *Mailbox) Poll() error {
	ctx, c := context.WithTimeout(context.Background(), 10*time.Second)
	defer c()
	rows, err := m.currentRecords(ctx)
	if err != nil {
		return err
	}
	if m.conn == nil {
		m.snapshot = rows
		return nil
	}
	current := map[uint32]memory.Message{}
	old := map[uint32]memory.Message{}
	for _, r := range rows {
		current[r.Uid] = r
	}
	removed := uint32(0)
	for i, r := range m.snapshot {
		old[r.Uid] = r
		if _, ok := current[r.Uid]; !ok {
			if err = m.conn.WriteResp(imap.NewUntaggedResp([]interface{}{uint32(i+1) - removed, imap.RawString("EXPUNGE")})); err != nil {
				return err
			}
			removed++
		}
	}
	if len(rows) != len(m.snapshot) || removed > 0 {
		if err = m.conn.WriteResp(imap.NewUntaggedResp([]interface{}{uint32(len(rows)), imap.RawString("EXISTS")})); err != nil {
			return err
		}
	}
	for i, r := range rows {
		prev, ok := old[r.Uid]
		if ok && slices.Equal(prev.Flags, r.Flags) {
			continue
		}
		msg := imap.NewMessage(uint32(i+1), []imap.FetchItem{imap.FetchUid, imap.FetchFlags})
		msg.Uid = r.Uid
		msg.Flags = r.Flags
		if err = m.conn.WriteResp(imap.NewUntaggedResp([]interface{}{msg.SeqNum, imap.RawString("FETCH"), msg.Format()})); err != nil {
			return err
		}
	}
	m.snapshot = rows
	return nil
}

type idleHandler struct{ server.Idle }

func (h *idleHandler) Handle(conn server.Conn) error {
	m, ok := conn.Context().Mailbox.(*Mailbox)
	if !ok {
		return h.Idle.Handle(conn)
	}
	if err := m.Poll(); err != nil {
		return err
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if err := m.Poll(); err != nil {
					conn.WriteResp(&imap.StatusResp{Type: imap.StatusRespBye, Info: "Mailbox access ended"})
					conn.Close()
					return
				}
			}
		}
	}()
	err := h.Idle.Handle(conn)
	close(stop)
	<-done
	return err
}
