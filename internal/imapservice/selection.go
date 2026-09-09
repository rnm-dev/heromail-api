package imapservice

import "github.com/emersion/go-imap/server"

// Track EXAMINE on the per-connection mailbox object. The base v1 backend
// interface doesn't otherwise pass read-only mode to FETCH or CLOSE.
type selectionExtension struct{ ready bool }

func (*selectionExtension) Capabilities(server.Conn) []string { return nil }
func (ext *selectionExtension) Command(name string) server.HandlerFactory {
	switch name {
	case "IDLE":
		if !ext.ready {
			return nil
		}
		return func() server.Handler { return &idleHandler{} }
	case "SELECT", "EXAMINE":
		return func() server.Handler { return &selectionHandler{readOnly: name == "EXAMINE"} }
	}
	return nil
}

type selectionHandler struct {
	server.Select
	readOnly bool
}

func (h *selectionHandler) Handle(conn server.Conn) error {
	h.Select.ReadOnly = h.readOnly
	err := h.Select.Handle(conn)
	if m, ok := conn.Context().Mailbox.(*Mailbox); ok {
		m.readOnly = conn.Context().MailboxReadOnly
		m.conn = conn
	}
	return err
}
