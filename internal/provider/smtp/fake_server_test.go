package smtp

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
)

// fakeSMTP is a throwaway SMTP server that speaks just enough of RFC 5321 to
// accept one message and hand back what it received. It deliberately advertises
// neither STARTTLS nor AUTH, which keeps the test hermetic: no TLS material, no
// credentials, no network beyond loopback.
type fakeSMTP struct {
	listener net.Listener

	mu       sync.Mutex
	envelope []envelope
	helo     string
}

// lastHELO returns the name the client announced in its EHLO greeting.
func (s *fakeSMTP) lastHELO() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.helo
}

type envelope struct {
	from string
	to   []string
	data string
}

func startFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeSMTP{listener: ln}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go s.handle(conn)
		}
	}()

	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *fakeSMTP) addr() (host string, port int) {
	a := s.listener.Addr().(*net.TCPAddr)
	return "127.0.0.1", a.Port
}

func (s *fakeSMTP) received() []envelope {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]envelope(nil), s.envelope...)
}

func (s *fakeSMTP) handle(conn net.Conn) {
	defer conn.Close()

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	reply := func(format string, args ...any) {
		fmt.Fprintf(w, format+"\r\n", args...)
		w.Flush()
	}

	reply("220 fake ESMTP ready")

	var env envelope
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(cmd)

		switch {
		case strings.HasPrefix(upper, "EHLO"):
			// Recorded so a test can assert on the name we announce: receivers
			// check it against the sending IP's PTR, so it is part of the
			// contract, not just a formality.
			s.mu.Lock()
			s.helo = strings.TrimSpace(cmd[len("EHLO"):])
			s.mu.Unlock()
			// No STARTTLS, no AUTH: the client must fall back to plaintext.
			reply("250-fake greets you")
			reply("250 SIZE 35882577")
		case strings.HasPrefix(upper, "HELO"):
			reply("250 fake greets you")
		case strings.HasPrefix(upper, "MAIL FROM:"):
			env.from = addrArg(cmd, "MAIL FROM:")
			reply("250 2.1.0 Ok")
		case strings.HasPrefix(upper, "RCPT TO:"):
			env.to = append(env.to, addrArg(cmd, "RCPT TO:"))
			reply("250 2.1.5 Ok")
		case upper == "DATA":
			reply("354 End data with <CR><LF>.<CR><LF>")
			var b strings.Builder
			for {
				dl, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if dl == ".\r\n" || dl == ".\n" {
					break
				}
				// Undo dot-stuffing.
				b.WriteString(strings.TrimPrefix(dl, "."))
			}
			env.data = b.String()
			s.mu.Lock()
			s.envelope = append(s.envelope, env)
			s.mu.Unlock()
			env = envelope{}
			reply("250 2.0.0 Ok: queued as FAKE1")
		case upper == "RSET":
			env = envelope{}
			reply("250 2.0.0 Ok")
		case upper == "NOOP":
			reply("250 2.0.0 Ok")
		case upper == "QUIT":
			reply("221 2.0.0 Bye")
			return
		default:
			reply("502 5.5.2 Command not implemented")
		}
	}
}

// addrArg pulls the address out of "MAIL FROM:<a@b> SIZE=123".
func addrArg(line, prefix string) string {
	rest := strings.TrimSpace(line[len(prefix):])
	if i := strings.Index(rest, ">"); i >= 0 {
		rest = rest[:i+1]
	}
	return strings.Trim(rest, "<>")
}
