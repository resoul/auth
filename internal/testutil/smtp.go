package testutil

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type SMTPMessage struct {
	From string
	To   []string
	Data string
}

type FakeSMTP struct {
	ln       net.Listener
	script   smtpScript
	mu       sync.Mutex
	messages []SMTPMessage
	conns    int
	done     chan struct{}
}

type smtpScript struct {
	greeting, mail, rcpt, data string
	hang                       bool
}

func (s *FakeSMTP) Reply(command, line string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch command {
	case "greeting":
		s.script.greeting = line
	case "mail":
		s.script.mail = line
	case "rcpt":
		s.script.rcpt = line
	case "data":
		s.script.data = line
	default:
		panic("unknown SMTP command " + command)
	}
}

func (s *FakeSMTP) Hang() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.script.hang = true
}

func (s *FakeSMTP) scripted() smtpScript {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.script
}

func NewFakeSMTP(t testing.TB) *FakeSMTP {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	s := &FakeSMTP{ln: ln, done: make(chan struct{})}
	go s.serve()

	t.Cleanup(func() {
		close(s.done)

		_ = ln.Close()
	})

	return s
}

func (s *FakeSMTP) Addr() (string, int) {
	addr := s.ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port
}

func (s *FakeSMTP) Messages() []SMTPMessage {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]SMTPMessage(nil), s.messages...)
}

func (s *FakeSMTP) Connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.conns
}

func reply(configured, fallback string) string {
	if configured != "" {
		return configured
	}

	return fallback
}

func (s *FakeSMTP) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}

		s.mu.Lock()
		s.conns++

		s.mu.Unlock()
		go s.handle(conn)
	}
}

func (s *FakeSMTP) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	script := s.scripted()
	if script.hang {
		select {
		case <-s.done:
		case <-time.After(time.Minute):
		}

		return
	}

	write := func(line string) { _, _ = io.WriteString(conn, line+"\r\n") }
	r := bufio.NewReader(conn)

	greeting := reply(script.greeting, "220 fake ESMTP")
	write(greeting)

	if !strings.HasPrefix(greeting, "2") {
		return
	}

	var msg SMTPMessage

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}

		line = strings.TrimRight(line, "\r\n")

		verb := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(verb, "EHLO"), strings.HasPrefix(verb, "HELO"):
			write("250-fake")
			write("250 8BITMIME")
		case strings.HasPrefix(verb, "MAIL FROM:"):
			reply := reply(script.mail, "250 OK")
			if strings.HasPrefix(reply, "2") {
				msg = SMTPMessage{From: addressOf(line)}
			}

			write(reply)
		case strings.HasPrefix(verb, "RCPT TO:"):
			reply := reply(script.rcpt, "250 OK")
			if strings.HasPrefix(reply, "2") {
				msg.To = append(msg.To, addressOf(line))
			}

			write(reply)
		case verb == "DATA":
			write("354 go ahead")

			var data strings.Builder

			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}

				if l == ".\r\n" {
					break
				}

				data.WriteString(strings.TrimPrefix(l, "."))
			}

			reply := reply(script.data, "250 queued")
			if strings.HasPrefix(reply, "2") {
				msg.Data = data.String()

				s.mu.Lock()
				s.messages = append(s.messages, msg)
				s.mu.Unlock()
			}

			write(reply)
		case verb == "RSET":
			msg = SMTPMessage{}

			write("250 OK")
		case verb == "NOOP":
			write("250 OK")
		case verb == "QUIT":
			write("221 bye")
			return
		default:
			write("502 not implemented " + strconv.Itoa(len(line)))
		}
	}
}

func addressOf(line string) string {
	start, end := strings.Index(line, "<"), strings.Index(line, ">")
	if start < 0 || end < start {
		return ""
	}

	return line[start+1 : end]
}
