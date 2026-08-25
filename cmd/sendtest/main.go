// Command sendtest delivers one message straight to a recipient's MX, using the
// production provider code path. It exists to answer a single question: can
// this host actually deliver to a real mailbox today?
//
//	go run ./cmd/sendtest -to someone@gmail.com
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"time"

	"github.com/rnm/heromail/backend/internal/provider"
	smtpprovider "github.com/rnm/heromail/backend/internal/provider/smtp"
)

func main() {
	to := flag.String("to", "", "recipient address (required)")
	from := flag.String("from", "noreply@app-dev-heromail.rnm.dev", "envelope sender")
	subject := flag.String("subject", "тест", "subject")
	body := flag.String("body", "тест тест", "plain text body")
	flag.Parse()

	if *to == "" {
		log.Fatal("-to is required")
	}

	domain := (*to)[indexAt(*to)+1:]
	mx, err := net.LookupMX(domain)
	if err != nil || len(mx) == 0 {
		log.Fatalf("no MX for %s: %v", domain, err)
	}
	sort.Slice(mx, func(i, j int) bool { return mx[i].Pref < mx[j].Pref })
	host := mx[0].Host[:len(mx[0].Host)-1] // strip the trailing dot

	fmt.Printf("MX для %s: %s (приоритет %d)\n", domain, host, mx[0].Pref)

	// Port 25 and no TLS requirement: this is server-to-server delivery, not a
	// submission relay.
	sender, err := smtpprovider.New(smtpprovider.Config{Host: host, Port: 25, Timeout: 30 * time.Second})
	if err != nil {
		log.Fatalf("build sender: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	id, err := sender.Send(ctx, provider.Message{
		From: *from, To: []string{*to}, Subject: *subject, TextBody: *body,
	})
	if err != nil {
		fmt.Printf("\nОТКАЗ: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\nПРИНЯТО. Message-ID: %s\n", id)
}

func indexAt(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '@' {
			return i
		}
	}
	return -1
}
