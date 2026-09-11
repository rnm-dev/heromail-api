package httpapi

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/rnm/heromail/backend/internal/inbound"
)

func TestReplyMediaAccessAndThread(t *testing.T) {
	h := newHarness(t)
	token, userID, _ := h.registerUser("reply-media")
	other, otherID, _ := h.registerUser("reply-other")
	ws := h.workspaceFor(token, "reply-media")
	domain := h.verifiedDomainFor(t, ws)
	path := "/workspaces/" + h.slugFor(ws)
	if _, err := h.pool.Exec(t.Context(), `INSERT INTO workspace_members(workspace_id,user_id,role) VALUES($1,$2,'member')`, ws, otherID); err != nil {
		t.Fatal(err)
	}
	r := h.do("POST", path+"/mailboxes", fmt.Sprintf(`{"domain":%q,"local_part":"me","owner_user_id":%q}`, domain, userID), token)
	if r.Code != 201 {
		t.Fatalf("box %d %s", r.Code, r.Body)
	}
	var box Mailbox
	if err := json.Unmarshal(r.Body.Bytes(), &box); err != nil {
		t.Fatal(err)
	}
	const png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII="
	raw := []byte("From: sender@example.test\r\nReply-To: support@example.test\r\nMessage-ID: <parent@example.test>\r\nReferences: <root@example.test>\r\nContent-Type: multipart/related; boundary=x\r\n\r\n--x\r\nContent-Type: text/html\r\n\r\n<img src=\"cid:pic\">\r\n--x\r\nContent-Type: image/png\r\nContent-ID: <pic>\r\nContent-Transfer-Encoding: base64\r\n\r\n" + png + "\r\n--x--\r\n")
	msg, err := inbound.NewStore(h.pool).Deliver(t.Context(), inbound.DeliverParams{MailboxID: box.Id.String(), EnvelopeTo: string(box.Address), Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	r = h.do("GET", path+"/messages/"+msg.ID, "", token)
	if r.Code != 200 {
		t.Fatalf("detail %d %s", r.Code, r.Body)
	}
	var detail ReceivedMessage
	if err = json.Unmarshal(r.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.InlineMedia == nil || (*detail.InlineMedia)["pic"] != "data:image/png;base64,"+png || detail.ReplyTo == nil || (*detail.ReplyTo)[0] != "support@example.test" {
		t.Fatalf("detail missing media/reply: %+v", detail)
	}
	if r = h.do("GET", path+"/messages/"+msg.ID, "", other); r.Code != 404 {
		t.Fatal("private media exposed")
	}
	// A shared sending address lets this member send ordinary mail, but not
	// derive headers from somebody else's private message.
	r = h.do("POST", path+"/mailboxes", fmt.Sprintf(`{"domain":%q,"local_part":"shared","shared":true}`, domain), token)
	if r.Code != 201 {
		t.Fatal(r.Body)
	}
	body := fmt.Sprintf(`{"from":"shared@%s","to":["support@example.test"],"text":"reply","reply_to_message_id":%q}`, domain, msg.ID)
	if r = h.do("POST", path+"/emails", body, other); r.Code != 404 {
		t.Fatalf("private reply allowed %d %s", r.Code, r.Body)
	}
	if r = h.do("POST", "/v1/emails", body, h.apiKeyFor(ws)); r.Code != 400 {
		t.Fatal("API key derived reply")
	}
	h.mail.reset()
	r = h.doWithHeader("POST", path+"/emails", body, token, "Idempotency-Key", "reply-media-key")
	if r.Code != 202 {
		t.Fatalf("send %d %s", r.Code, r.Body)
	}
	var queued SendEmailResponse
	if err = json.Unmarshal(r.Body.Bytes(), &queued); err != nil {
		t.Fatal(err)
	}
	retry := h.doWithHeader("POST", path+"/emails", body, token, "Idempotency-Key", "reply-media-key")
	if retry.Code != 202 {
		t.Fatalf("retry %d %s", retry.Code, retry.Body)
	}
	var retried SendEmailResponse
	if err := json.Unmarshal(retry.Body.Bytes(), &retried); err != nil || retried.Id != queued.Id {
		t.Fatal("retry created a different reply")
	}
	changed, err := inbound.NewStore(h.pool).Deliver(t.Context(), inbound.DeliverParams{MailboxID: box.Id.String(), EnvelopeTo: string(box.Address), Raw: []byte("From: sender@example.test\r\nMessage-ID: <different@example.test>\r\n\r\nother")})
	if err != nil {
		t.Fatal(err)
	}
	differentBody := strings.Replace(body, msg.ID, changed.ID, 1)
	if r = h.doWithHeader("POST", path+"/emails", differentBody, token, "Idempotency-Key", "reply-media-key"); r.Code != 400 {
		t.Fatal("same retry key accepted a different parent")
	}
	h.runWorker(queued.Id.String())
	wire, ok := h.mail.last()
	if !ok || wire.Headers["In-Reply-To"] != "<parent@example.test>" || wire.Headers["References"] != "<root@example.test> <parent@example.test>" {
		t.Fatalf("lost thread: %+v", wire.Headers)
	}
	h.runWorker(queued.Id.String())
	if h.mail.count() != 1 {
		t.Fatal("duplicate reply sent")
	}
}
