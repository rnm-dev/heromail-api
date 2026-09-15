package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/rnm/heromail/backend/internal/inbound"
)

func TestReceivedAttachmentAccess(t *testing.T) {
	h := newHarness(t)
	ctx := t.Context()
	owner, _, _ := h.registerUser("attachment-owner")
	member, uid, _ := h.registerUser("attachment-reader")
	ws := h.workspaceFor(owner, "attachments")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	if _, err := h.pool.Exec(ctx, `INSERT INTO workspace_members(workspace_id,user_id,role) VALUES($1,$2,'member')`, ws, uid); err != nil {
		t.Fatal(err)
	}
	domain := h.verifiedDomainFor(t, ws)
	store := inbound.NewStore(h.pool)
	box, err := store.CreateMailbox(ctx, mustDomainID(t, h, domain), "files", "Files", &uid)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("PK\x00\xff"), 3<<20)
	raw := []byte("From: sender@example.test\r\nMIME-Version: 1.0\r\nContent-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\r\nContent-Disposition: attachment; filename=report.xlsx\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString(data))
	msg, err := store.Deliver(ctx, inbound.DeliverParams{MailboxID: box.ID, EnvelopeTo: box.Address, Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	path := "/workspaces/" + h.slugFor(ws) + "/messages/" + msg.ID
	response := h.do("GET", path, "", member)
	var detail ReceivedMessage
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &detail) != nil || detail.Attachments == nil || len(*detail.Attachments) != 1 {
		t.Fatalf("listing: %d", response.Code)
	}
	file := (*detail.Attachments)[0]
	if file.SizeBytes != int64(len(data)) {
		t.Fatal("wrong size")
	}
	download := path + "/attachments/" + file.Id
	for _, token := range []string{owner, "", h.apiKeyFor(ws)} {
		r := h.do("GET", download, "", token)
		if r.Code == 200 {
			t.Fatal("private attachment leaked")
		}
	}
	r := h.do("GET", download, "", member)
	if r.Code != 200 || !bytes.Equal(data, r.Body.Bytes()) || r.Header().Get("Content-Type") != "application/octet-stream" || r.Header().Get("Content-Disposition") != "attachment; filename=report.xlsx" || r.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("download: %d", r.Code)
	}
	if h.do("GET", path+"/attachments/999", "", member).Code != 404 {
		t.Fatal("missing attachment")
	}
	other := h.workspaceFor(member, "attachment-other")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, other) })
	if h.do("GET", "/workspaces/"+h.slugFor(other)+"/messages/"+msg.ID+"/attachments/"+file.Id, "", member).Code != 404 {
		t.Fatal("cross tenant download")
	}
}
