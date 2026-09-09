package submission

import (
	"bytes"
	"testing"
)

func TestPrepareRejectsSpoofingAndPreservesMIME(t *testing.T) {
	body := "--boundary\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\nAAECAwQ=\r\n--boundary--\r\n"
	raw := []byte("From: Employee <employee@example.test>\r\nBcc: secret@example.test\r\n\t, other@example.test\r\nReturn-Path: <forged@example.test>\r\nDKIM-Signature: fake\r\nContent-Type: multipart/mixed; boundary=boundary\r\n\r\n" + body)
	got, err := prepare(raw, "employee@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(got, []byte(body)) || bytes.Contains(got, []byte("secret@")) || bytes.Contains(got, []byte("other@")) || bytes.Contains(got, []byte("forged@")) || bytes.Contains(got, []byte("DKIM-Signature")) {
		t.Fatal("MIME changed or private/forged headers retained")
	}
	for _, headers := range []string{"From: other@example.test", "From: employee@example.test\r\nFrom: other@example.test", "From: employee@example.test, other@example.test", "From: employee@example.test\r\nSender: other@example.test", "From: employee@example.test\r\nResent-From: other@example.test", "Subject: no author"} {
		if _, err := prepare([]byte(headers+"\r\n\r\nhello\r\n"), "employee@example.test"); err == nil {
			t.Errorf("accepted %q", headers)
		}
	}
}
