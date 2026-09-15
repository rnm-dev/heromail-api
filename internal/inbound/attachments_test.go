package inbound

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestLargeNestedAttachment(t *testing.T) {
	data := bytes.Repeat([]byte("PK\x03\x04binary\x00\xff"), 1200000)
	raw := []byte("MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\nContent-Type: multipart/mixed; boundary=inner\r\n\r\n--inner\r\nContent-Type: text/plain\r\n\r\nbody\r\n--inner\r\nContent-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\r\nContent-Disposition: attachment; filename*=utf-8''report%20file.xlsx\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString(data) + "\r\n--inner--\r\n--outer--\r\n")
	items, body, omitted := ScanAttachments(raw, "")
	if omitted || len(items) != 1 || body != nil || items[0].Filename != "report file.xlsx" || items[0].Size != int64(len(data)) {
		t.Fatalf("listing: %+v omitted=%v", items, omitted)
	}
	_, body, omitted = ScanAttachments(raw, items[0].ID)
	if omitted || !bytes.Equal(body, data) {
		t.Fatal("large binary download corrupted")
	}
}
func TestAttachmentInvalidEncoding(t *testing.T) {
	items, _, omitted := ScanAttachments([]byte("Content-Disposition: attachment; filename=broken.xlsx\r\nContent-Transfer-Encoding: base64\r\n\r\n!!!!"), "")
	if !omitted || len(items) != 0 {
		t.Fatal("invalid encoding silently accepted")
	}
}

func TestTextAttachmentPreservesCharsetBytes(t *testing.T) {
	data := []byte{0xcf, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2}
	raw := []byte("Content-Type: text/csv; charset=windows-1251\r\nContent-Disposition: attachment; filename=report.csv\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString(data))
	items, body, omitted := ScanAttachments(raw, "1")
	if omitted || len(items) != 1 || !bytes.Equal(body, data) {
		t.Fatal("text attachment transcoded")
	}
}
