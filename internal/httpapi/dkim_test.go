package httpapi

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// recordsByPurpose groups a domain's DNS records for assertions.
func recordsByPurpose(d apiDomain) map[string][]dnsRecord {
	out := map[string][]dnsRecord{}
	for _, r := range d.DnsRecords {
		out[r.Purpose] = append(out[r.Purpose], r)
	}
	return out
}

func TestAddDomainReturnsAllRecords(t *testing.T) {
	h, token, slug := domainHarness(t)
	name := fmt.Sprintf("records-%d.test", time.Now().UnixNano()%1_000_000)

	rec := h.do(http.MethodPost, "/workspaces/"+slug+"/domains",
		fmt.Sprintf(`{"domain":%q}`, name), token)
	if rec.Code != http.StatusCreated {
		t.Fatalf("add: %d %s", rec.Code, rec.Body)
	}
	d := decodeDomain(t, rec.Body.Bytes())

	by := recordsByPurpose(d)
	for _, purpose := range []string{"ownership", "spf", "dkim", "dmarc"} {
		if len(by[purpose]) == 0 {
			t.Errorf("no %s record returned", purpose)
		}
	}

	if got := by["spf"][0]; got.Name != name || !strings.HasPrefix(got.Value, "v=spf1 ") {
		t.Errorf("spf record = %+v", got)
	}
	if got := by["dmarc"][0]; got.Name != "_dmarc."+name || !strings.HasPrefix(got.Value, "v=DMARC1;") {
		t.Errorf("dmarc record = %+v", got)
	}

	// The DKIM record must carry a usable public key under a selector.
	dkim := by["dkim"][0]
	if !strings.HasSuffix(dkim.Name, "._domainkey."+name) {
		t.Errorf("dkim record name = %q", dkim.Name)
	}
	if !strings.HasPrefix(dkim.Value, "v=DKIM1; k=rsa; p=") {
		t.Fatalf("dkim record value = %q", dkim.Value)
	}

	der, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(dkim.Value, "v=DKIM1; k=rsa; p="))
	if err != nil {
		t.Fatalf("dkim public key is not base64: %v", err)
	}
	if _, err := x509.ParsePKIXPublicKey(der); err != nil {
		t.Errorf("dkim public key does not parse: %v", err)
	}
}

func TestPrivateKeyIsEncryptedAtRest(t *testing.T) {
	h, token, slug := domainHarness(t)
	name := fmt.Sprintf("sealed-%d.test", time.Now().UnixNano()%1_000_000)
	h.do(http.MethodPost, "/workspaces/"+slug+"/domains", fmt.Sprintf(`{"domain":%q}`, name), token)

	var stored string
	err := h.pool.QueryRow(context.Background(),
		`SELECT k.private_key FROM dkim_keys k JOIN domains d ON d.id = k.domain_id WHERE d.domain = $1`,
		name).Scan(&stored)
	if err != nil {
		t.Fatalf("read stored key: %v", err)
	}

	// A PEM header or DER prefix in the column would mean it went in raw.
	if strings.Contains(stored, "PRIVATE KEY") || strings.Contains(stored, "BEGIN") {
		t.Fatalf("the private key looks unencrypted: %.40s", stored)
	}

	raw, err := base64.StdEncoding.DecodeString(stored)
	if err != nil {
		t.Fatalf("stored value is not base64: %v", err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(raw); err == nil {
		t.Fatal("the stored bytes parse as a private key, so they are not encrypted")
	}

	// And it must decrypt back to a real key through the service.
	var domainID string
	h.pool.QueryRow(context.Background(), `SELECT id FROM domains WHERE domain = $1`, name).Scan(&domainID)

	selector, der, err := h.domains.SigningKey(context.Background(), domainID)
	if err != nil {
		t.Fatalf("SigningKey: %v", err)
	}
	if selector == "" {
		t.Error("no selector returned")
	}
	if _, err := x509.ParsePKCS8PrivateKey(der); err != nil {
		t.Errorf("decrypted key does not parse: %v", err)
	}
}

func TestDkimRotationIsTwoPhase(t *testing.T) {
	h, token, slug := domainHarness(t)
	name := fmt.Sprintf("rotate-%d.test", time.Now().UnixNano()%1_000_000)
	base := "/workspaces/" + slug + "/domains"

	created := h.do(http.MethodPost, base, fmt.Sprintf(`{"domain":%q}`, name), token)
	first := recordsByPurpose(decodeDomain(t, created.Body.Bytes()))["dkim"][0]

	activeSelector := func() string {
		t.Helper()
		var sel string
		h.pool.QueryRow(context.Background(),
			`SELECT k.selector FROM dkim_keys k JOIN domains d ON d.id = k.domain_id
			 WHERE d.domain = $1 AND k.is_active`, name).Scan(&sel)
		return sel
	}
	firstSelector := activeSelector()
	if firstSelector == "" {
		t.Fatal("the first key should be active immediately")
	}

	// Rotate: a second record appears, but signing must not move yet.
	rotated := h.do(http.MethodPost, base+"/"+name+"/dkim/rotate", "", token)
	if rotated.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rotated.Code, rotated.Body)
	}
	dkimRecords := recordsByPurpose(decodeDomain(t, rotated.Body.Bytes()))["dkim"]
	if len(dkimRecords) != 2 {
		t.Fatalf("expected 2 DKIM records after rotation, got %d", len(dkimRecords))
	}
	if activeSelector() != firstSelector {
		t.Error("signing switched before the new record was published")
	}

	var pending struct{ Name, Value string }
	for _, r := range dkimRecords {
		if r.Name != first.Name {
			pending.Name, pending.Value = r.Name, r.Value
		}
	}
	if pending.Name == "" {
		t.Fatal("no new DKIM record was produced")
	}

	// Verifying without the new record published leaves the signer alone.
	h.dns.publish("_heromail-challenge."+name, "")
	h.do(http.MethodPost, base+"/"+name+"/verify", "", token)
	if activeSelector() != firstSelector {
		t.Error("signing switched even though the new record is still absent")
	}

	// Publish it, verify again: now the new key takes over and the old retires.
	h.dns.publish(pending.Name, pending.Value)
	if rec := h.do(http.MethodPost, base+"/"+name+"/verify", "", token); rec.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", rec.Code, rec.Body)
	}

	promoted := activeSelector()
	if promoted == firstSelector {
		t.Fatal("the pending key was not promoted after its record appeared")
	}

	var retiredAt *time.Time
	h.pool.QueryRow(context.Background(),
		`SELECT k.retired_at FROM dkim_keys k JOIN domains d ON d.id = k.domain_id
		 WHERE d.domain = $1 AND k.selector = $2`, name, firstSelector).Scan(&retiredAt)
	if retiredAt == nil {
		t.Error("the previous key was not retired")
	}

	// The retired key stays listed so the customer does not delete its record.
	after := h.do(http.MethodGet, base+"/"+name, "", token)
	if got := len(recordsByPurpose(decodeDomain(t, after.Body.Bytes()))["dkim"]); got != 2 {
		t.Errorf("retired key dropped from dns_records (%d DKIM records)", got)
	}
}

func TestVerifyReportsPerRecordStatus(t *testing.T) {
	h, token, slug := domainHarness(t)
	name := fmt.Sprintf("status-%d.test", time.Now().UnixNano()%1_000_000)
	base := "/workspaces/" + slug + "/domains"

	created := h.do(http.MethodPost, base, fmt.Sprintf(`{"domain":%q}`, name), token)
	d := decodeDomain(t, created.Body.Bytes())

	// Reads that did not resolve DNS must not claim a status.
	for _, r := range d.DnsRecords {
		if r.Status != "" {
			t.Errorf("record %s has status %q before any check", r.Name, r.Status)
		}
	}

	// Publish ownership and SPF, leave DKIM and DMARC absent.
	by := recordsByPurpose(d)
	h.dns.publish(by["ownership"][0].Name, by["ownership"][0].Value)
	h.dns.publish(name, "v=spf1 include:spf.heromail.local ~all")

	rec := h.do(http.MethodPost, base+"/"+name+"/verify", "", token)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", rec.Code, rec.Body)
	}
	verified := decodeDomain(t, rec.Body.Bytes())
	if !verified.Verified {
		t.Error("ownership was published but the domain is not verified")
	}

	got := map[string]string{}
	for _, r := range verified.DnsRecords {
		got[r.Purpose] = r.Status
	}
	if got["ownership"] != "ok" || got["spf"] != "ok" {
		t.Errorf("published records reported as %v", got)
	}
	if got["dkim"] != "missing" || got["dmarc"] != "missing" {
		t.Errorf("absent records reported as %v", got)
	}
}

func TestSpfMatchesMergedPolicy(t *testing.T) {
	h, token, slug := domainHarness(t)
	name := fmt.Sprintf("spfmerge-%d.test", time.Now().UnixNano()%1_000_000)
	base := "/workspaces/" + slug + "/domains"
	h.do(http.MethodPost, base, fmt.Sprintf(`{"domain":%q}`, name), token)

	// A customer who already sends from elsewhere merges our mechanism in.
	// Demanding a byte-for-byte match would call this working setup broken.
	h.dns.publish(name, "v=spf1 include:_spf.google.com include:spf.heromail.local -all")

	rec := h.do(http.MethodPost, base+"/"+name+"/verify", "", token)
	for _, r := range decodeDomain(t, rec.Body.Bytes()).DnsRecords {
		if r.Purpose == "spf" && r.Status != "ok" {
			t.Errorf("merged SPF policy reported as %q: %s", r.Status, r.Value)
		}
	}

	// An SPF record that does not authorise us is a mismatch, not a pass.
	h.dns.publish(name, "v=spf1 include:_spf.google.com -all")
	rec = h.do(http.MethodPost, base+"/"+name+"/verify", "", token)
	for _, r := range decodeDomain(t, rec.Body.Bytes()).DnsRecords {
		if r.Purpose == "spf" && r.Status == "ok" {
			t.Error("an SPF record that omits our mechanism was accepted")
		}
	}
}
