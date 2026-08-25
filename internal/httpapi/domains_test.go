package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"
)

// fakeResolver answers TXT lookups from a map, so domain verification is
// tested without touching DNS.
type fakeResolver struct {
	mu      sync.Mutex
	records map[string][]string
	err     error
}

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.records[name], nil
}

func (f *fakeResolver) publish(name string, values ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.records == nil {
		f.records = map[string][]string{}
	}
	f.records[name] = values
}

type dnsRecord struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Value   string   `json:"value"`
	Purpose string   `json:"purpose"`
	Status  string   `json:"status"`
	Found   []string `json:"found"`
}

type apiDomain struct {
	ID         string      `json:"id"`
	Domain     string      `json:"domain"`
	IsPrimary  bool        `json:"is_primary"`
	Verified   bool        `json:"verified"`
	LastError  string      `json:"last_error"`
	DnsRecords []dnsRecord `json:"dns_records"`
}

func decodeDomain(t *testing.T, body []byte) apiDomain {
	t.Helper()
	var d apiDomain
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatalf("decode domain: %v (body: %s)", err, body)
	}
	return d
}

// domainHarness sets up a workspace whose owner can manage domains.
func domainHarness(t *testing.T) (h *harness, token, slug string) {
	t.Helper()

	h = newHarness(t)
	token, _, _ = h.registerUser("dom")

	slug = fmt.Sprintf("dom-%d", time.Now().UnixNano()%1_000_000)
	rec := h.do(http.MethodPost, "/workspaces",
		fmt.Sprintf(`{"slug":%q,"name":"Domain Test"}`, slug), token)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create workspace: %d %s", rec.Code, rec.Body)
	}
	t.Cleanup(func() {
		h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE slug = $1`, slug)
	})
	return h, token, slug
}

func TestDomainLifecycle(t *testing.T) {
	h, token, slug := domainHarness(t)
	name := fmt.Sprintf("acme-%d.test", time.Now().UnixNano()%1_000_000)
	base := "/workspaces/" + slug + "/domains"

	// Claim it. Not verified, and the response carries the record to publish.
	created := h.do(http.MethodPost, base, fmt.Sprintf(`{"domain":%q}`, name), token)
	if created.Code != http.StatusCreated {
		t.Fatalf("add: %d %s", created.Code, created.Body)
	}
	d := decodeDomain(t, created.Body.Bytes())
	if d.Verified {
		t.Error("a freshly claimed domain must not be verified")
	}
	// Ownership, SPF, DKIM and DMARC all come back at once, so the customer
	// visits their DNS provider a single time.
	if len(d.DnsRecords) < 4 {
		t.Fatalf("expected ownership, spf, dkim and dmarc records, got %d", len(d.DnsRecords))
	}
	var record dnsRecord
	for _, r := range d.DnsRecords {
		if r.Purpose == "ownership" {
			record = r
		}
	}
	if record.Type != "TXT" || record.Name == "" {
		t.Fatalf("ownership record = %+v", record)
	}
	if record.Name != "_heromail-challenge."+name {
		t.Errorf("record name = %q", record.Name)
	}

	// Verifying before publishing fails, and says what was missing.
	notYet := h.do(http.MethodPost, base+"/"+name+"/verify", "", token)
	if notYet.Code != http.StatusOK {
		t.Fatalf("verify: %d %s — a failed check is still a 200", notYet.Code, notYet.Body)
	}
	d = decodeDomain(t, notYet.Body.Bytes())
	if d.Verified {
		t.Error("verified without the record being published")
	}
	if d.LastError == "" {
		t.Error("a failed check must record why")
	}

	// Promoting an unverified domain is refused.
	if rec := h.do(http.MethodPatch, base+"/"+name, `{"is_primary":true}`, token); rec.Code != http.StatusBadRequest {
		t.Errorf("promoting an unverified domain returned %d, want 400", rec.Code)
	}

	// Publish the record and verify for real.
	h.dns.publish(record.Name, record.Value)
	ok := h.do(http.MethodPost, base+"/"+name+"/verify", "", token)
	if ok.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", ok.Code, ok.Body)
	}
	d = decodeDomain(t, ok.Body.Bytes())
	if !d.Verified {
		t.Fatalf("still unverified after publishing: %+v", d)
	}
	if d.LastError != "" {
		t.Errorf("last_error should be cleared on success, got %q", d.LastError)
	}

	// Now it can be primary.
	promoted := h.do(http.MethodPatch, base+"/"+name, `{"is_primary":true}`, token)
	if promoted.Code != http.StatusOK {
		t.Fatalf("promote: %d %s", promoted.Code, promoted.Body)
	}
	if !decodeDomain(t, promoted.Body.Bytes()).IsPrimary {
		t.Error("is_primary was not set")
	}

	// List and get agree.
	list := h.do(http.MethodGet, base, "", token)
	var listed struct {
		Domains []apiDomain `json:"domains"`
	}
	json.Unmarshal(list.Body.Bytes(), &listed)
	if len(listed.Domains) != 1 || listed.Domains[0].Domain != name {
		t.Errorf("listed = %+v", listed.Domains)
	}
	if rec := h.do(http.MethodGet, base+"/"+name, "", token); rec.Code != http.StatusOK {
		t.Errorf("get: %d %s", rec.Code, rec.Body)
	}

	// Release it.
	if rec := h.do(http.MethodDelete, base+"/"+name, "", token); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	if rec := h.do(http.MethodGet, base+"/"+name, "", token); rec.Code != http.StatusNotFound {
		t.Errorf("deleted domain still readable (%d)", rec.Code)
	}
}

func TestAddDomainNormalisesAndValidates(t *testing.T) {
	h, token, slug := domainHarness(t)
	base := "/workspaces/" + slug + "/domains"

	name := fmt.Sprintf("Mixed-%d.TEST", time.Now().UnixNano()%1_000_000)
	rec := h.do(http.MethodPost, base, fmt.Sprintf(`{"domain":%q}`, name), token)
	if rec.Code != http.StatusCreated {
		t.Fatalf("add: %d %s", rec.Code, rec.Body)
	}
	if got := decodeDomain(t, rec.Body.Bytes()).Domain; got != lower(name) {
		t.Errorf("domain stored as %q, want lowercase %q", got, lower(name))
	}

	for label, body := range map[string]string{
		"no dot":       `{"domain":"localhost"}`,
		"leading dash": `{"domain":"-acme.test"}`,
		"empty":        `{"domain":""}`,
	} {
		t.Run(label, func(t *testing.T) {
			if got := h.do(http.MethodPost, base, body, token); got.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body = %s", got.Code, got.Body)
			}
		})
	}
}

func TestDomainIsGloballyUnique(t *testing.T) {
	h, token, slug := domainHarness(t)
	name := fmt.Sprintf("shared-%d.test", time.Now().UnixNano()%1_000_000)

	if rec := h.do(http.MethodPost, "/workspaces/"+slug+"/domains",
		fmt.Sprintf(`{"domain":%q}`, name), token); rec.Code != http.StatusCreated {
		t.Fatalf("first claim: %d %s", rec.Code, rec.Body)
	}

	// A second workspace — a different tenant entirely — cannot claim it.
	otherToken, _, _ := h.registerUser("dom-other")
	otherSlug := fmt.Sprintf("other-%d", time.Now().UnixNano()%1_000_000)
	h.do(http.MethodPost, "/workspaces", fmt.Sprintf(`{"slug":%q,"name":"Other"}`, otherSlug), otherToken)
	t.Cleanup(func() {
		h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE slug = $1`, otherSlug)
	})

	rec := h.do(http.MethodPost, "/workspaces/"+otherSlug+"/domains",
		fmt.Sprintf(`{"domain":%q}`, name), otherToken)
	if rec.Code != http.StatusConflict {
		t.Errorf("another tenant claimed the same domain: %d %s", rec.Code, rec.Body)
	}

	// And it must not be readable from there either.
	if got := h.do(http.MethodGet, "/workspaces/"+otherSlug+"/domains/"+name, "", otherToken); got.Code != http.StatusNotFound {
		t.Errorf("another tenant can read the domain (%d)", got.Code)
	}
}

func TestDomainsRequireMembershipAndRole(t *testing.T) {
	h, token, slug := domainHarness(t)
	base := "/workspaces/" + slug + "/domains"
	name := fmt.Sprintf("perm-%d.test", time.Now().UnixNano()%1_000_000)
	h.do(http.MethodPost, base, fmt.Sprintf(`{"domain":%q}`, name), token)

	// A non-member sees the workspace as absent, not forbidden.
	outsider, _, _ := h.registerUser("dom-outsider")
	for label, path := range map[string]string{"list": base, "get": base + "/" + name} {
		t.Run("outsider "+label, func(t *testing.T) {
			if rec := h.do(http.MethodGet, path, "", outsider); rec.Code != http.StatusNotFound {
				t.Errorf("status = %d, want 404", rec.Code)
			}
		})
	}

	// A plain member may read but not change.
	memberToken, memberID, _ := h.registerUser("dom-member")
	var workspaceID string
	h.pool.QueryRow(context.Background(), `SELECT id FROM workspaces WHERE slug = $1`, slug).Scan(&workspaceID)
	if _, err := h.pool.Exec(context.Background(),
		`INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1, $2, 'member')`,
		workspaceID, memberID); err != nil {
		t.Fatalf("seed member: %v", err)
	}

	if rec := h.do(http.MethodGet, base, "", memberToken); rec.Code != http.StatusOK {
		t.Errorf("a member cannot list domains (%d)", rec.Code)
	}
	for label, req := range map[string]struct {
		method, path, body string
	}{
		"add":    {http.MethodPost, base, `{"domain":"nope-member.test"}`},
		"verify": {http.MethodPost, base + "/" + name + "/verify", ""},
		"patch":  {http.MethodPatch, base + "/" + name, `{"is_primary":true}`},
		"delete": {http.MethodDelete, base + "/" + name, ""},
	} {
		t.Run("member "+label, func(t *testing.T) {
			rec := h.do(req.method, req.path, req.body, memberToken)
			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403; body = %s", rec.Code, rec.Body)
			}
			if code := errorCode(t, rec); code != "forbidden" {
				t.Errorf("error code = %q, want forbidden", code)
			}
		})
	}

	// An API key is the wrong credential for this surface entirely.
	key := h.apiKeyFor(workspaceID)
	if rec := h.do(http.MethodGet, base, "", key); rec.Code != http.StatusUnauthorized {
		t.Errorf("an API key reached the domains API (%d)", rec.Code)
	}
}

func TestVerifyReportsResolverFailure(t *testing.T) {
	h, token, slug := domainHarness(t)
	name := fmt.Sprintf("dnsfail-%d.test", time.Now().UnixNano()%1_000_000)
	base := "/workspaces/" + slug + "/domains"
	h.do(http.MethodPost, base, fmt.Sprintf(`{"domain":%q}`, name), token)

	h.dns.err = errors.New("server misbehaving")
	defer func() { h.dns.err = nil }()

	rec := h.do(http.MethodPost, base+"/"+name+"/verify", "", token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a DNS outage is an outcome, not a request error", rec.Code)
	}
	d := decodeDomain(t, rec.Body.Bytes())
	if d.Verified || d.LastError == "" {
		t.Errorf("resolver failure was not reported: %+v", d)
	}
}

func lower(s string) string {
	out := []rune(s)
	for i, r := range out {
		if r >= 'A' && r <= 'Z' {
			out[i] = r + 32
		}
	}
	return string(out)
}
