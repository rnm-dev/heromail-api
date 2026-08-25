package maildomain

import (
	"context"
	"fmt"
	"strings"
)

// RecordPurpose says why a record exists, so the UI can group and explain them.
type RecordPurpose string

const (
	PurposeOwnership RecordPurpose = "ownership"
	PurposeSPF       RecordPurpose = "spf"
	PurposeDKIM      RecordPurpose = "dkim"
	PurposeDMARC     RecordPurpose = "dmarc"
)

// RecordStatus is only known after a check. Reads that did not resolve DNS
// leave it empty rather than guessing.
type RecordStatus string

const (
	StatusOK       RecordStatus = "ok"
	StatusMissing  RecordStatus = "missing"
	StatusMismatch RecordStatus = "mismatch"
)

// Record is one DNS entry the customer has to publish.
type Record struct {
	Type     string
	Name     string
	Value    string
	Purpose  RecordPurpose
	Required bool
	Status   RecordStatus
	// Found is what actually resolved, so a mismatch can be shown side by side
	// instead of just asserting the customer is wrong.
	Found []string
}

// Config is what the expected record values depend on: our own sending
// infrastructure, which the customer's DNS has to authorise.
type Config struct {
	// SPFInclude is the mechanism authorising our senders, e.g.
	// "include:spf.heromail.dev" or "ip4:203.0.113.10".
	SPFInclude string
	// DMARCReportTo receives aggregate reports.
	DMARCReportTo string
}

func (c Config) withDefaults() Config {
	if c.SPFInclude == "" {
		c.SPFInclude = "include:spf.heromail.local"
	}
	if c.DMARCReportTo == "" {
		c.DMARCReportTo = "dmarc@heromail.local"
	}
	return c
}

// spfValue is a complete SPF record. `~all` (softfail) rather than `-all`
// because a customer who also sends from elsewhere would otherwise have their
// own mail rejected the moment they publish this; tightening to `-all` is a
// deliberate later step, not a default.
func (c Config) spfValue() string {
	return "v=spf1 " + c.SPFInclude + " ~all"
}

// dmarcValue starts at p=none: collect reports first, enforce once the reports
// show alignment. Publishing p=reject on day one silently drops real mail.
func (c Config) dmarcValue() string {
	return "v=DMARC1; p=none; rua=mailto:" + c.DMARCReportTo
}

// Records lists everything the domain needs published, with no DNS lookups.
// Statuses are left empty; Verify fills them in.
func (s *Service) Records(ctx context.Context, d *Domain) ([]Record, error) {
	ownershipName, ownershipValue := d.ChallengeRecord()

	records := []Record{
		{
			Type: "TXT", Name: ownershipName, Value: ownershipValue,
			Purpose: PurposeOwnership, Required: true,
		},
		{
			Type: "TXT", Name: d.Domain, Value: s.cfg.spfValue(),
			Purpose: PurposeSPF, Required: true,
		},
	}

	keys, err := s.store.DKIMKeys(ctx, d.ID)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		// Retired keys stay listed: their record must remain published until
		// mail signed with them has been delivered and verified.
		records = append(records, Record{
			Type: "TXT", Name: k.RecordName(d.Domain), Value: k.RecordValue(),
			Purpose: PurposeDKIM, Required: k.RetiredAt == nil,
		})
	}

	records = append(records, Record{
		Type: "TXT", Name: "_dmarc." + d.Domain, Value: s.cfg.dmarcValue(),
		Purpose: PurposeDMARC,
		// Recommended, not required: mail delivers without it, but reputation
		// and reporting are much worse.
		Required: false,
	})

	return records, nil
}

// checkRecord resolves one record and classifies the result.
//
// SPF and DMARC are matched loosely — by their key mechanism rather than the
// exact string — because customers legitimately merge our mechanism into an
// existing policy, and demanding a byte-for-byte match would report a working
// setup as broken.
func (s *Service) checkRecord(ctx context.Context, r Record) Record {
	values, err := s.resolver.LookupTXT(ctx, r.Name)
	if err != nil || len(values) == 0 {
		r.Status = StatusMissing
		return r
	}
	r.Found = values

	for _, raw := range values {
		v := strings.TrimSpace(strings.Trim(raw, `"`))
		switch r.Purpose {
		case PurposeSPF:
			if strings.HasPrefix(strings.ToLower(v), "v=spf1") && strings.Contains(v, s.cfg.SPFInclude) {
				r.Status = StatusOK
				return r
			}
		case PurposeDMARC:
			if strings.HasPrefix(strings.ToLower(v), "v=dmarc1") {
				r.Status = StatusOK
				return r
			}
		default:
			if v == r.Value {
				r.Status = StatusOK
				return r
			}
		}
	}

	r.Status = StatusMismatch
	return r
}

// describeFailure turns a failed ownership check into a message for the UI.
func describeFailure(r Record) string {
	if r.Status == StatusMissing {
		return fmt.Sprintf("no TXT record at %s", r.Name)
	}
	return fmt.Sprintf("TXT %s does not contain the expected value (found %d record(s))",
		r.Name, len(r.Found))
}
