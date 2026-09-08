// Package maildomain owns the mail domains a workspace claims, and the DNS
// challenge that proves it owns them.
package maildomain

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound    = errors.New("domain not found")
	ErrTaken       = errors.New("domain is already claimed")
	ErrValidation  = errors.New("validation failed")
	ErrNotVerified = errors.New("domain is not verified")
)

// challengeHost is the label the ownership TXT record lives under.
const challengeHost = "_heromail-challenge"

// tokenPrefix makes the record recognisable in a zone file full of other
// verification strings.
const tokenPrefix = "heromail-verify="

// namePattern mirrors the CHECK constraint on domains.domain.
var namePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

type Domain struct {
	ID                string
	WorkspaceID       string
	Domain            string
	IsPrimary         bool
	VerificationToken string
	VerifiedAt        *time.Time
	LastCheckedAt     *time.Time
	LastError         *string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

func (d Domain) Verified() bool { return d.VerifiedAt != nil }

// ChallengeRecord is the TXT record the customer must publish.
func (d Domain) ChallengeRecord() (name, value string) {
	return challengeHost + "." + d.Domain, d.VerificationToken
}

// Resolver is the DNS lookup the verifier needs. It is an interface so tests
// can answer without touching the network.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// ---------------------------------------------------------------- store

type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

const columns = ` id, workspace_id, domain, is_primary, verification_token,
	verified_at, last_checked_at, last_error, created_at, updated_at`

func scan(row pgx.Row) (*Domain, error) {
	var d Domain
	err := row.Scan(&d.ID, &d.WorkspaceID, &d.Domain, &d.IsPrimary, &d.VerificationToken,
		&d.VerifiedAt, &d.LastCheckedAt, &d.LastError, &d.CreatedAt, &d.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (s *Store) Create(ctx context.Context, workspaceID, name, token string) (*Domain, error) {
	d, err := scan(s.pool.QueryRow(ctx,
		`INSERT INTO domains (workspace_id, domain, verification_token)
		 VALUES ($1, $2, $3) RETURNING`+columns, workspaceID, name, token))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			// Globally unique: this covers both "already yours" and "someone
			// else's". The caller gets one answer either way, because telling
			// them which would leak another tenant's domains.
			return nil, ErrTaken
		}
		return nil, fmt.Errorf("insert domain: %w", err)
	}
	return d, nil
}

func (s *Store) ListForWorkspace(ctx context.Context, workspaceID string) ([]Domain, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT`+columns+` FROM domains WHERE workspace_id = $1 ORDER BY created_at`, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	domains := []Domain{}
	for rows.Next() {
		var d Domain
		if err := rows.Scan(&d.ID, &d.WorkspaceID, &d.Domain, &d.IsPrimary, &d.VerificationToken,
			&d.VerifiedAt, &d.LastCheckedAt, &d.LastError, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return nil, err
		}
		domains = append(domains, d)
	}
	return domains, rows.Err()
}

// ByName is scoped to the workspace, so another tenant's domain reads as absent.
func (s *Store) ByName(ctx context.Context, workspaceID, name string) (*Domain, error) {
	return scan(s.pool.QueryRow(ctx,
		`SELECT`+columns+` FROM domains WHERE workspace_id = $1 AND domain = $2`, workspaceID, name))
}

// ByNameUnscoped finds a domain without a workspace filter. Domain names are
// globally unique, so the name alone identifies one row.
//
// Only system mail uses it: our own verification codes and reset links are not
// sent on behalf of a tenant, so there is no workspace to scope the lookup to.
// Every tenant-facing path must keep using ByName, or one workspace could read
// another's domain.
func (s *Store) ByNameUnscoped(ctx context.Context, name string) (*Domain, error) {
	return scan(s.pool.QueryRow(ctx,
		`SELECT`+columns+` FROM domains WHERE domain = $1`, name))
}

// RecordCheck stores the outcome of a DNS check. On success it stamps
// verified_at; on failure it records why, leaving any previous verification
// intact — a transient DNS blip must not un-verify a working domain.
func (s *Store) RecordCheck(ctx context.Context, id string, ok bool, reason string) (*Domain, error) {
	if ok {
		return scan(s.pool.QueryRow(ctx, `
			UPDATE domains
			SET verified_at = coalesce(verified_at, now()),
			    last_checked_at = now(), last_error = NULL
			WHERE id = $1 RETURNING`+columns, id))
	}
	return scan(s.pool.QueryRow(ctx, `
		UPDATE domains SET last_checked_at = now(), last_error = $2
		WHERE id = $1 RETURNING`+columns, id, reason))
}

// SetPrimary demotes the current primary and promotes this one in a single
// transaction, because the partial unique index allows only one at a time.
func (s *Store) SetPrimary(ctx context.Context, workspaceID, id string) (*Domain, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`UPDATE domains SET is_primary = false WHERE workspace_id = $1 AND is_primary`,
		workspaceID); err != nil {
		return nil, err
	}
	d, err := scan(tx.QueryRow(ctx,
		`UPDATE domains SET is_primary = true WHERE id = $1 RETURNING`+columns, id))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return d, nil
}

func (s *Store) Delete(ctx context.Context, workspaceID, name string) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM domains WHERE workspace_id = $1 AND domain = $2`, workspaceID, name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------- service

// Sealer encrypts DKIM private keys before they reach the database.
type Sealer interface {
	Seal(plaintext []byte) (string, error)
	Open(encoded string) ([]byte, error)
}

type Service struct {
	store    *Store
	resolver Resolver
	sealer   Sealer
	cfg      Config
}

func NewService(store *Store, resolver Resolver, sealer Sealer, cfg Config) *Service {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return &Service{store: store, resolver: resolver, sealer: sealer, cfg: cfg.withDefaults()}
}

// Add claims a domain, mints its challenge token, and generates its first DKIM
// key.
//
// The key is created up front so the customer publishes every record in one
// visit to their DNS provider. Making them come back later for DKIM is how
// domains end up half-configured.
func (s *Service) Add(ctx context.Context, workspaceID, name string) (*Domain, error) {
	name = Normalise(name)
	if !namePattern.MatchString(name) || len(name) > 253 {
		return nil, fmt.Errorf("%w: %q is not a valid domain name", ErrValidation, name)
	}

	token, err := newToken()
	if err != nil {
		return nil, err
	}

	d, err := s.store.Create(ctx, workspaceID, name, token)
	if err != nil {
		return nil, err
	}

	if _, err := s.generateKey(ctx, d.ID, true); err != nil {
		return nil, fmt.Errorf("generate initial DKIM key for %s: %w", name, err)
	}
	return d, nil
}

// generateKey creates a keypair, seals the private half and stores both.
func (s *Service) generateKey(ctx context.Context, domainID string, active bool) (*DKIMKey, error) {
	selector, publicKey, privateDER, err := generateDKIM(time.Now())
	if err != nil {
		return nil, err
	}

	sealed, err := s.sealer.Seal(privateDER)
	if err != nil {
		return nil, fmt.Errorf("seal private key: %w", err)
	}
	// privateDER is not zeroed here: Go's GC may already have copied it. Real
	// protection would need a locked buffer, which is out of proportion to the
	// exposure of a short-lived heap value in this process.
	return s.store.CreateDKIMKey(ctx, domainID, selector, publicKey, sealed, active)
}

// RotateDKIM mints a replacement key in the pending state.
//
// It does not start signing yet: the record has to reach DNS first, or every
// message sent in the gap fails DKIM. Verify promotes it once the record
// resolves, which is why rotation is two steps and not one.
func (s *Service) RotateDKIM(ctx context.Context, workspaceID, name string) (*Domain, error) {
	d, err := s.store.ByName(ctx, workspaceID, Normalise(name))
	if err != nil {
		return nil, err
	}
	if _, err := s.generateKey(ctx, d.ID, false); err != nil {
		return nil, err
	}
	return d, nil
}

func (s *Service) List(ctx context.Context, workspaceID string) ([]Domain, error) {
	return s.store.ListForWorkspace(ctx, workspaceID)
}

func (s *Service) Get(ctx context.Context, workspaceID, name string) (*Domain, error) {
	return s.store.ByName(ctx, workspaceID, Normalise(name))
}

func (s *Service) Delete(ctx context.Context, workspaceID, name string) error {
	return s.store.Delete(ctx, workspaceID, Normalise(name))
}

// Verify reconciles the domain against DNS: it checks every expected record,
// records the ownership outcome, and promotes a pending DKIM key whose record
// has appeared.
//
// A record that is missing is a normal outcome, not an error. The caller gets
// the domain and per-record statuses back, which is what the settings page
// renders.
func (s *Service) Verify(ctx context.Context, workspaceID, name string) (*Domain, []Record, error) {
	d, err := s.store.ByName(ctx, workspaceID, Normalise(name))
	if err != nil {
		return nil, nil, err
	}

	expected, err := s.Records(ctx, d)
	if err != nil {
		return nil, nil, err
	}

	checked := make([]Record, 0, len(expected))
	for _, r := range expected {
		checked = append(checked, s.checkRecord(ctx, r))
	}

	// Ownership is what gates the domain being usable at all, so it is the one
	// outcome persisted on the row.
	for _, r := range checked {
		if r.Purpose != PurposeOwnership {
			continue
		}
		if r.Status == StatusOK {
			d, err = s.store.RecordCheck(ctx, d.ID, true, "")
		} else {
			d, err = s.store.RecordCheck(ctx, d.ID, false, describeFailure(r))
		}
		if err != nil {
			return nil, nil, err
		}
	}

	if err := s.promotePendingKey(ctx, d, checked); err != nil {
		return nil, nil, err
	}
	return d, checked, nil
}

// promotePendingKey activates a rotated key once its record resolves, retiring
// the one that was signing.
func (s *Service) promotePendingKey(ctx context.Context, d *Domain, checked []Record) error {
	keys, err := s.store.DKIMKeys(ctx, d.ID)
	if err != nil {
		return err
	}

	published := map[string]bool{}
	for _, r := range checked {
		if r.Purpose == PurposeDKIM && r.Status == StatusOK {
			published[r.Name] = true
		}
	}

	for _, k := range keys {
		if k.IsActive || k.RetiredAt != nil {
			continue
		}
		if published[k.RecordName(d.Domain)] {
			return s.store.ActivateDKIMKey(ctx, d.ID, k.ID)
		}
	}
	return nil
}

// SigningKey returns the active selector and decrypted private key, for the
// component that signs outbound mail.
func (s *Service) SigningKey(ctx context.Context, domainID string) (selector string, privateDER []byte, err error) {
	selector, sealed, err := s.store.ActivePrivateKey(ctx, domainID)
	if err != nil {
		return "", nil, err
	}
	privateDER, err = s.sealer.Open(sealed)
	if err != nil {
		return "", nil, fmt.Errorf("open DKIM private key for %s: %w", selector, err)
	}
	return selector, privateDER, nil
}

// SigningKeyForDomain resolves the active DKIM key for the domain a message
// claims to be From, scoped to the workspace sending it. It exists for the
// worker: given a From address, sign with whatever key the sending
// workspace has proven ownership of — or don't, and let the caller decide
// what that means.
//
// Returns ErrNotFound if the workspace never claimed the domain, and
// ErrNotVerified if it has not proven ownership yet. Neither is a failure
// worth stopping delivery over: sending From a domain nobody verified is
// already allowed today, DKIM or not.
func (s *Service) SigningKeyForDomain(ctx context.Context, workspaceID, domainName string) (selector string, privateDER []byte, err error) {
	d, err := s.store.ByName(ctx, workspaceID, Normalise(domainName))
	if err != nil {
		return "", nil, err
	}
	if !d.Verified() {
		return "", nil, ErrNotVerified
	}
	return s.SigningKey(ctx, d.ID)
}

// AllowsSender reports whether the workspace has claimed this domain and
// proven it owns it.
//
// Deliberately not the DKIM lookup: a domain can be verified and still have no
// active signing key, and "may they send as this" is a question about
// ownership, not about whether we can sign. Conflating them refuses mail from
// a domain the workspace demonstrably owns.
func (s *Service) AllowsSender(ctx context.Context, workspaceID, domainName string) error {
	d, err := s.store.ByName(ctx, workspaceID, Normalise(domainName))
	if err != nil {
		return err
	}
	if !d.Verified() {
		return ErrNotVerified
	}
	return nil
}

// SystemSigningKey resolves the active DKIM key for a domain we send our own
// mail from, without reference to a workspace — see ByNameUnscoped.
//
// Same contract as SigningKeyForDomain: ErrNotFound and ErrNotVerified mean
// "send unsigned", anything else is a real failure.
func (s *Service) SystemSigningKey(ctx context.Context, domainName string) (selector string, privateDER []byte, err error) {
	d, err := s.store.ByNameUnscoped(ctx, Normalise(domainName))
	if err != nil {
		return "", nil, err
	}
	if !d.Verified() {
		return "", nil, ErrNotVerified
	}
	return s.SigningKey(ctx, d.ID)
}

// SetPrimary makes a verified domain the workspace default.
func (s *Service) SetPrimary(ctx context.Context, workspaceID, name string) (*Domain, error) {
	d, err := s.store.ByName(ctx, workspaceID, Normalise(name))
	if err != nil {
		return nil, err
	}
	if !d.Verified() {
		// The database would refuse this anyway; failing here gives a usable
		// message instead of a constraint violation.
		return nil, fmt.Errorf("%w: verify %s before making it primary", ErrNotVerified, d.Domain)
	}
	return s.store.SetPrimary(ctx, workspaceID, d.ID)
}

// Normalise lowercases and trims, including a trailing dot from a copied FQDN.
func Normalise(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func newToken() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return tokenPrefix + hex.EncodeToString(raw), nil
}
