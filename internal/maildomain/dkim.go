package maildomain

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// dkimKeyBits is 2048 because that is what every receiver accepts. 1024 is
// deprecated and widely distrusted; 4096 does not fit in a single 255-character
// TXT string and has to be split, which zone editors routinely get wrong.
const dkimKeyBits = 2048

var ErrNoActiveKey = errors.New("domain has no active DKIM key")

// DKIMKey is one signing key. Several coexist during rotation; exactly one
// signs.
type DKIMKey struct {
	ID        string
	DomainID  string
	Selector  string
	PublicKey string // base64 DER, as it appears in DNS
	IsActive  bool
	CreatedAt time.Time
	RetiredAt *time.Time
}

// RecordName is the host the public key is published at.
func (k DKIMKey) RecordName(domain string) string {
	return k.Selector + "._domainkey." + domain
}

// RecordValue is the TXT payload.
func (k DKIMKey) RecordValue() string {
	return "v=DKIM1; k=rsa; p=" + k.PublicKey
}

// generateDKIM produces a keypair and the selector it will be published under.
// The private key is returned in PKCS#8 DER for the caller to encrypt; it is
// never returned anywhere else.
func generateDKIM(now time.Time) (selector string, publicB64 string, privateDER []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, dkimKeyBits)
	if err != nil {
		return "", "", nil, fmt.Errorf("generate DKIM key: %w", err)
	}

	privateDER, err = x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", nil, err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", nil, err
	}

	// Date plus randomness: readable in a zone file, and two rotations in the
	// same month still get distinct selectors.
	suffix := make([]byte, 3)
	if _, err := rand.Read(suffix); err != nil {
		return "", "", nil, err
	}
	selector = "hm" + now.UTC().Format("200601") + hex.EncodeToString(suffix)

	return selector, base64.StdEncoding.EncodeToString(publicDER), privateDER, nil
}

// ---------------------------------------------------------------- store

const dkimColumns = ` id, domain_id, selector, public_key, is_active, created_at, retired_at`

func scanDKIM(row pgx.Row) (*DKIMKey, error) {
	var k DKIMKey
	err := row.Scan(&k.ID, &k.DomainID, &k.Selector, &k.PublicKey, &k.IsActive, &k.CreatedAt, &k.RetiredAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// CreateDKIMKey stores a key. Only the first key for a domain is active
// immediately; later ones start pending, so signing does not switch to a key
// whose DNS record nobody has published yet.
func (s *Store) CreateDKIMKey(ctx context.Context, domainID, selector, publicKey, sealedPrivate string, active bool) (*DKIMKey, error) {
	return scanDKIM(s.pool.QueryRow(ctx, `
		INSERT INTO dkim_keys (domain_id, selector, public_key, private_key, is_active)
		VALUES ($1, $2, $3, $4, $5) RETURNING`+dkimColumns,
		domainID, selector, publicKey, sealedPrivate, active))
}

// DKIMKeys returns every key for a domain, active first.
func (s *Store) DKIMKeys(ctx context.Context, domainID string) ([]DKIMKey, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT`+dkimColumns+` FROM dkim_keys WHERE domain_id = $1
		 ORDER BY is_active DESC, created_at DESC`, domainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := []DKIMKey{}
	for rows.Next() {
		var k DKIMKey
		if err := rows.Scan(&k.ID, &k.DomainID, &k.Selector, &k.PublicKey,
			&k.IsActive, &k.CreatedAt, &k.RetiredAt); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// ActivateDKIMKey promotes a pending key and retires whatever was signing, in
// one transaction because the partial unique index permits only one active key.
func (s *Store) ActivateDKIMKey(ctx context.Context, domainID, keyID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// The old key keeps its DNS record published; retired only means "stops
	// signing", so mail already in flight still verifies.
	if _, err := tx.Exec(ctx,
		`UPDATE dkim_keys SET is_active = false, retired_at = now()
		 WHERE domain_id = $1 AND is_active AND id <> $2`, domainID, keyID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE dkim_keys SET is_active = true, retired_at = NULL WHERE id = $1`, keyID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// PrivateKey returns the sealed private key for the active signer.
func (s *Store) ActivePrivateKey(ctx context.Context, domainID string) (selector string, sealed string, err error) {
	err = s.pool.QueryRow(ctx,
		`SELECT selector, private_key FROM dkim_keys WHERE domain_id = $1 AND is_active`,
		domainID).Scan(&selector, &sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrNoActiveKey
	}
	return selector, sealed, err
}
