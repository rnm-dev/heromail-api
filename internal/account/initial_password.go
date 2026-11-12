package account

import (
	"bytes"
	"context"
	"errors"
	"fmt"
)

var ErrPasswordAlreadyChanged = errors.New("initial password already replaced")

// The flag, password and session revocation change in the same transaction.
func (s *Service) ChangeInitialPassword(ctx context.Context, userID, current, password string, rc RequestContext) (*Credentials, error) {
	if current == password {
		return nil, fmt.Errorf("%w: новый пароль должен отличаться от начального", ErrValidation)
	}
	return s.replacePassword(ctx, userID, current, password, true, rc)
}

// ChangePassword replaces a known password from an ordinary session. Other
// sessions are revoked so a leaked password stops working everywhere.
func (s *Service) ChangePassword(ctx context.Context, userID, current, password string, rc RequestContext) (*Credentials, error) {
	if current == password {
		return nil, fmt.Errorf("%w: новый пароль должен отличаться от текущего", ErrValidation)
	}
	return s.replacePassword(ctx, userID, current, password, false, rc)
}

func (s *Service) replacePassword(ctx context.Context, userID, current, password string, initial bool, rc RequestContext) (*Credentials, error) {
	hash, err := hashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrValidation, err)
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var required bool
	if err = tx.QueryRow(ctx, `SELECT must_change_password FROM users WHERE id=$1 FOR UPDATE`, userID).Scan(&required); err != nil {
		return nil, err
	}
	if initial && !required {
		return nil, ErrPasswordAlreadyChanged
	}
	var old string
	if err = tx.QueryRow(ctx, `SELECT password_hash FROM identities WHERE user_id=$1 AND provider='password' FOR UPDATE`, userID).Scan(&old); err != nil {
		return nil, err
	}
	if !verifyPassword([]byte(old), current) {
		return nil, ErrCredentials
	}
	if _, err = tx.Exec(ctx, `UPDATE identities SET password_hash=$2 WHERE user_id=$1 AND provider='password'`, userID, string(hash)); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `UPDATE users SET must_change_password=false WHERE id=$1`, userID); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, userID); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM user_tokens WHERE user_id=$1 AND purpose='password_reset'`, userID); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	user, err := s.store.UserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return s.startSession(ctx, user, rc)
}

// Password verification and session creation cannot straddle a password change.
func (s *Service) startPasswordSession(ctx context.Context, userID string, verifiedHash []byte, rc RequestContext) (*Credentials, error) {
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	user, err := scanUser(tx.QueryRow(ctx, `SELECT`+userColumns+` FROM users WHERE id=$1 FOR UPDATE`, userID))
	if err != nil {
		return nil, err
	}
	var current string
	if err = tx.QueryRow(ctx, `SELECT password_hash FROM identities WHERE user_id=$1 AND provider='password'`, userID).Scan(&current); err != nil {
		return nil, err
	}
	if !bytes.Equal([]byte(current), verifiedHash) {
		return nil, ErrCredentials
	}
	creds, err := insertSession(ctx, tx, user, rc)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return creds, nil
}
