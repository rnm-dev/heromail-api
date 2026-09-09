// Package account handles human authentication: registration, sign-in,
// sessions and email verification.
//
// It is deliberately separate from internal/auth, which authenticates machines
// by API key. The two have different subjects, lifetimes and revocation
// stories, and folding them together is a mistake that is expensive to undo.
package account

import (
	"encoding/json"
	"time"
)

// Provider mirrors the identity_provider enum. Password is the only one
// implemented today; the rest are the shape the model was built for.
type Provider string

const (
	ProviderPassword  Provider = "password"
	ProviderGoogle    Provider = "google"
	ProviderMicrosoft Provider = "microsoft"
	ProviderOIDC      Provider = "oidc"
	ProviderSAML      Provider = "saml"
	ProviderLDAP      Provider = "ldap"
)

// User is a person. Identities are how they sign in; a user may have several.
type User struct {
	MustChangePassword bool       `json:"must_change_password"`
	ID                 string     `json:"id"`
	Email              string     `json:"email"`
	Name               string     `json:"name"`
	EmailVerifiedAt    *time.Time `json:"email_verified_at"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// EmailVerified is the flag the UI actually wants.
func (u User) EmailVerified() bool { return u.EmailVerifiedAt != nil }

// MarshalJSON adds the derived flag without storing it.
func (u User) MarshalJSON() ([]byte, error) {
	type alias User // avoid recursing into this method
	return json.Marshal(struct {
		alias
		EmailVerified bool `json:"email_verified"`
	}{alias(u), u.EmailVerified()})
}

// Identity is one way a user can authenticate.
type Identity struct {
	ID          string          `json:"id"`
	UserID      string          `json:"user_id"`
	Provider    Provider        `json:"provider"`
	Subject     string          `json:"subject"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
	LastLoginAt *time.Time      `json:"last_login_at"`
	CreatedAt   time.Time       `json:"created_at"`
}

// ExternalIdentity is what an SSO callback produces once it has verified the
// provider's assertion. Wiring Google, Entra ID or a customer's OIDC amounts
// to building one of these and calling Service.SignInWithIdentity — no other
// layer needs to change.
type ExternalIdentity struct {
	Provider Provider
	// Subject is the provider's stable id (OIDC `sub`, SAML NameID, AD GUID).
	Subject string
	Email   string
	Name    string
	// EmailVerified reports whether the provider vouches for the address.
	// Google and Entra do; a bare LDAP bind does not.
	EmailVerified bool
	Metadata      json.RawMessage
}

// Session is a signed-in browser.
type Session struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	UserAgent  *string    `json:"user_agent,omitempty"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// TokenPurpose mirrors the user_token_purpose enum.
type TokenPurpose string

const (
	PurposeEmailVerification TokenPurpose = "email_verification"
	PurposePasswordReset     TokenPurpose = "password_reset"
)
