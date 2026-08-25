package main

import "time"

// Role mirrors the workspace_role enum in Postgres.
type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
)

// rank orders roles by privilege, so permission checks can compare them
// instead of enumerating cases.
func (r Role) rank() int {
	switch r {
	case RoleOwner:
		return 3
	case RoleAdmin:
		return 2
	case RoleMember:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether r carries at least the privileges of min.
func (r Role) AtLeast(min Role) bool { return r.rank() >= min.rank() }

func (r Role) Valid() bool { return r.rank() > 0 }

// Workspace is a tenant: one company. Its mail domains live in Domain.
type Workspace struct {
	ID        string    `json:"id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// DomainStatus is derived from verified_at, not stored.
type DomainStatus string

const (
	DomainPending  DomainStatus = "pending"
	DomainVerified DomainStatus = "verified"
)

// Domain is a mail domain owned by a workspace, e.g. acme.com. Ownership is
// proven by publishing VerificationToken as a DNS TXT record.
type Domain struct {
	ID          string `json:"id"`
	WorkspaceID string `json:"workspace_id"`
	Domain      string `json:"domain"`
	IsPrimary   bool   `json:"is_primary"`
	// Public by design — shown to the admin so they can paste it into DNS.
	VerificationToken string     `json:"verification_token"`
	VerifiedAt        *time.Time `json:"verified_at"`
	LastCheckedAt     *time.Time `json:"last_checked_at"`
	LastError         *string    `json:"last_error"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

func (d Domain) Status() DomainStatus {
	if d.VerifiedAt != nil {
		return DomainVerified
	}
	return DomainPending
}

// DKIMKey signs outbound mail for a domain. Several keys coexist during
// rotation; exactly one is active.
type DKIMKey struct {
	ID        string     `json:"id"`
	DomainID  string     `json:"domain_id"`
	Selector  string     `json:"selector"`
	PublicKey string     `json:"public_key"`
	IsActive  bool       `json:"is_active"`
	CreatedAt time.Time  `json:"created_at"`
	RetiredAt *time.Time `json:"retired_at"`
	// privateKey stays unexported: it must never be serialised to a client.
	privateKey string
}

// User is a global identity, shared across every workspace they belong to.
type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	// passwordHash is deliberately unexported so it cannot leak through JSON.
	passwordHash *string
}

// Member binds a user to a workspace with a role.
type Member struct {
	WorkspaceID string    `json:"workspace_id"`
	UserID      string    `json:"user_id"`
	Role        Role      `json:"role"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// InviteStatus is derived from the invite's timestamps rather than stored.
type InviteStatus string

const (
	InvitePending  InviteStatus = "pending"
	InviteAccepted InviteStatus = "accepted"
	InviteRevoked  InviteStatus = "revoked"
	InviteExpired  InviteStatus = "expired"
)

// Invite offers an email address a seat in a workspace at a given role.
type Invite struct {
	ID          string     `json:"id"`
	WorkspaceID string     `json:"workspace_id"`
	Email       string     `json:"email"`
	Role        Role       `json:"role"`
	InvitedBy   *string    `json:"invited_by"`
	ExpiresAt   time.Time  `json:"expires_at"`
	AcceptedAt  *time.Time `json:"accepted_at"`
	AcceptedBy  *string    `json:"accepted_by"`
	RevokedAt   *time.Time `json:"revoked_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

// Status resolves the invite's current state. Revoked and accepted are terminal
// and take precedence over expiry.
func (i Invite) Status(now time.Time) InviteStatus {
	switch {
	case i.AcceptedAt != nil:
		return InviteAccepted
	case i.RevokedAt != nil:
		return InviteRevoked
	case now.After(i.ExpiresAt):
		return InviteExpired
	default:
		return InvitePending
	}
}
