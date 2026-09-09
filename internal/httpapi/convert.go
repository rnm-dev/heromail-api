package httpapi

import (
	"context"
	"log"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/auth"
	"github.com/rnm/heromail/backend/internal/email"
	"github.com/rnm/heromail/backend/internal/maildomain"
	"github.com/rnm/heromail/backend/internal/workspace"
)

// Conversions between domain types and the generated wire types. Keeping them
// here means the domain packages never import generated code, so regenerating
// the spec cannot ripple into business logic.

func userToAPI(u *account.User) User {
	return User{
		Id:                 mustUUID(u.ID),
		Email:              openapi_types.Email(u.Email),
		Name:               u.Name,
		EmailVerified:      u.EmailVerified(),
		MustChangePassword: u.MustChangePassword,
		EmailVerifiedAt:    u.EmailVerifiedAt,
		CreatedAt:          u.CreatedAt,
		UpdatedAt:          u.UpdatedAt,
	}
}

func credentialsToAPI(c *account.Credentials) Credentials {
	return Credentials{
		Token:     c.Token,
		User:      userToAPI(c.User),
		ExpiresAt: c.ExpiresAt,
	}
}

func workspaceToAPI(w *workspace.Workspace) Workspace {
	return Workspace{
		Personal:  &w.Personal,
		Id:        mustUUID(w.ID),
		Slug:      w.Slug,
		Name:      w.Name,
		CreatedAt: w.CreatedAt,
		UpdatedAt: w.UpdatedAt,
	}
}

// domainToAPI renders a domain plus the records it needs published. The
// records are computed from the domain, its token and its DKIM keys rather
// than stored, so there is nothing that can fall out of sync.
func domainToAPI(d *maildomain.Domain, records []maildomain.Record) Domain {
	out := make([]DnsRecord, 0, len(records))
	for _, r := range records {
		required := r.Required
		rec := DnsRecord{
			Type:     r.Type,
			Name:     r.Name,
			Value:    r.Value,
			Purpose:  DnsRecordPurpose(r.Purpose),
			Required: &required,
		}
		// Status and Found are only meaningful after a check.
		if r.Status != "" {
			status := DnsRecordStatus(r.Status)
			rec.Status = &status
		}
		if len(r.Found) > 0 {
			found := r.Found
			rec.Found = &found
		}
		out = append(out, rec)
	}

	return Domain{
		Id:            mustUUID(d.ID),
		WorkspaceId:   mustUUID(d.WorkspaceID),
		Domain:        DomainName(d.Domain),
		IsPrimary:     d.IsPrimary,
		Verified:      d.Verified(),
		VerifiedAt:    d.VerifiedAt,
		DnsRecords:    out,
		LastCheckedAt: d.LastCheckedAt,
		LastError:     d.LastError,
		CreatedAt:     d.CreatedAt,
		UpdatedAt:     d.UpdatedAt,
	}
}

func emailToAPI(e *email.Email, attachments []email.Attachment) Email {
	to := make([]openapi_types.Email, 0, len(e.ToAddrs))
	for _, addr := range e.ToAddrs {
		to = append(to, openapi_types.Email(addr))
	}

	out := Email{
		Id:                mustUUID(e.ID),
		WorkspaceId:       mustUUID(e.WorkspaceID),
		From:              openapi_types.Email(e.FromAddr),
		To:                to,
		Cc:                apiEmailAddresses(e.CcAddrs),
		Bcc:               apiEmailAddresses(e.BccAddrs),
		Subject:           e.Subject,
		Html:              e.HTMLBody,
		Text:              e.TextBody,
		Status:            EmailStatus(e.Status),
		ProviderMessageId: e.ProviderMessageID,
		IdempotencyKey:    e.IdempotencyKey,
		Attempts:          e.Attempts,
		LastError:         e.LastError,
		CreatedAt:         e.CreatedAt,
		UpdatedAt:         e.UpdatedAt,
	}
	if len(attachments) > 0 {
		list := make([]Attachment, 0, len(attachments))
		for i := range attachments {
			list = append(list, attachmentToAPI(&attachments[i]))
		}
		out.Attachments = &list
	}
	return out
}

func attachmentToAPI(a *email.Attachment) Attachment {
	return Attachment{
		Id:          mustUUID(a.ID),
		Filename:    a.Filename,
		ContentType: a.ContentType,
		SizeBytes:   a.SizeBytes,
		CreatedAt:   a.CreatedAt,
	}
}

// mustUUID parses an id that came out of Postgres, where the column type
// already guarantees it is a UUID. A failure here means the row was not what
// the schema says it is, so log it and hand back the zero value rather than
// failing the whole response.
func mustUUID(s string) openapi_types.UUID {
	id, err := uuid.Parse(s)
	if err != nil {
		log.Printf("httpapi: %q is not a UUID, which should be impossible: %v", s, err)
		return openapi_types.UUID{}
	}
	return id
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// workspaceIDFrom reads the workspace the API key middleware resolved.
func workspaceIDFrom(ctx context.Context) (string, bool) {
	return auth.WorkspaceID(ctx)
}

// requestContextFrom carries the browser details the session store records.
// The strict handler hands operations a context rather than the request, so
// the router stashes them on the way in.
func requestContextFrom(ctx context.Context) account.RequestContext {
	rc, _ := ctx.Value(requestContextKey).(account.RequestContext)
	return rc
}

func emailAddresses(values *[]openapi_types.Email) []string {
	if values == nil {
		return nil
	}
	out := make([]string, len(*values))
	for i, v := range *values {
		out[i] = string(v)
	}
	return out
}
func apiEmailAddresses(values []string) *[]openapi_types.Email {
	out := make([]openapi_types.Email, len(values))
	for i, v := range values {
		out[i] = openapi_types.Email(v)
	}
	return &out
}
