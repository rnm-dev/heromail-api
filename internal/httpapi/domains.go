package httpapi

import (
	"context"
	"errors"
	"log"

	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/maildomain"
	"github.com/rnm/heromail/backend/internal/workspace"
)

// scope resolves the workspace behind a slug and the caller's role in it.
//
// It returns two distinct failures on purpose: a workspace the caller cannot
// see is a 404 (they must not learn it exists), while one they can see but may
// not change is a 403.
func (s *Server) scope(ctx context.Context, slug string, minRole workspace.Role) (workspaceID string, forbidden bool, err error) {
	user, ok := account.CurrentUser(ctx)
	if !ok {
		return "", false, workspace.ErrNotFound
	}

	ws, err := s.workspaces.BySlugForUser(ctx, user.ID, slug)
	if err != nil {
		return "", false, err
	}

	role, err := s.workspaces.MembershipRole(ctx, ws.ID, user.ID)
	if err != nil {
		return "", false, err
	}
	if !role.AtLeast(minRole) {
		return ws.ID, true, nil
	}
	return ws.ID, false, nil
}

func (s *Server) ListDomains(ctx context.Context, request ListDomainsRequestObject) (ListDomainsResponseObject, error) {
	workspaceID, _, err := s.scope(ctx, request.Slug, workspace.RoleMember)
	if errors.Is(err, workspace.ErrNotFound) {
		return ListDomains404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "workspace not found"))}, nil
	}
	if err != nil {
		log.Printf("list domains: %v", err)
		return nil, err
	}

	domains, err := s.domains.List(ctx, workspaceID)
	if err != nil {
		log.Printf("list domains: %v", err)
		return nil, err
	}

	out := make([]Domain, 0, len(domains))
	for i := range domains {
		records, err := s.domains.Records(ctx, &domains[i])
		if err != nil {
			log.Printf("list domains: records for %s: %v", domains[i].Domain, err)
			return nil, err
		}
		out = append(out, domainToAPI(&domains[i], records))
	}
	return ListDomains200JSONResponse{Domains: out}, nil
}

func (s *Server) AddDomain(ctx context.Context, request AddDomainRequestObject) (AddDomainResponseObject, error) {
	workspaceID, forbidden, err := s.scope(ctx, request.Slug, workspace.RoleAdmin)
	switch {
	case errors.Is(err, workspace.ErrNotFound):
		return AddDomain404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "workspace not found"))}, nil
	case err != nil:
		log.Printf("add domain: %v", err)
		return nil, err
	case forbidden:
		return AddDomain403JSONResponse{ForbiddenJSONResponse(errorBody("forbidden", "adding a domain requires the admin role"))}, nil
	}
	if request.Body == nil {
		return AddDomain400JSONResponse{BadRequestJSONResponse(errorBody("invalid_json", "a JSON body is required"))}, nil
	}

	d, err := s.domains.Add(ctx, workspaceID, string(request.Body.Domain))
	switch {
	case errors.Is(err, maildomain.ErrValidation):
		return AddDomain400JSONResponse{BadRequestJSONResponse(errorBody("validation_failed", err.Error()))}, nil
	case errors.Is(err, maildomain.ErrTaken):
		return AddDomain409JSONResponse(errorBody("domain_taken", "this domain is already claimed")), nil
	case err != nil:
		log.Printf("add domain: %v", err)
		return nil, err
	}
	return AddDomain201JSONResponse(s.describe(ctx, d)), nil
}

func (s *Server) GetDomain(ctx context.Context, request GetDomainRequestObject) (GetDomainResponseObject, error) {
	workspaceID, _, err := s.scope(ctx, request.Slug, workspace.RoleMember)
	if errors.Is(err, workspace.ErrNotFound) {
		return GetDomain404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "workspace not found"))}, nil
	}
	if err != nil {
		log.Printf("get domain: %v", err)
		return nil, err
	}

	d, err := s.domains.Get(ctx, workspaceID, string(request.Domain))
	if errors.Is(err, maildomain.ErrNotFound) {
		return GetDomain404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "domain not found"))}, nil
	}
	if err != nil {
		log.Printf("get domain: %v", err)
		return nil, err
	}
	return GetDomain200JSONResponse(s.describe(ctx, d)), nil
}

func (s *Server) VerifyDomain(ctx context.Context, request VerifyDomainRequestObject) (VerifyDomainResponseObject, error) {
	workspaceID, forbidden, err := s.scope(ctx, request.Slug, workspace.RoleAdmin)
	switch {
	case errors.Is(err, workspace.ErrNotFound):
		return VerifyDomain404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "workspace not found"))}, nil
	case err != nil:
		log.Printf("verify domain: %v", err)
		return nil, err
	case forbidden:
		return VerifyDomain403JSONResponse{ForbiddenJSONResponse(errorBody("forbidden", "verifying a domain requires the admin role"))}, nil
	}

	// A DNS check that finds nothing is a 200 with last_error set, not a 4xx:
	// the request succeeded, the answer is just "not yet".
	d, records, err := s.domains.Verify(ctx, workspaceID, string(request.Domain))
	if errors.Is(err, maildomain.ErrNotFound) {
		return VerifyDomain404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "domain not found"))}, nil
	}
	if err != nil {
		log.Printf("verify domain: %v", err)
		return nil, err
	}
	return VerifyDomain200JSONResponse(domainToAPI(d, records)), nil
}

func (s *Server) UpdateDomain(ctx context.Context, request UpdateDomainRequestObject) (UpdateDomainResponseObject, error) {
	workspaceID, forbidden, err := s.scope(ctx, request.Slug, workspace.RoleAdmin)
	switch {
	case errors.Is(err, workspace.ErrNotFound):
		return UpdateDomain404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "workspace not found"))}, nil
	case err != nil:
		log.Printf("update domain: %v", err)
		return nil, err
	case forbidden:
		return UpdateDomain403JSONResponse{ForbiddenJSONResponse(errorBody("forbidden", "changing a domain requires the admin role"))}, nil
	}
	if request.Body == nil {
		return UpdateDomain400JSONResponse{BadRequestJSONResponse(errorBody("invalid_json", "a JSON body is required"))}, nil
	}
	if !request.Body.IsPrimary {
		return UpdateDomain400JSONResponse{BadRequestJSONResponse(errorBody("validation_failed",
			"only is_primary=true is meaningful; promote another domain instead of demoting this one"))}, nil
	}

	d, err := s.domains.SetPrimary(ctx, workspaceID, string(request.Domain))
	switch {
	case errors.Is(err, maildomain.ErrNotFound):
		return UpdateDomain404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "domain not found"))}, nil
	case errors.Is(err, maildomain.ErrNotVerified):
		return UpdateDomain400JSONResponse{BadRequestJSONResponse(errorBody("not_verified", err.Error()))}, nil
	case err != nil:
		log.Printf("update domain: %v", err)
		return nil, err
	}
	return UpdateDomain200JSONResponse(s.describe(ctx, d)), nil
}

func (s *Server) DeleteDomain(ctx context.Context, request DeleteDomainRequestObject) (DeleteDomainResponseObject, error) {
	workspaceID, forbidden, err := s.scope(ctx, request.Slug, workspace.RoleAdmin)
	switch {
	case errors.Is(err, workspace.ErrNotFound):
		return DeleteDomain404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "workspace not found"))}, nil
	case err != nil:
		log.Printf("delete domain: %v", err)
		return nil, err
	case forbidden:
		return DeleteDomain403JSONResponse{ForbiddenJSONResponse(errorBody("forbidden", "removing a domain requires the admin role"))}, nil
	}

	err = s.domains.Delete(ctx, workspaceID, string(request.Domain))
	if errors.Is(err, maildomain.ErrNotFound) {
		return DeleteDomain404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "domain not found"))}, nil
	}
	if err != nil {
		log.Printf("delete domain: %v", err)
		return nil, err
	}
	return DeleteDomain204Response{}, nil
}

// describe renders a domain with its expected records, and no DNS lookups.
// A failure to load the records is logged and swallowed: the domain itself is
// still worth returning, and the settings page degrades to showing no records
// rather than an error page.
func (s *Server) describe(ctx context.Context, d *maildomain.Domain) Domain {
	records, err := s.domains.Records(ctx, d)
	if err != nil {
		log.Printf("records for %s: %v", d.Domain, err)
	}
	return domainToAPI(d, records)
}

func (s *Server) RotateDkimKey(ctx context.Context, request RotateDkimKeyRequestObject) (RotateDkimKeyResponseObject, error) {
	workspaceID, forbidden, err := s.scope(ctx, request.Slug, workspace.RoleAdmin)
	switch {
	case errors.Is(err, workspace.ErrNotFound):
		return RotateDkimKey404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "workspace not found"))}, nil
	case err != nil:
		log.Printf("rotate dkim: %v", err)
		return nil, err
	case forbidden:
		return RotateDkimKey403JSONResponse{ForbiddenJSONResponse(errorBody("forbidden", "rotating a DKIM key requires the admin role"))}, nil
	}

	d, err := s.domains.RotateDKIM(ctx, workspaceID, string(request.Domain))
	if errors.Is(err, maildomain.ErrNotFound) {
		return RotateDkimKey404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "domain not found"))}, nil
	}
	if err != nil {
		log.Printf("rotate dkim: %v", err)
		return nil, err
	}
	return RotateDkimKey200JSONResponse(s.describe(ctx, d)), nil
}
