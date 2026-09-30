package httpapi

import (
	"context"
	"errors"
	"net/mail"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/workspace"
)

func (s *Server) memberScope(ctx context.Context, slug string) (string, int, Error, error) {
	id, forbidden, err := s.scope(ctx, slug, workspace.RoleOwner)
	if errors.Is(err, workspace.ErrNotFound) {
		return "", 404, errorBody("not_found", "workspace not found"), nil
	}
	if err != nil {
		return "", 0, Error{}, err
	}
	if forbidden {
		return "", 403, errorBody("forbidden", "only the workspace owner can manage users"), nil
	}
	var personal bool
	if err := s.pool.QueryRow(ctx, `SELECT personal_owner_id IS NOT NULL FROM workspaces WHERE id=$1`, id).Scan(&personal); err != nil {
		return "", 0, Error{}, err
	}
	if personal {
		return "", 403, errorBody("personal_workspace", "Личный ящик доступен только владельцу; управление участниками отключено."), nil
	}
	return id, 0, Error{}, nil
}

func (s *Server) members(ctx context.Context, id string) (MemberList, error) {
	rows, err := s.pool.Query(ctx, `SELECT u.id, u.email, u.name, m.role FROM workspace_members m JOIN users u ON u.id=m.user_id WHERE m.workspace_id=$1 ORDER BY m.created_at, u.id`, id)
	if err != nil {
		return MemberList{}, err
	}
	defer rows.Close()
	out := MemberList{Members: []Member{}}
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.Id, &m.Email, &m.Name, &m.Role); err != nil {
			return out, err
		}
		out.Members = append(out.Members, m)
	}
	return out, rows.Err()
}

func (s *Server) ListMembers(ctx context.Context, r ListMembersRequestObject) (ListMembersResponseObject, error) {
	id, status, body, err := s.memberScope(ctx, r.Slug)
	if err != nil {
		return nil, err
	}
	if status != 0 {
		return ListMembersdefaultJSONResponse{StatusCode: status, Body: body}, nil
	}
	out, err := s.members(ctx, id)
	return ListMembers200JSONResponse(out), err
}

func (s *Server) AddMember(ctx context.Context, r AddMemberRequestObject) (AddMemberResponseObject, error) {
	id, status, body, err := s.memberScope(ctx, r.Slug)
	fail := func(code int, message string) (AddMemberResponseObject, error) {
		return AddMemberdefaultJSONResponse{StatusCode: code, Body: errorBody("member_error", message)}, nil
	}
	if err != nil {
		return nil, err
	}
	if status != 0 {
		return AddMemberdefaultJSONResponse{StatusCode: status, Body: body}, nil
	}
	if r.Body == nil {
		return fail(400, "email and role are required")
	}
	email := strings.TrimSpace(r.Body.Email)
	parsed, e := mail.ParseAddress(email)
	role := string(r.Body.Role)
	if e != nil || parsed.Address != email || (role != "admin" && role != "member") {
		return fail(400, "provide a valid email and admin or member role")
	}
	var userID string
	err = s.pool.QueryRow(ctx, `SELECT id FROM users WHERE email=$1`, email).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return fail(404, "No account with this email. Ask the user to register first.")
	}
	if err != nil {
		return nil, err
	}
	result, err := s.pool.Exec(ctx, `INSERT INTO workspace_members(workspace_id,user_id,role) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, id, userID, role)
	if err != nil {
		return nil, err
	}
	if result.RowsAffected() == 0 {
		return fail(409, "this user is already a workspace member")
	}
	out, err := s.members(ctx, id)
	return AddMember201JSONResponse(out), err
}

func (s *Server) ProvisionWorkspaceUser(ctx context.Context, r ProvisionWorkspaceUserRequestObject) (ProvisionWorkspaceUserResponseObject, error) {
	id, status, body, err := s.memberScope(ctx, r.Slug)
	if err != nil {
		return nil, err
	}
	if status != 0 {
		return ProvisionWorkspaceUserdefaultJSONResponse{StatusCode: status, Body: body}, nil
	}
	fail := func(code int, errorCode, message string) (ProvisionWorkspaceUserResponseObject, error) {
		return ProvisionWorkspaceUserdefaultJSONResponse{StatusCode: code, Body: errorBody(errorCode, message)}, nil
	}
	if r.Body == nil {
		return fail(400, "validation_failed", "name and email are required")
	}
	name := strings.TrimSpace(r.Body.Name)
	email := strings.ToLower(strings.TrimSpace(string(r.Body.Email)))
	parsed, parseErr := mail.ParseAddress(email)
	local, domain, ok := strings.Cut(email, "@")
	if name == "" || len([]rune(name)) > 200 || parseErr != nil || parsed.Address != email || !ok || local == "" || domain == "" {
		return fail(400, "validation_failed", "provide a name and valid workspace email address")
	}
	user, password, err := s.accounts.ProvisionWorkspaceUser(ctx, account.ProvisionWorkspaceUserRequest{
		WorkspaceID: id, Email: email, Name: name, LocalPart: local, Domain: domain,
	})
	switch {
	case errors.Is(err, account.ErrEmailTaken):
		return fail(409, "email_taken", "an account with this email already exists")
	case errors.Is(err, account.ErrAddressTaken):
		return fail(409, "address_taken", "that mailbox address already exists")
	case errors.Is(err, account.ErrDomainInvalid):
		return fail(400, "domain_not_verified", "choose an address under a verified workspace domain")
	case err != nil:
		return nil, err
	}
	return ProvisionWorkspaceUser201JSONResponse{
		User:              Member{Id: uuid.MustParse(user.ID), Email: user.Email, Name: user.Name, Role: RoleMember},
		TemporaryPassword: &password,
	}, nil
}

func (s *Server) UpdateMember(ctx context.Context, r UpdateMemberRequestObject) (UpdateMemberResponseObject, error) {
	id, status, body, err := s.memberScope(ctx, r.Slug)
	if err != nil {
		return nil, err
	}
	if status != 0 {
		return UpdateMemberdefaultJSONResponse{StatusCode: status, Body: body}, nil
	}
	if r.Body == nil || (string(r.Body.Role) != "admin" && string(r.Body.Role) != "member") {
		return UpdateMemberdefaultJSONResponse{StatusCode: 400, Body: errorBody("validation_failed", "role must be admin or member")}, nil
	}
	result, err := s.pool.Exec(ctx, `UPDATE workspace_members SET role=$3 WHERE workspace_id=$1 AND user_id=$2 AND role <> 'owner'`, id, r.UserId, string(r.Body.Role))
	if err != nil {
		return nil, err
	}
	if result.RowsAffected() == 0 {
		return UpdateMemberdefaultJSONResponse{StatusCode: 409, Body: errorBody("member_conflict", "member not found or is the workspace owner")}, nil
	}
	return UpdateMember204Response{}, nil
}

func (s *Server) RemoveMember(ctx context.Context, r RemoveMemberRequestObject) (RemoveMemberResponseObject, error) {
	id, status, body, err := s.memberScope(ctx, r.Slug)
	if err != nil {
		return nil, err
	}
	if status != 0 {
		return RemoveMemberdefaultJSONResponse{StatusCode: status, Body: body}, nil
	}
	result, err := s.pool.Exec(ctx, `DELETE FROM workspace_members WHERE workspace_id=$1 AND user_id=$2 AND role <> 'owner'`, id, r.UserId)
	if err != nil {
		return nil, err
	}
	if result.RowsAffected() == 0 {
		return RemoveMemberdefaultJSONResponse{StatusCode: 409, Body: errorBody("member_conflict", "member not found or is the workspace owner")}, nil
	}
	return RemoveMember204Response{}, nil
}
