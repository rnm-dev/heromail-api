package httpapi

import (
	"context"
	"errors"
	"net/mail"
	"strings"

	"github.com/jackc/pgx/v5"
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
