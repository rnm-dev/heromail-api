package httpapi

import (
	"context"
	"errors"

	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/workspace"
)

func (s *Server) DeleteWorkspace(ctx context.Context, r DeleteWorkspaceRequestObject) (DeleteWorkspaceResponseObject, error) {
	_, forbidden, err := s.scope(ctx, r.Slug, workspace.RoleOwner)
	if errors.Is(err, workspace.ErrNotFound) {
		return DeleteWorkspace404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "workspace not found"))}, nil
	}
	if err != nil {
		return nil, err
	}
	if forbidden {
		return DeleteWorkspace403JSONResponse{ForbiddenJSONResponse(errorBody("forbidden", "only the owner can delete a workspace"))}, nil
	}
	user, _ := account.CurrentUser(ctx)
	err = s.workspaces.DeleteOwned(ctx, user.ID, r.Slug)
	if errors.Is(err, workspace.ErrNotFound) {
		return DeleteWorkspace404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "workspace not found"))}, nil
	}
	if err != nil {
		return nil, err
	}
	return DeleteWorkspace204Response{}, nil
}
