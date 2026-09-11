// Package httpapi is the HTTP surface. It implements StrictServerInterface,
// which oapi-codegen generates from api/openapi.yaml — so an endpoint declared
// in the spec and not implemented here does not compile, and a response shape
// the spec does not declare cannot be returned.
package httpapi

import (
	"context"
	"errors"
	"io"
	"log"
	"mime/multipart"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/email"
	"github.com/rnm/heromail/backend/internal/inbound"
	"github.com/rnm/heromail/backend/internal/maildomain"
	"github.com/rnm/heromail/backend/internal/ratelimit"
	"github.com/rnm/heromail/backend/internal/workspace"
)

//go:generate sh -c "cd ../.. && go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0 -config internal/httpapi/config.yaml api/openapi.yaml"

// Server wires the domain services to the generated interface. It holds no
// business rules of its own: decode, delegate, map errors to status codes.
type Server struct {
	pool       *pgxpool.Pool
	accounts   *account.Service
	emails     *email.Service
	workspaces *workspace.Service
	domains    *maildomain.Service
	inbound    *inbound.Store
	limiter    *ratelimit.Limiter
}

func NewServer(
	pool *pgxpool.Pool,
	accounts *account.Service,
	emails *email.Service,
	workspaces *workspace.Service,
	domains *maildomain.Service,
	inboundStore *inbound.Store,
	limiter *ratelimit.Limiter,
) *Server {
	return &Server{
		pool:       pool,
		accounts:   accounts,
		emails:     emails,
		workspaces: workspaces,
		domains:    domains,
		inbound:    inboundStore,
		limiter:    limiter,
	}
}

// tooMany renders the shared 429 body and its Retry-After header.
func tooMany(res ratelimit.Result, message string) TooManyRequestsJSONResponse {
	retryAfter := retryAfterSeconds(res.RetryAfter)
	return TooManyRequestsJSONResponse{
		Body:    errorBody("rate_limited", message),
		Headers: TooManyRequestsResponseHeaders{RetryAfter: &retryAfter},
	}
}

var _ StrictServerInterface = (*Server)(nil)

// ---------------------------------------------------------- message search

func (s *Server) SearchMessages(ctx context.Context, request SearchMessagesRequestObject) (SearchMessagesResponseObject, error) {
	user, ok := account.CurrentUser(ctx)
	if !ok {
		return SearchMessages401JSONResponse{UnauthorizedJSONResponse(errorBody("unauthenticated", "no session"))}, nil
	}

	query := strings.TrimSpace(request.Params.Q)
	if query == "" {
		return SearchMessages400JSONResponse{BadRequestJSONResponse(errorBody("validation_failed", "search query is required"))}, nil
	}
	limit := 50
	if request.Params.Limit != nil {
		limit = *request.Params.Limit
	}
	if limit < 1 || limit > 100 {
		return SearchMessages400JSONResponse{BadRequestJSONResponse(errorBody("validation_failed", "limit must be between 1 and 100"))}, nil
	}

	matches, err := s.emails.SearchForUser(ctx, user.ID, query, limit)
	if err != nil {
		log.Printf("search messages: %v", err)
		return nil, err
	}
	out := make([]Email, 0, len(matches))
	for i := range matches {
		// Attachments are omitted here: a search result list does not need
		// them, and fetching per row would turn one query into N+1.
		out = append(out, emailToAPI(&matches[i], nil))
	}
	return SearchMessages200JSONResponse{Messages: out}, nil
}

// errorBody builds the single error envelope the spec declares.
func errorBody(code, message string) Error {
	return Error{Error: struct {
		Code    string      `json:"code"`
		Details interface{} `json:"details,omitempty"`
		Message string      `json:"message"`
	}{Code: code, Message: message}}
}

// ---------------------------------------------------------------- health

func (s *Server) GetHealth(ctx context.Context, _ GetHealthRequestObject) (GetHealthResponseObject, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if err := s.pool.Ping(ctx); err != nil {
		return GetHealth503JSONResponse{
			Status:   HealthStatusDegraded,
			Database: HealthDatabaseUnreachable,
		}, nil
	}
	return GetHealth200JSONResponse{
		Status:   HealthStatusOk,
		Database: HealthDatabaseOk,
	}, nil
}

// ---------------------------------------------------------------- auth

func (s *Server) Register(ctx context.Context, request RegisterRequestObject) (RegisterResponseObject, error) {
	if request.Body == nil {
		return Register400JSONResponse{BadRequestJSONResponse(errorBody("invalid_json", "a JSON body is required"))}, nil
	}

	rc := requestContextFrom(ctx)
	if res := s.allow(ctx, rc.IP, registerPerIP); !res.Allowed {
		return Register429JSONResponse{tooMany(res, "too many sign-ups from this address; try again later")}, nil
	}

	name := ""
	if request.Body.Name != nil {
		name = *request.Body.Name
	}

	creds, err := s.accounts.Register(ctx, account.RegisterRequest{
		Email:        string(request.Body.Email),
		Password:     request.Body.Password,
		Name:         name,
		PersonalName: deref(request.Body.PersonalName),
	}, rc)
	switch {
	case errors.Is(err, account.ErrValidation):
		return Register400JSONResponse{BadRequestJSONResponse(errorBody("validation_failed", err.Error()))}, nil
	case errors.Is(err, account.ErrEmailTaken):
		return Register409JSONResponse(errorBody("email_taken", "this email is already registered")), nil
	case err != nil:
		log.Printf("register: %v", err)
		return nil, err
	}
	return Register201JSONResponse(credentialsToAPI(creds)), nil
}

func (s *Server) Login(ctx context.Context, request LoginRequestObject) (LoginResponseObject, error) {
	if request.Body == nil {
		return Login400JSONResponse{BadRequestJSONResponse(errorBody("invalid_json", "a JSON body is required"))}, nil
	}

	rc := requestContextFrom(ctx)
	email := normaliseKey(string(request.Body.Email))
	if res := s.allow(ctx, email, loginPerEmail); !res.Allowed {
		return Login429JSONResponse{tooMany(res, "too many sign-in attempts for this account; try again later")}, nil
	}
	if res := s.allow(ctx, rc.IP, loginPerIP); !res.Allowed {
		return Login429JSONResponse{tooMany(res, "too many sign-in attempts from this address; try again later")}, nil
	}

	creds, err := s.accounts.Login(ctx, account.LoginRequest{
		Email:    string(request.Body.Email),
		Password: request.Body.Password,
	}, rc)
	switch {
	case errors.Is(err, account.ErrCredentials):
		return Login401JSONResponse(errorBody("invalid_credentials", "invalid email or password")), nil
	case err != nil:
		log.Printf("login: %v", err)
		return nil, err
	}
	return Login200JSONResponse(credentialsToAPI(creds)), nil
}

func (s *Server) VerifyEmail(ctx context.Context, request VerifyEmailRequestObject) (VerifyEmailResponseObject, error) {
	if request.Body == nil || request.Body.Code == "" || request.Body.Email == "" {
		return VerifyEmail400JSONResponse(errorBody("validation_failed", "email and code are required")), nil
	}

	// A coarse per-address limit on top of the per-code counter in Postgres.
	// This one throttles someone burning through *fresh* codes; the row
	// counter is what caps guesses against a single code, and it is the
	// authoritative one because it does not fail open when Redis is down.
	if res := s.allow(ctx, normaliseKey(string(request.Body.Email)), verifyAttemptPerEmail); !res.Allowed {
		return VerifyEmail429JSONResponse{tooMany(res, "too many attempts, try again later")}, nil
	}

	user, err := s.accounts.VerifyEmail(ctx, string(request.Body.Email), request.Body.Code)
	switch {
	case errors.Is(err, account.ErrCodeLocked):
		return VerifyEmail429JSONResponse{TooManyRequestsJSONResponse{
			Body:    errorBody("code_locked", err.Error()),
			Headers: TooManyRequestsResponseHeaders{RetryAfter: &otpLockoutSeconds},
		}}, nil
	case errors.Is(err, account.ErrInvalidToken):
		// Deliberately the same answer for a wrong code and for an address
		// with nothing pending.
		return VerifyEmail400JSONResponse(errorBody("invalid_code", err.Error())), nil
	case err != nil:
		log.Printf("verify-email: %v", err)
		return nil, err
	}
	return VerifyEmail200JSONResponse{User: userToAPI(user)}, nil
}

// otpLockoutSeconds mirrors account.otpLockout for the Retry-After header.
var otpLockoutSeconds = int((15 * time.Minute).Seconds())

func (s *Server) ResendVerification(ctx context.Context, request ResendVerificationRequestObject) (ResendVerificationResponseObject, error) {
	// Answers 202 regardless — see the spec note on enumeration.
	if request.Body == nil {
		return ResendVerification202Response{}, nil
	}
	// Limited per address, not per IP: the harm is a flooded mailbox, and the
	// sender's address is free to change.
	if res := s.allow(ctx, normaliseKey(string(request.Body.Email)), verifyPerEmail); !res.Allowed {
		return ResendVerification429JSONResponse{tooMany(res, "a verification link was already sent recently")}, nil
	}
	s.accounts.ResendVerification(ctx, string(request.Body.Email))
	return ResendVerification202Response{}, nil
}

func (s *Server) ForgotPassword(ctx context.Context, request ForgotPasswordRequestObject) (ForgotPasswordResponseObject, error) {
	// Answers 202 regardless — see the spec note on enumeration.
	if request.Body == nil {
		return ForgotPassword202Response{}, nil
	}
	// Without this, anyone can use us to bomb a third party's inbox with reset
	// mail, which costs them nothing and costs our sending reputation a lot.
	if res := s.allow(ctx, normaliseKey(string(request.Body.Email)), resetPerEmail); !res.Allowed {
		return ForgotPassword429JSONResponse{tooMany(res, "a reset link was already sent recently")}, nil
	}
	s.accounts.RequestPasswordReset(ctx, string(request.Body.Email))
	return ForgotPassword202Response{}, nil
}

func (s *Server) ResetPassword(ctx context.Context, request ResetPasswordRequestObject) (ResetPasswordResponseObject, error) {
	if request.Body == nil {
		return ResetPassword400JSONResponse(errorBody("invalid_json", "a JSON body is required")), nil
	}

	creds, err := s.accounts.ResetPassword(ctx, request.Body.Token, request.Body.Password, requestContextFrom(ctx))
	switch {
	case errors.Is(err, account.ErrInvalidToken):
		return ResetPassword400JSONResponse(errorBody("invalid_token", "this link is invalid or has expired")), nil
	case errors.Is(err, account.ErrValidation):
		return ResetPassword400JSONResponse(errorBody("validation_failed", err.Error())), nil
	case err != nil:
		log.Printf("reset-password: %v", err)
		return nil, err
	}
	return ResetPassword200JSONResponse(credentialsToAPI(creds)), nil
}

func (s *Server) GetCurrentUser(ctx context.Context, _ GetCurrentUserRequestObject) (GetCurrentUserResponseObject, error) {
	user, ok := account.CurrentUser(ctx)
	if !ok {
		return GetCurrentUser401JSONResponse{UnauthorizedJSONResponse(errorBody("unauthenticated", "no session"))}, nil
	}
	return GetCurrentUser200JSONResponse{User: userToAPI(user)}, nil
}

func (s *Server) Logout(ctx context.Context, _ LogoutRequestObject) (LogoutResponseObject, error) {
	if token, ok := account.SessionToken(ctx); ok {
		if err := s.accounts.Logout(ctx, token); err != nil {
			// The client clears local state regardless; a failed revocation
			// must not leave the UI stuck signed in.
			log.Printf("logout: %v", err)
		}
	}
	return Logout204Response{}, nil
}

// ---------------------------------------------------------------- workspaces

func (s *Server) ListWorkspaces(ctx context.Context, _ ListWorkspacesRequestObject) (ListWorkspacesResponseObject, error) {
	user, ok := account.CurrentUser(ctx)
	if !ok {
		return ListWorkspaces401JSONResponse{UnauthorizedJSONResponse(errorBody("unauthenticated", "no session"))}, nil
	}

	memberships, err := s.workspaces.ListForUser(ctx, user.ID)
	if err != nil {
		log.Printf("list workspaces: %v", err)
		return nil, err
	}

	out := make([]WorkspaceMembership, 0, len(memberships))
	for _, m := range memberships {
		out = append(out, WorkspaceMembership{
			Personal: &m.Personal, Id: mustUUID(m.ID),
			Slug:      m.Slug,
			Name:      m.Name,
			Role:      Role(m.Role),
			CreatedAt: m.CreatedAt,
			UpdatedAt: m.UpdatedAt,
		})
	}
	return ListWorkspaces200JSONResponse{Workspaces: out}, nil
}

func (s *Server) CreateWorkspace(ctx context.Context, request CreateWorkspaceRequestObject) (CreateWorkspaceResponseObject, error) {
	user, ok := account.CurrentUser(ctx)
	if !ok {
		return CreateWorkspace401JSONResponse{UnauthorizedJSONResponse(errorBody("unauthenticated", "no session"))}, nil
	}
	if request.Body == nil {
		return CreateWorkspace400JSONResponse{BadRequestJSONResponse(errorBody("invalid_json", "a JSON body is required"))}, nil
	}

	ws, err := s.workspaces.Create(ctx, user.ID, request.Body.Slug, request.Body.Name)
	switch {
	case errors.Is(err, workspace.ErrValidation):
		return CreateWorkspace400JSONResponse{BadRequestJSONResponse(errorBody("validation_failed", err.Error()))}, nil
	case errors.Is(err, workspace.ErrSlugTaken):
		return CreateWorkspace409JSONResponse(errorBody("slug_taken", "this slug is already taken")), nil
	case err != nil:
		log.Printf("create workspace: %v", err)
		return nil, err
	}
	return CreateWorkspace201JSONResponse(workspaceToAPI(ws)), nil
}

func (s *Server) GetWorkspace(ctx context.Context, request GetWorkspaceRequestObject) (GetWorkspaceResponseObject, error) {
	user, ok := account.CurrentUser(ctx)
	if !ok {
		return GetWorkspace401JSONResponse{UnauthorizedJSONResponse(errorBody("unauthenticated", "no session"))}, nil
	}

	ws, err := s.workspaces.BySlugForUser(ctx, user.ID, request.Slug)
	switch {
	case errors.Is(err, workspace.ErrNotFound):
		// Includes workspaces the user is simply not a member of.
		return GetWorkspace404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "workspace not found"))}, nil
	case err != nil:
		log.Printf("get workspace: %v", err)
		return nil, err
	}
	return GetWorkspace200JSONResponse(workspaceToAPI(ws)), nil
}

// ---------------------------------------------------------------- emails

func (s *Server) GetApiKeyWorkspace(ctx context.Context, _ GetApiKeyWorkspaceRequestObject) (GetApiKeyWorkspaceResponseObject, error) {
	workspaceID, ok := workspaceIDFrom(ctx)
	if !ok {
		return GetApiKeyWorkspace401JSONResponse{UnauthorizedJSONResponse(errorBody("unauthenticated", "no API key"))}, nil
	}

	ws, err := s.workspaces.ByID(ctx, workspaceID)
	if err != nil {
		log.Printf("api key workspace: %v", err)
		return nil, err
	}
	return GetApiKeyWorkspace200JSONResponse(workspaceToAPI(ws)), nil
}

func (s *Server) SendEmail(ctx context.Context, request SendEmailRequestObject) (SendEmailResponseObject, error) {
	workspaceID, ok := workspaceIDFrom(ctx)
	if !ok {
		return SendEmail401JSONResponse{UnauthorizedJSONResponse(errorBody("unauthenticated", "no API key"))}, nil
	}
	if request.Body == nil {
		return SendEmail400JSONResponse{BadRequestJSONResponse(errorBody("invalid_json", "a JSON body is required"))}, nil
	}

	if request.Body.ReplyToMessageId != nil {
		return SendEmail400JSONResponse{BadRequestJSONResponse(errorBody("invalid_request", "reply_to_message_id requires session sending"))}, nil
	}

	// Per workspace, because the hazard is multi-tenant: one abusive tenant
	// burns the sending reputation every other tenant depends on.
	if res := s.allow(ctx, workspaceID, sendQuota()...); !res.Allowed {
		return SendEmail429JSONResponse{tooMany(res, "this workspace has reached its send limit")}, nil
	}

	idempotencyKey := ""
	if request.Params.IdempotencyKey != nil {
		idempotencyKey = *request.Params.IdempotencyKey
	}

	to := make([]string, 0, len(request.Body.To))
	for _, addr := range request.Body.To {
		to = append(to, string(addr))
	}

	var attachmentIDs []string
	if request.Body.Attachments != nil {
		attachmentIDs = make([]string, 0, len(*request.Body.Attachments))
		for _, id := range *request.Body.Attachments {
			attachmentIDs = append(attachmentIDs, id.String())
		}
	}

	msg, err := s.emails.Send(ctx, workspaceID, idempotencyKey, email.SendRequest{
		From:          string(request.Body.From),
		To:            to,
		Cc:            emailAddresses(request.Body.Cc),
		Bcc:           emailAddresses(request.Body.Bcc),
		Subject:       deref(request.Body.Subject),
		HTML:          deref(request.Body.Html),
		Text:          deref(request.Body.Text),
		AttachmentIDs: attachmentIDs,
	})
	switch {
	case errors.Is(err, email.ErrValidation),
		errors.Is(err, email.ErrNotFound),
		errors.Is(err, email.ErrAttachmentNotFound),
		errors.Is(err, email.ErrAttachmentsTooLarge),
		errors.Is(err, email.ErrFromNotAllowed):
		return SendEmail400JSONResponse{BadRequestJSONResponse(errorBody("validation_failed", err.Error()))}, nil
	case errors.Is(err, email.ErrEnqueueFailed):
		// The row exists but nothing will deliver it. A 5xx is right: this is
		// our fault and the caller should retry, which their idempotency key
		// makes safe.
		log.Printf("send email %s: %v", msg.ID, err)
		return nil, err
	case err != nil:
		log.Printf("send email: %v", err)
		return nil, err
	}
	return SendEmail202JSONResponse{Id: mustUUID(msg.ID), Status: EmailStatus(msg.Status)}, nil
}

// UploadAttachment reads the "file" part of a multipart body and stores it.
// Every other part is skipped rather than rejected, so a client that also
// sends form fields (a filename override, a note) is not punished for it.
func (s *Server) UploadAttachment(ctx context.Context, request UploadAttachmentRequestObject) (UploadAttachmentResponseObject, error) {
	workspaceID, ok := workspaceIDFrom(ctx)
	if !ok {
		return UploadAttachment401JSONResponse{UnauthorizedJSONResponse(errorBody("unauthenticated", "no API key"))}, nil
	}
	if res := s.allow(ctx, workspaceID, uploadQuota()...); !res.Allowed {
		return UploadAttachment429JSONResponse{tooMany(res, "this workspace has reached its upload limit")}, nil
	}
	if request.Body == nil {
		return UploadAttachment400JSONResponse{BadRequestJSONResponse(errorBody("invalid_request", "a multipart body is required"))}, nil
	}

	var part *multipart.Part
	for {
		p, err := request.Body.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return UploadAttachment400JSONResponse{BadRequestJSONResponse(errorBody("invalid_request", "malformed multipart body"))}, nil
		}
		if p.FormName() == "file" {
			part = p
			break
		}
		p.Close()
	}
	if part == nil {
		return UploadAttachment400JSONResponse{BadRequestJSONResponse(errorBody("validation_failed", `a "file" part is required`))}, nil
	}
	defer part.Close()

	filename := part.FileName()
	contentType := part.Header.Get("Content-Type")

	attachment, err := s.emails.UploadAttachment(ctx, workspaceID, filename, contentType, part)
	switch {
	case errors.Is(err, email.ErrStorageNotConfigured):
		return UploadAttachment503JSONResponse(errorBody("storage_not_configured", "attachment storage is not configured on this deployment")), nil
	case errors.Is(err, email.ErrAttachmentTooLarge):
		return UploadAttachment413JSONResponse(errorBody("attachment_too_large", err.Error())), nil
	case errors.Is(err, email.ErrValidation):
		return UploadAttachment400JSONResponse{BadRequestJSONResponse(errorBody("validation_failed", err.Error()))}, nil
	case err != nil:
		log.Printf("upload attachment: %v", err)
		return nil, err
	}
	return UploadAttachment201JSONResponse(attachmentToAPI(attachment)), nil
}

func (s *Server) GetEmail(ctx context.Context, request GetEmailRequestObject) (GetEmailResponseObject, error) {
	workspaceID, ok := workspaceIDFrom(ctx)
	if !ok {
		return GetEmail401JSONResponse{UnauthorizedJSONResponse(errorBody("unauthenticated", "no API key"))}, nil
	}

	msg, err := s.emails.ByID(ctx, workspaceID, request.Id.String())
	switch {
	case errors.Is(err, email.ErrNotFound):
		// Another workspace's message lands here too, which is the point.
		return GetEmail404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "email not found"))}, nil
	case err != nil:
		log.Printf("get email: %v", err)
		return nil, err
	}

	userID := ""
	if user, ok := account.CurrentUser(ctx); ok {
		userID = user.ID
	}
	allowed, err := s.inbound.CanReadOutbound(ctx, userID, msg.ID)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return GetEmail404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "email not found"))}, nil
	}

	attachments, err := s.emails.AttachmentsForEmail(ctx, msg.ID)
	if err != nil {
		log.Printf("get email %s: load attachments: %v", msg.ID, err)
		return nil, err
	}
	return GetEmail200JSONResponse(emailToAPI(msg, attachments)), nil
}
