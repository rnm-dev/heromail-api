package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/apikey"
	"github.com/rnm/heromail/backend/internal/auth"
	"github.com/rnm/heromail/backend/internal/email"
	"github.com/rnm/heromail/backend/internal/maildomain"
	"github.com/rnm/heromail/backend/internal/provider"
	"github.com/rnm/heromail/backend/internal/ratelimit"
	"github.com/rnm/heromail/backend/internal/secrets"
	"github.com/rnm/heromail/backend/internal/storage"
	"github.com/rnm/heromail/backend/internal/workspace"
)

// These drive the real router — generated routing, prefix-based authentication
// and all — so they cover the contract in api/openapi.yaml, not just handler
// internals. Only the mail transport is faked.

type fakeSender struct {
	mu   sync.Mutex
	sent []provider.Message
	err  error
}

func (f *fakeSender) Send(_ context.Context, msg provider.Message) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return "", f.err
	}
	f.sent = append(f.sent, msg)
	return "fake-message-id@acme.test", nil
}

func (f *fakeSender) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

// reset drops what the harness sent while setting a test up. Registration
// sends a verification email through the same transport, so without this every
// "how many messages went out?" assertion counts that one too.
func (f *fakeSender) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = nil
}

func (f *fakeSender) last() (provider.Message, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sent) == 0 {
		return provider.Message{}, false
	}
	return f.sent[len(f.sent)-1], true
}

// fakeEnqueuer stands in for Redis. It records what would have been queued so
// a test can run the worker itself, synchronously and in order.
type fakeEnqueuer struct {
	mu  sync.Mutex
	ids []string
	err error
}

func (f *fakeEnqueuer) EnqueueSend(_ context.Context, emailID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.ids = append(f.ids, emailID)
	return nil
}

func (f *fakeEnqueuer) queued() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ids...)
}

func (f *fakeEnqueuer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.ids)
}

// fakeBlobStore stands in for S3: an in-memory map, so attachment tests never
// touch the network. Present by default in the harness, so uploads work
// without every test needing to know storage exists.
type fakeBlobStore struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func newFakeBlobStore() *fakeBlobStore { return &fakeBlobStore{objects: map[string][]byte{}} }

func (f *fakeBlobStore) Put(_ context.Context, key string, r io.Reader, _ int64, _ string) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = data
	return nil
}

func (f *fakeBlobStore) Get(_ context.Context, key string) (io.ReadCloser, error) {
	f.mu.Lock()
	data, ok := f.objects[key]
	f.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("fakeBlobStore: no object %q", key)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (f *fakeBlobStore) Delete(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objects, key)
	return nil
}

var _ storage.Store = (*fakeBlobStore)(nil)

type harness struct {
	t       *testing.T
	handler http.Handler
	mail    *fakeSender
	dns     *fakeResolver
	queue   *fakeEnqueuer
	worker  *email.Worker
	blobs   *fakeBlobStore
	limiter *ratelimit.Limiter
	// clientIP is unique per harness so IP-keyed limits from one test never
	// spill into another.
	clientIP string
	domains  *maildomain.Service
	pool     *pgxpool.Pool
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL is not set; skipping API tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	mail := &fakeSender{}
	accounts := account.NewService(account.NewStore(pool), mail, account.Config{
		AppBaseURL: "https://app.test",
		MailFrom:   "noreply@test",
	})
	dns := &fakeResolver{}
	sealer, err := secrets.New(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	domains := maildomain.NewService(maildomain.NewStore(pool), dns, sealer, maildomain.Config{
		SPFInclude:    "include:spf.heromail.local",
		DMARCReportTo: "dmarc@heromail.local",
	})
	// The limiter is real when Redis is configured: rate limiting is not worth
	// testing against a fake. Without it the server allows everything, which is
	// what keeps the rest of this suite free of limits.
	var limiter *ratelimit.Limiter
	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		limiter = ratelimit.New(addr)
		t.Cleanup(func() { limiter.Close() })
	}

	queue := &fakeEnqueuer{}
	blobs := newFakeBlobStore()
	emailStore := email.NewStore(pool)
	server := NewServer(pool,
		accounts,
		email.NewService(emailStore, queue, blobs),
		workspace.NewService(workspace.NewStore(pool)),
		domains,
		limiter,
	)

	return &harness{
		t:        t,
		handler:  Router(server, auth.New(pool), accounts),
		mail:     mail,
		dns:      dns,
		queue:    queue,
		worker:   email.NewWorker(emailStore, mail, blobs, domains),
		blobs:    blobs,
		limiter:  limiter,
		clientIP: fmt.Sprintf("198.51.100.%d", time.Now().UnixNano()%250+1),
		domains:  domains,
		pool:     pool,
	}
}

func (h *harness) do(method, path, body, token string) *httptest.ResponseRecorder {
	h.t.Helper()

	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("X-Forwarded-For", h.clientIP)

	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, r)
	return rec
}

func (h *harness) doWithHeader(method, path, body, token, headerKey, headerValue string) *httptest.ResponseRecorder {
	h.t.Helper()

	r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set(headerKey, headerValue)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("X-Forwarded-For", h.clientIP)

	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, r)
	return rec
}

// registerUser creates an account through the API and returns its session token.
func (h *harness) registerUser(name string) (token, userID, addr string) {
	h.t.Helper()

	addr = fmt.Sprintf("%s-%d@acme.test", name, time.Now().UnixNano())
	h.t.Cleanup(func() {
		h.pool.Exec(context.Background(), `DELETE FROM users WHERE email = $1`, addr)
	})

	rec := h.do(http.MethodPost, "/auth/register",
		fmt.Sprintf(`{"email":%q,"password":"correct-horse-battery","name":"Test"}`, addr), "")
	if rec.Code != http.StatusCreated {
		h.t.Fatalf("register %s: status %d, body %s", addr, rec.Code, rec.Body)
	}

	var creds struct {
		Token string `json:"token"`
		User  struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &creds); err != nil {
		h.t.Fatalf("decode credentials: %v", err)
	}
	return creds.Token, creds.User.ID, addr
}

// apiKeyFor mints a key straight into the database, the same way the CLI does.
func (h *harness) apiKeyFor(workspaceID string) string {
	h.t.Helper()

	key, prefix, hash, err := apikey.New()
	if err != nil {
		h.t.Fatalf("generate api key: %v", err)
	}
	_, err = h.pool.Exec(context.Background(),
		`INSERT INTO api_keys (workspace_id, name, key_hash, key_prefix) VALUES ($1, 'test', $2, $3)`,
		workspaceID, hash, prefix)
	if err != nil {
		h.t.Fatalf("insert api key: %v", err)
	}
	return key
}

// uploadFile POSTs a single-part multipart body to /v1/attachments, the way
// a real client would.
func (h *harness) uploadFile(key, filename, contentType string, data []byte) *httptest.ResponseRecorder {
	h.t.Helper()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Disposition": {fmt.Sprintf(`form-data; name="file"; filename=%q`, filename)},
		"Content-Type":        {contentType},
	})
	if err != nil {
		h.t.Fatalf("create multipart part: %v", err)
	}
	part.Write(data)
	mw.Close()

	r := httptest.NewRequest(http.MethodPost, "/v1/attachments", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Authorization", "Bearer "+key)
	r.Header.Set("X-Forwarded-For", h.clientIP)

	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, r)
	return rec
}

// workspaceFor creates a workspace through the API and returns its id.
func (h *harness) workspaceFor(sessionToken, slug string) string {
	h.t.Helper()

	unique := fmt.Sprintf("%s-%d", slug, time.Now().UnixNano()%1_000_000)
	rec := h.do(http.MethodPost, "/workspaces",
		fmt.Sprintf(`{"slug":%q,"name":"Test Workspace"}`, unique), sessionToken)
	if rec.Code != http.StatusCreated {
		h.t.Fatalf("create workspace: status %d, body %s", rec.Code, rec.Body)
	}

	var ws struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &ws)
	return ws.ID
}

// runWorker delivers one queued message, as the worker process would.
func (h *harness) runWorker(emailID string) {
	h.t.Helper()
	if err := h.runWorkerAttempt(emailID, 0, 8); err != nil {
		h.t.Logf("worker returned %v (a retry was requested)", err)
	}
}

// runWorkerAttempt runs the handler with asynq's retry counters set, so the
// give-up branch can be exercised without waiting for eight real retries.
func (h *harness) runWorkerAttempt(emailID string, retried, maxRetry int) error {
	h.t.Helper()

	return h.worker.Deliver(context.Background(), emailID, retried, maxRetry)
}

// eventTrail returns the event types recorded for a message, oldest first.
func (h *harness) eventTrail(emailID string) []string {
	h.t.Helper()

	rows, err := h.pool.Query(context.Background(),
		`SELECT type FROM email_events WHERE email_id = $1 ORDER BY created_at, id`, emailID)
	if err != nil {
		h.t.Fatalf("read events: %v", err)
	}
	defer rows.Close()

	var trail []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			h.t.Fatalf("scan event: %v", err)
		}
		trail = append(trail, t)
	}
	return trail
}

// emailState reads the stored status and last error straight from the table.
func (h *harness) emailState(emailID string) (status, lastError string) {
	h.t.Helper()

	var last *string
	if err := h.pool.QueryRow(context.Background(),
		`SELECT status, last_error FROM emails WHERE id = $1`, emailID).Scan(&status, &last); err != nil {
		h.t.Fatalf("read email state: %v", err)
	}
	if last != nil {
		lastError = *last
	}
	return status, lastError
}

// errorEnvelope asserts the API-wide error shape and returns the code.
func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()

	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body is not the declared envelope: %v (body: %s)", err, rec.Body)
	}
	if body.Error.Code == "" || body.Error.Message == "" {
		t.Errorf("error envelope is missing code or message: %s", rec.Body)
	}
	return body.Error.Code
}

// ---------------------------------------------------------------- health

func TestHealth(t *testing.T) {
	h := newHarness(t)

	rec := h.do(http.MethodGet, "/health", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}

	var body struct {
		Status   string `json:"status"`
		Database string `json:"database"`
	}
	json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Status != "ok" || body.Database != "ok" {
		t.Errorf("health = %+v", body)
	}
}

// ---------------------------------------------------------------- auth

func TestRegisterAndVerifyEmail(t *testing.T) {
	h := newHarness(t)
	token, _, addr := h.registerUser("verify")

	msg, ok := h.mail.last()
	if !ok {
		t.Fatal("no verification email was sent")
	}
	if len(msg.To) != 1 || msg.To[0] != addr {
		t.Errorf("verification sent to %v, want %s", msg.To, addr)
	}

	code := extractOTP(t, msg.TextBody)
	verifyBody := fmt.Sprintf(`{"email":%q,"code":%q}`, addr, code)
	if rec := h.do(http.MethodPost, "/auth/verify-email", verifyBody, ""); rec.Code != http.StatusOK {
		t.Fatalf("verify: status %d, body %s", rec.Code, rec.Body)
	}

	rec := h.do(http.MethodGet, "/auth/me", "", token)
	if rec.Code != http.StatusOK {
		t.Fatalf("me: status %d, body %s", rec.Code, rec.Body)
	}
	var me struct {
		User struct {
			EmailVerified bool `json:"email_verified"`
		} `json:"user"`
	}
	json.Unmarshal(rec.Body.Bytes(), &me)
	if !me.User.EmailVerified {
		t.Error("email_verified is still false after verification")
	}

	// Single use.
	again := h.do(http.MethodPost, "/auth/verify-email", verifyBody, "")
	if again.Code != http.StatusBadRequest {
		t.Errorf("reusing a code returned %d, want 400", again.Code)
	}
	if got := errorCode(t, again); got != "invalid_code" {
		t.Errorf("error code = %q, want invalid_code", got)
	}
}

func TestLoginAndSessionLifecycle(t *testing.T) {
	h := newHarness(t)
	token, _, addr := h.registerUser("login")

	ok := h.do(http.MethodPost, "/auth/login",
		fmt.Sprintf(`{"email":%q,"password":"correct-horse-battery"}`, addr), "")
	if ok.Code != http.StatusOK {
		t.Fatalf("login: status %d, body %s", ok.Code, ok.Body)
	}

	// Wrong password and unknown address must be indistinguishable.
	wrong := h.do(http.MethodPost, "/auth/login",
		fmt.Sprintf(`{"email":%q,"password":"wrong-password-xx"}`, addr), "")
	unknown := h.do(http.MethodPost, "/auth/login",
		`{"email":"nobody@acme.test","password":"wrong-password-xx"}`, "")
	if wrong.Code != http.StatusUnauthorized || unknown.Code != http.StatusUnauthorized {
		t.Fatalf("statuses = %d/%d, want 401/401", wrong.Code, unknown.Code)
	}
	if wrong.Body.String() != unknown.Body.String() {
		t.Errorf("responses differ, which is an account oracle:\n%s\n%s", wrong.Body, unknown.Body)
	}

	if rec := h.do(http.MethodPost, "/auth/logout", "", token); rec.Code != http.StatusNoContent {
		t.Fatalf("logout: status %d", rec.Code)
	}
	if rec := h.do(http.MethodGet, "/auth/me", "", token); rec.Code != http.StatusUnauthorized {
		t.Errorf("the token still works after logout (%d)", rec.Code)
	}
}

func TestResendVerificationDoesNotLeakAccounts(t *testing.T) {
	h := newHarness(t)
	_, _, addr := h.registerUser("resend")

	known := h.do(http.MethodPost, "/auth/resend-verification", fmt.Sprintf(`{"email":%q}`, addr), "")
	unknown := h.do(http.MethodPost, "/auth/resend-verification", `{"email":"nobody@acme.test"}`, "")

	if known.Code != http.StatusAccepted || unknown.Code != http.StatusAccepted {
		t.Errorf("statuses = %d/%d, want 202/202", known.Code, unknown.Code)
	}
}

func TestAuthRejectsBadInput(t *testing.T) {
	h := newHarness(t)
	_, _, addr := h.registerUser("dup")

	cases := map[string]struct {
		path string
		body string
		want int
	}{
		"duplicate email":  {"/auth/register", fmt.Sprintf(`{"email":%q,"password":"correct-horse-battery"}`, addr), http.StatusConflict},
		"short password":   {"/auth/register", `{"email":"short@acme.test","password":"abc"}`, http.StatusBadRequest},
		"bad email":        {"/auth/register", `{"email":"not-an-email","password":"correct-horse-battery"}`, http.StatusBadRequest},
		"missing password": {"/auth/register", `{"email":"x@acme.test"}`, http.StatusBadRequest},
		"malformed json":   {"/auth/register", `{"email":`, http.StatusBadRequest},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec := h.do(http.MethodPost, tc.path, tc.body, "")
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d; body = %s", rec.Code, tc.want, rec.Body)
			}
			errorCode(t, rec)
		})
	}
}

// ---------------------------------------------------------------- workspaces

func TestWorkspaceLifecycle(t *testing.T) {
	h := newHarness(t)
	token, _, _ := h.registerUser("ws")

	slug := fmt.Sprintf("acme-%d", time.Now().UnixNano()%1_000_000)
	created := h.do(http.MethodPost, "/workspaces",
		fmt.Sprintf(`{"slug":%q,"name":"Acme Corp"}`, slug), token)
	if created.Code != http.StatusCreated {
		t.Fatalf("create: status %d, body %s", created.Code, created.Body)
	}

	// The creator is listed as owner.
	list := h.do(http.MethodGet, "/workspaces", "", token)
	if list.Code != http.StatusOK {
		t.Fatalf("list: status %d, body %s", list.Code, list.Body)
	}
	var listed struct {
		Workspaces []struct {
			Slug string `json:"slug"`
			Role string `json:"role"`
		} `json:"workspaces"`
	}
	json.Unmarshal(list.Body.Bytes(), &listed)
	if len(listed.Workspaces) != 1 {
		t.Fatalf("listed %d workspaces, want 1", len(listed.Workspaces))
	}
	if listed.Workspaces[0].Slug != slug || listed.Workspaces[0].Role != "owner" {
		t.Errorf("listed %+v, want slug %s as owner", listed.Workspaces[0], slug)
	}

	if rec := h.do(http.MethodGet, "/workspaces/"+slug, "", token); rec.Code != http.StatusOK {
		t.Errorf("get own workspace: status %d, body %s", rec.Code, rec.Body)
	}

	// Someone else's workspace is simply absent.
	otherToken, _, _ := h.registerUser("ws-other")
	if rec := h.do(http.MethodGet, "/workspaces/"+slug, "", otherToken); rec.Code != http.StatusNotFound {
		t.Errorf("a non-member got %d for someone else's workspace, want 404", rec.Code)
	}
	if rec := h.do(http.MethodGet, "/workspaces", "", otherToken); rec.Code == http.StatusOK {
		var other struct {
			Workspaces []json.RawMessage `json:"workspaces"`
		}
		json.Unmarshal(rec.Body.Bytes(), &other)
		if len(other.Workspaces) != 0 {
			t.Errorf("a new user sees %d workspaces, want 0", len(other.Workspaces))
		}
	}

	// Duplicate slug and bad slug.
	if rec := h.do(http.MethodPost, "/workspaces", fmt.Sprintf(`{"slug":%q,"name":"Dup"}`, slug), token); rec.Code != http.StatusConflict {
		t.Errorf("duplicate slug: status %d, want 409", rec.Code)
	}
	if rec := h.do(http.MethodPost, "/workspaces", `{"slug":"NOT_A_SLUG","name":"Bad"}`, token); rec.Code != http.StatusBadRequest {
		t.Errorf("invalid slug: status %d, want 400", rec.Code)
	}
}

func TestWorkspacesRequireSessionNotApiKey(t *testing.T) {
	h := newHarness(t)
	token, _, _ := h.registerUser("cred")
	workspaceID := h.workspaceFor(token, "cred")
	key := h.apiKeyFor(workspaceID)

	// The two credentials are not interchangeable in either direction.
	if rec := h.do(http.MethodGet, "/workspaces", "", key); rec.Code != http.StatusUnauthorized {
		t.Errorf("an API key reached /workspaces (%d)", rec.Code)
	}
	if rec := h.do(http.MethodGet, "/v1/workspace", "", token); rec.Code != http.StatusUnauthorized {
		t.Errorf("a session token reached /v1 (%d)", rec.Code)
	}
	if rec := h.do(http.MethodGet, "/workspaces", "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous reached /workspaces (%d)", rec.Code)
	}
}

// ---------------------------------------------------------------- emails

func TestSendEmailIsQueuedThenDelivered(t *testing.T) {
	h := newHarness(t)
	token, _, _ := h.registerUser("send")
	workspaceID := h.workspaceFor(token, "send")
	key := h.apiKeyFor(workspaceID)
	h.mail.reset()

	const body = `{"from":"noreply@acme.com","to":["viktor@acme.com"],"subject":"Hi","text":"hello"}`

	rec := h.do(http.MethodPost, "/v1/emails", body, key)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("send: status %d, want 202; body %s", rec.Code, rec.Body)
	}

	var queued struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	json.Unmarshal(rec.Body.Bytes(), &queued)
	if queued.Status != "queued" || queued.ID == "" {
		t.Fatalf("response = %+v", queued)
	}

	// Nothing has been delivered yet: the request only queued it.
	if h.mail.count() != 0 {
		t.Errorf("the transport was called during the request (%d times)", h.mail.count())
	}
	if got := h.queue.queued(); len(got) != 1 || got[0] != queued.ID {
		t.Fatalf("queued %v, want [%s]", got, queued.ID)
	}

	var before struct {
		Status string `json:"status"`
	}
	json.Unmarshal(h.do(http.MethodGet, "/v1/emails/"+queued.ID, "", key).Body.Bytes(), &before)
	if before.Status != "queued" {
		t.Errorf("status before the worker runs = %q, want queued", before.Status)
	}

	h.runWorker(queued.ID)

	if h.mail.count() != 1 {
		t.Errorf("transport called %d times, want 1", h.mail.count())
	}

	var stored struct {
		Status            string `json:"status"`
		ProviderMessageID string `json:"provider_message_id"`
		Attempts          int    `json:"attempts"`
	}
	json.Unmarshal(h.do(http.MethodGet, "/v1/emails/"+queued.ID, "", key).Body.Bytes(), &stored)
	if stored.Status != "sent" || stored.Attempts != 1 || stored.ProviderMessageID == "" {
		t.Errorf("after the worker: %+v", stored)
	}

	trail := h.eventTrail(queued.ID)
	if len(trail) < 3 || trail[0] != "queued" || trail[1] != "processing" || trail[len(trail)-1] != "sent" {
		t.Errorf("event trail = %v, want queued -> processing -> sent", trail)
	}
}

func TestSendEmailIsIdempotent(t *testing.T) {
	h := newHarness(t)
	token, _, _ := h.registerUser("idem")
	workspaceID := h.workspaceFor(token, "idem")
	key := h.apiKeyFor(workspaceID)
	h.mail.reset()

	const body = `{"from":"noreply@acme.com","to":["viktor@acme.com"],"text":"hello"}`

	first := h.doWithHeader(http.MethodPost, "/v1/emails", body, key, "Idempotency-Key", "order-42")
	second := h.doWithHeader(http.MethodPost, "/v1/emails", body, key, "Idempotency-Key", "order-42")

	if first.Code != http.StatusAccepted || second.Code != http.StatusAccepted {
		t.Fatalf("statuses = %d/%d, want 202/202", first.Code, second.Code)
	}

	var a, b struct {
		ID string `json:"id"`
	}
	json.Unmarshal(first.Body.Bytes(), &a)
	json.Unmarshal(second.Body.Bytes(), &b)
	if a.ID != b.ID {
		t.Errorf("ids differ: %s vs %s", a.ID, b.ID)
	}
	if h.queue.count() != 1 {
		t.Errorf("queued %d times; the repeat must not enqueue again", h.queue.count())
	}

	var rows int
	h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM emails WHERE workspace_id = $1`, workspaceID).Scan(&rows)
	if rows != 1 {
		t.Errorf("stored %d emails, want 1", rows)
	}
}

func TestWorkerRetriesThenGivesUp(t *testing.T) {
	h := newHarness(t)
	token, _, _ := h.registerUser("retry")
	workspaceID := h.workspaceFor(token, "retry")
	key := h.apiKeyFor(workspaceID)
	h.mail.reset()
	h.mail.err = errors.New("connection refused")

	rec := h.do(http.MethodPost, "/v1/emails",
		`{"from":"noreply@acme.com","to":["viktor@acme.com"],"text":"hello"}`, key)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("send: status %d, want 202", rec.Code)
	}
	var queued struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &queued)

	// An attempt with retries left leaves the message failed, not dead, and
	// returns an error so asynq schedules another try.
	if err := h.runWorkerAttempt(queued.ID, 0, 8); err == nil {
		t.Error("a failed delivery must return an error so the task is retried")
	}
	if status, lastErr := h.emailState(queued.ID); status != "failed" || lastErr == "" {
		t.Errorf("after one failure: status %q, last_error %q", status, lastErr)
	}

	// The final attempt marks it dead and stops asking for retries.
	if err := h.runWorkerAttempt(queued.ID, 8, 8); err != nil {
		t.Errorf("the last attempt must not ask for another retry: %v", err)
	}
	if status, lastErr := h.emailState(queued.ID); status != "dead" || lastErr == "" {
		t.Errorf("after the last attempt: status %q, last_error %q", status, lastErr)
	}

	// A stray duplicate task must not resurrect a dead message.
	sentBefore := h.mail.count()
	h.runWorker(queued.ID)
	if h.mail.count() != sentBefore {
		t.Error("a dead message was picked up again")
	}
}

func TestWorkerIgnoresAnAlreadySentMessage(t *testing.T) {
	h := newHarness(t)
	token, _, _ := h.registerUser("dupsend")
	workspaceID := h.workspaceFor(token, "dupsend")
	key := h.apiKeyFor(workspaceID)
	h.mail.reset()

	rec := h.do(http.MethodPost, "/v1/emails",
		`{"from":"noreply@acme.com","to":["viktor@acme.com"],"text":"hello"}`, key)
	var queued struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &queued)

	h.runWorker(queued.ID)
	h.runWorker(queued.ID) // duplicate task, e.g. after a Redis hiccup

	if h.mail.count() != 1 {
		t.Errorf("delivered %d times; a duplicate task must be a no-op", h.mail.count())
	}
}

func TestEmailScopingAndValidation(t *testing.T) {
	h := newHarness(t)

	tokenA, _, _ := h.registerUser("scope-a")
	workspaceA := h.workspaceFor(tokenA, "scope-a")
	keyA := h.apiKeyFor(workspaceA)

	rec := h.do(http.MethodPost, "/v1/emails",
		`{"from":"noreply@acme.com","to":["viktor@acme.com"],"text":"hello"}`, keyA)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("send: status %d, want 202", rec.Code)
	}
	var sent struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &sent)

	tokenB, _, _ := h.registerUser("scope-b")
	workspaceB := h.workspaceFor(tokenB, "scope-b")
	keyB := h.apiKeyFor(workspaceB)

	if got := h.do(http.MethodGet, "/v1/emails/"+sent.ID, "", keyB); got.Code != http.StatusNotFound {
		t.Errorf("another workspace read someone else's email (%d)", got.Code)
	}

	for name, id := range map[string]string{
		"unknown uuid": "11111111-1111-4111-8111-111111111111",
		"not a uuid":   "definitely-not-a-uuid",
	} {
		t.Run(name, func(t *testing.T) {
			got := h.do(http.MethodGet, "/v1/emails/"+id, "", keyA)
			if got.Code != http.StatusNotFound && got.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 404 or 400", got.Code)
			}
		})
	}

	for name, body := range map[string]string{
		"no recipients": `{"from":"a@acme.com","to":[],"text":"x"}`,
		"missing from":  `{"to":["b@acme.com"],"text":"x"}`,
		"bad from":      `{"from":"not-an-email","to":["b@acme.com"],"text":"x"}`,
		"no body":       `{"from":"a@acme.com","to":["b@acme.com"],"subject":"s"}`,
	} {
		t.Run(name, func(t *testing.T) {
			got := h.do(http.MethodPost, "/v1/emails", body, keyA)
			if got.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body = %s", got.Code, got.Body)
			}
		})
	}

	if h.do(http.MethodPost, "/v1/emails", `{"from":"a@acme.com","to":["b@acme.com"],"text":"x"}`, "hm_live_garbage").Code != http.StatusUnauthorized {
		t.Error("a garbage API key was accepted")
	}
}

// extractOTP pulls the six-digit code out of a verification email.
func extractOTP(t *testing.T, body string) string {
	t.Helper()

	for i := 0; i+6 <= len(body); i++ {
		run := body[i : i+6]
		digits := true
		for _, c := range run {
			if c < '0' || c > '9' {
				digits = false
				break
			}
		}
		// Bounded on both sides so a longer number cannot yield a six-digit
		// substring of itself.
		if digits &&
			(i == 0 || body[i-1] < '0' || body[i-1] > '9') &&
			(i+6 == len(body) || body[i+6] < '0' || body[i+6] > '9') {
			return run
		}
	}
	t.Fatalf("no six-digit code in body:\n%s", body)
	return ""
}

func extractToken(t *testing.T, body string) string {
	t.Helper()

	const marker = "token="
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("no token in body:\n%s", body)
	}
	token := body[i+len(marker):]
	if end := strings.IndexAny(token, "\n\r \""); end >= 0 {
		token = token[:end]
	}
	return token
}
