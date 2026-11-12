package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"
)

// loginAs signs an existing harness user in with optional client fields and
// returns the decoded credentials.
func (h *harness) loginAs(addr, extra string) Credentials {
	h.t.Helper()
	body := fmt.Sprintf(`{"email":%q,"password":"correct-horse-battery"%s}`, addr, extra)
	rec := h.do(http.MethodPost, "/auth/login", body, "")
	if rec.Code != http.StatusOK {
		h.t.Fatalf("login %s: %d %s", addr, rec.Code, rec.Body)
	}
	var c Credentials
	if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil {
		h.t.Fatalf("decode credentials: %v", err)
	}
	return c
}

func (h *harness) refresh(token string) (int, Credentials, string) {
	h.t.Helper()
	rec := h.do(http.MethodPost, "/auth/refresh", fmt.Sprintf(`{"refresh_token":%q}`, token), "")
	var c Credentials
	var e Error
	if rec.Code == http.StatusOK {
		json.Unmarshal(rec.Body.Bytes(), &c)
	} else {
		json.Unmarshal(rec.Body.Bytes(), &e)
	}
	return rec.Code, c, e.Error.Code
}

const androidClient = `,"client":"android","device_name":"Pixel 9","app_version":"1.0.0"`

func TestWebLoginKeepsSingleToken(t *testing.T) {
	h := newHarness(t)
	_, _, addr := h.registerUser("web-session")

	c := h.loginAs(addr, "")
	if c.RefreshToken != nil || c.RefreshExpiresAt != nil {
		t.Fatalf("web login got a refresh token: %+v", c)
	}
	if d := time.Until(c.ExpiresAt); d < 29*24*time.Hour {
		t.Fatalf("web session lifetime shrank: %v", d)
	}
	if c.SessionId.String() == "00000000-0000-0000-0000-000000000000" {
		t.Fatal("sessionId missing")
	}
	if r := h.do(http.MethodGet, "/auth/me", "", c.Token); r.Code != http.StatusOK {
		t.Fatalf("me: %d %s", r.Code, r.Body)
	}
	// An explicit web client is the same thing.
	if c := h.loginAs(addr, `,"client":"web"`); c.RefreshToken != nil {
		t.Fatal("client=web got a refresh token")
	}
	if r := h.do(http.MethodPost, "/auth/login",
		fmt.Sprintf(`{"email":%q,"password":"correct-horse-battery","client":"desktop"}`, addr), ""); r.Code != http.StatusBadRequest {
		t.Fatalf("unknown client accepted: %d", r.Code)
	}
}

func TestMobileRefreshRotationAndReuse(t *testing.T) {
	h := newHarness(t)
	_, _, addr := h.registerUser("mobile-refresh")

	first := h.loginAs(addr, androidClient)
	if first.RefreshToken == nil || first.RefreshExpiresAt == nil {
		t.Fatalf("mobile login without refresh token: %+v", first)
	}
	if d := time.Until(first.ExpiresAt); d > 16*time.Minute || d < 10*time.Minute {
		t.Fatalf("access token lifetime %v, want ~15m", d)
	}
	if r := h.do(http.MethodGet, "/auth/me", "", first.Token); r.Code != http.StatusOK {
		t.Fatalf("me with access token: %d", r.Code)
	}

	code, second, _ := h.refresh(*first.RefreshToken)
	if code != http.StatusOK || second.RefreshToken == nil {
		t.Fatalf("refresh: %d", code)
	}
	if second.SessionId != first.SessionId {
		t.Fatal("refresh changed the session id")
	}
	if *second.RefreshToken == *first.RefreshToken || second.Token == first.Token {
		t.Fatal("refresh did not rotate")
	}
	if r := h.do(http.MethodGet, "/auth/me", "", first.Token); r.Code != http.StatusUnauthorized {
		t.Fatalf("old access token still works: %d", r.Code)
	}
	if r := h.do(http.MethodGet, "/auth/me", "", second.Token); r.Code != http.StatusOK {
		t.Fatalf("new access token: %d", r.Code)
	}

	// The successor rotates again: the chain continues.
	code, third, _ := h.refresh(*second.RefreshToken)
	if code != http.StatusOK {
		t.Fatalf("second refresh: %d", code)
	}

	// Replaying the first token kills the whole chain.
	if code, _, ec := h.refresh(*first.RefreshToken); code != http.StatusUnauthorized || ec != "refresh_token_reused" {
		t.Fatalf("reuse: %d %s", code, ec)
	}
	if r := h.do(http.MethodGet, "/auth/me", "", third.Token); r.Code != http.StatusUnauthorized {
		t.Fatalf("access token survived reuse detection: %d", r.Code)
	}
	if code, _, ec := h.refresh(*third.RefreshToken); code != http.StatusUnauthorized || ec != "invalid_refresh_token" {
		t.Fatalf("latest refresh token survived reuse detection: %d %s", code, ec)
	}

	if code, _, ec := h.refresh("not-a-token"); code != http.StatusUnauthorized || ec != "invalid_refresh_token" {
		t.Fatalf("garbage token: %d %s", code, ec)
	}
}

func TestConcurrentRefreshMintsOneSuccessor(t *testing.T) {
	h := newHarness(t)
	_, _, addr := h.registerUser("mobile-race")
	c := h.loginAs(addr, androidClient)

	var wg sync.WaitGroup
	codes := make([]int, 5)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i], _, _ = h.refresh(*c.RefreshToken)
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, code := range codes {
		if code == http.StatusOK {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("%d concurrent refreshes succeeded, want exactly 1 (%v)", ok, codes)
	}
}

func TestExpiredAccessTokenAsksForRefresh(t *testing.T) {
	h := newHarness(t)
	_, _, addr := h.registerUser("mobile-expired")
	c := h.loginAs(addr, androidClient)

	if _, err := h.pool.Exec(context.Background(),
		`UPDATE sessions SET access_expires_at = now() - interval '1 minute' WHERE id = $1`, c.SessionId); err != nil {
		t.Fatal(err)
	}
	r := h.do(http.MethodGet, "/auth/me", "", c.Token)
	if r.Code != http.StatusUnauthorized || errorCode(t, r) != "access_token_expired" {
		t.Fatalf("expired access token: %d %s", r.Code, r.Body)
	}
	// A revoked or unknown token is a different answer: sign in again.
	r = h.do(http.MethodGet, "/auth/me", "", "unknown-token")
	if errorCode(t, r) != "unauthenticated" {
		t.Fatalf("unknown token code: %s", r.Body)
	}

	code, fresh, _ := h.refresh(*c.RefreshToken)
	if code != http.StatusOK {
		t.Fatalf("refresh after expiry: %d", code)
	}
	if r := h.do(http.MethodGet, "/auth/me", "", fresh.Token); r.Code != http.StatusOK {
		t.Fatalf("refreshed token: %d", r.Code)
	}
}

func TestListAndRevokeSessions(t *testing.T) {
	h := newHarness(t)
	_, _, addr := h.registerUser("devices")
	web := h.loginAs(addr, "")
	phone := h.loginAs(addr, androidClient)

	r := h.do(http.MethodGet, "/auth/sessions", "", web.Token)
	if r.Code != http.StatusOK {
		t.Fatalf("list: %d %s", r.Code, r.Body)
	}
	var list DeviceSessionList
	json.Unmarshal(r.Body.Bytes(), &list)
	found := map[string]DeviceSession{}
	for _, s := range list.Sessions {
		found[s.Id.String()] = s
	}
	if s, ok := found[web.SessionId.String()]; !ok || !s.Current || s.Client != SessionClientWeb {
		t.Fatalf("web session in list: %+v", s)
	}
	p, ok := found[phone.SessionId.String()]
	if !ok || p.Current || p.Client != SessionClientAndroid || deref(p.DeviceName) != "Pixel 9" || deref(p.AppVersion) != "1.0.0" {
		t.Fatalf("phone session in list: %+v", p)
	}

	// Another user can neither see nor revoke these.
	strangerToken, _, _ := h.registerUser("devices-stranger")
	if r := h.do(http.MethodDelete, "/auth/sessions/"+phone.SessionId.String(), "", strangerToken); r.Code != http.StatusNotFound {
		t.Fatalf("stranger revoked a session: %d", r.Code)
	}
	if r := h.do(http.MethodDelete, "/auth/sessions/00000000-0000-4000-8000-000000000000", "", web.Token); r.Code != http.StatusNotFound {
		t.Fatalf("unknown session: %d", r.Code)
	}
	if r := h.do(http.MethodGet, "/auth/sessions", "", ""); r.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous list: %d", r.Code)
	}

	if r := h.do(http.MethodDelete, "/auth/sessions/"+phone.SessionId.String(), "", web.Token); r.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", r.Code, r.Body)
	}
	if r := h.do(http.MethodGet, "/auth/me", "", phone.Token); r.Code != http.StatusUnauthorized {
		t.Fatalf("revoked access token works: %d", r.Code)
	}
	if code, _, ec := h.refresh(*phone.RefreshToken); code != http.StatusUnauthorized || ec != "invalid_refresh_token" {
		t.Fatalf("revoked session refreshed: %d %s", code, ec)
	}
	if r := h.do(http.MethodDelete, "/auth/sessions/"+phone.SessionId.String(), "", web.Token); r.Code != http.StatusNotFound {
		t.Fatalf("second revoke: %d", r.Code)
	}

	r = h.do(http.MethodGet, "/auth/sessions", "", web.Token)
	json.Unmarshal(r.Body.Bytes(), &list)
	for _, s := range list.Sessions {
		if s.Id == phone.SessionId {
			t.Fatal("revoked session still listed")
		}
	}
}

func TestMobileLogoutEndsRefreshChain(t *testing.T) {
	h := newHarness(t)
	_, _, addr := h.registerUser("mobile-logout")
	c := h.loginAs(addr, androidClient)

	if r := h.do(http.MethodPost, "/auth/logout", "", c.Token); r.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", r.Code)
	}
	if code, _, _ := h.refresh(*c.RefreshToken); code != http.StatusUnauthorized {
		t.Fatalf("refresh after logout: %d", code)
	}
}

func TestPasswordChangeKeepsMobileClient(t *testing.T) {
	h := newHarness(t)
	_, _, addr := h.registerUser("mobile-password")
	c := h.loginAs(addr, `,"client":"ios","device_name":"iPhone"`)

	r := h.do(http.MethodPost, "/auth/change-password",
		`{"current_password":"correct-horse-battery","password":"replacement-password-2026"}`, c.Token)
	if r.Code != http.StatusOK {
		t.Fatalf("change password: %d %s", r.Code, r.Body)
	}
	var fresh Credentials
	json.Unmarshal(r.Body.Bytes(), &fresh)
	if fresh.RefreshToken == nil {
		t.Fatal("password change from a phone returned a web session")
	}
	// Every earlier session, the phone's own included, is revoked.
	if code, _, _ := h.refresh(*c.RefreshToken); code != http.StatusUnauthorized {
		t.Fatalf("old refresh token survived a password change: %d", code)
	}
	if code, _, _ := h.refresh(*fresh.RefreshToken); code != http.StatusOK {
		t.Fatalf("fresh refresh token: %d", code)
	}
}
