package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVersionOrdering(t *testing.T) {
	// Each version is lower than the next.
	ordered := []string{"0.9.9", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
		"1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.2", "1.2.1", "1.2.10", "1.10.0", "2"}
	for i := 0; i+1 < len(ordered); i++ {
		a, err1 := ParseVersion(ordered[i])
		b, err2 := ParseVersion(ordered[i+1])
		if err1 != nil || err2 != nil {
			t.Fatalf("parse %s / %s: %v %v", ordered[i], ordered[i+1], err1, err2)
		}
		if !a.Less(b) || b.Less(a) {
			t.Errorf("want %s < %s", ordered[i], ordered[i+1])
		}
	}
	// Build metadata and a leading v do not change the version.
	a, _ := ParseVersion("1.2.3+45")
	b, _ := ParseVersion("v1.2.3")
	if a.Less(b) || b.Less(a) || a.String() != "1.2.3" {
		t.Fatalf("1.2.3+45 vs v1.2.3: %v %v", a, b)
	}
	for _, bad := range []string{"", "x", "1.x", "1.2.3.4", "1.-1.0", "1.2.3-", "1..2", "1234567890.0.0"} {
		if _, err := ParseVersion(bad); err == nil {
			t.Errorf("parsed %q", bad)
		}
	}
}

func TestMobilePolicyFromEnv(t *testing.T) {
	t.Setenv("MOBILE_IOS_MIN_VERSION", "1.2.0")
	t.Setenv("MOBILE_IOS_LATEST_VERSION", "1.4.1")
	t.Setenv("MOBILE_IOS_STORE_URL", "https://apps.apple.com/app/id1")
	t.Setenv("MOBILE_ANDROID_MIN_VERSION", "")
	t.Setenv("MOBILE_FEATURES", "calendar, offline=false ,push=true")
	cfg, err := MobilePolicyFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IOS.MinSupported.String() != "1.2.0" || cfg.IOS.Latest.String() != "1.4.1" || cfg.Android.MinSupported != nil {
		t.Fatalf("versions: %+v", cfg)
	}
	if !cfg.Features["calendar"] || cfg.Features["offline"] || !cfg.Features["push"] || len(cfg.Features) != 3 {
		t.Fatalf("features: %v", cfg.Features)
	}
	// A typo must not silently switch the gate off.
	for env, value := range map[string]string{"MOBILE_ANDROID_MIN_VERSION": "1.2.x", "MOBILE_IOS_LATEST_VERSION": "1.0.0", "MOBILE_FEATURES": "push=maybe"} {
		t.Run(env, func(t *testing.T) {
			t.Setenv(env, value)
			if _, err := MobilePolicyFromEnv(); err == nil {
				t.Fatalf("%s=%s accepted", env, value)
			}
		})
	}
}

func (h *harness) doClient(method, path, body, token, client, version string) *httptest.ResponseRecorder {
	h.t.Helper()
	r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if client != "" {
		r.Header.Set("X-Client", client)
	}
	if version != "" {
		r.Header.Set("X-App-Version", version)
	}
	r.Header.Set("X-Forwarded-For", h.clientIP)
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, r)
	return rec
}

func mustVersion(t *testing.T, s string) *Version {
	t.Helper()
	v, err := ParseVersion(s)
	if err != nil {
		t.Fatal(err)
	}
	return &v
}

func TestMobileConfigEndpoint(t *testing.T) {
	h := newHarness(t)
	h.server.SetMobilePolicy(MobilePolicy{
		IOS:      PlatformConfig{MinSupported: mustVersion(t, "1.2.0"), Latest: mustVersion(t, "1.4.0"), StoreURL: "https://apps.apple.com/app/id1"},
		Features: map[string]bool{"calendar": true},
		TermsURL: "https://heromail.kz/terms",
	})
	// Public, and readable even by an app far below the minimum.
	r := h.doClient(http.MethodGet, "/mobile/config", "", "", "ios", "0.1.0")
	if r.Code != http.StatusOK {
		t.Fatalf("config: %d %s", r.Code, r.Body)
	}
	var cfg MobileConfig
	json.Unmarshal(r.Body.Bytes(), &cfg)
	if deref(cfg.Ios.MinSupportedVersion) != "1.2.0" || deref(cfg.Ios.LatestVersion) != "1.4.0" || deref(cfg.Ios.StoreUrl) == "" ||
		cfg.Android.MinSupportedVersion != nil || !cfg.Features["calendar"] || deref(cfg.TermsUrl) == "" || cfg.PrivacyPolicyUrl != nil {
		t.Fatalf("config: %s", r.Body)
	}
}

func TestUpdateGate(t *testing.T) {
	h := newHarness(t)
	h.server.SetMobilePolicy(MobilePolicy{
		Android: PlatformConfig{MinSupported: mustVersion(t, "1.2.0"), Latest: mustVersion(t, "1.4.0"),
			StoreURL: "https://play.google.com/store/apps/details?id=kz.heromail.mobile"},
	})
	token, _, addr := h.registerUser("update-gate")

	r := h.doClient(http.MethodGet, "/workspaces", "", token, "android", "1.1.9")
	if r.Code != http.StatusUpgradeRequired || errorCode(t, r) != "app_update_required" {
		t.Fatalf("old app: %d %s", r.Code, r.Body)
	}
	var body struct {
		Error struct {
			Details map[string]string `json:"details"`
		} `json:"error"`
	}
	json.Unmarshal(r.Body.Bytes(), &body)
	d := body.Error.Details
	if d["platform"] != "android" || d["current_version"] != "1.1.9" || d["min_supported_version"] != "1.2.0" ||
		d["latest_version"] != "1.4.0" || d["store_url"] == "" {
		t.Fatalf("details: %v", d)
	}

	for _, c := range []struct {
		name, client, version string
		gated                 bool
	}{
		{"pre-release of the minimum", "android", "1.2.0-beta.1", true},
		{"build number does not help", "android", "1.1.9+999", true},
		{"anonymous request is gated too", "android", "1.0.0", true},
		{"exactly the minimum", "android", "1.2.0", false},
		{"newer", "android", "1.3.0+12", false},
		{"web client", "web", "0.0.1", false},
		{"no headers (web)", "", "", false},
		{"client without version", "android", "", false},
		{"unparseable version", "android", "nightly", false},
		{"platform without a minimum", "ios", "0.0.1", false},
	} {
		tok := token
		if c.name == "anonymous request is gated too" {
			tok = ""
		}
		r := h.doClient(http.MethodGet, "/workspaces", "", tok, c.client, c.version)
		if (r.Code == http.StatusUpgradeRequired) != c.gated {
			t.Errorf("%s: %d", c.name, r.Code)
		}
	}

	// What an outdated app needs to show the update screen and sign out.
	login := fmt.Sprintf(`{"email":%q,"password":"correct-horse-battery"}`, addr)
	for _, c := range []struct{ method, path, body, token string }{
		{http.MethodGet, "/mobile/config", "", ""},
		{http.MethodGet, "/health", "", ""},
		{http.MethodPost, "/auth/login", login, ""},
		{http.MethodGet, "/auth/me", "", token},
		{http.MethodPost, "/auth/refresh", `{"refresh_token":"x"}`, ""},
		{http.MethodGet, "/.well-known/assetlinks.json", "", ""},
		{http.MethodGet, "/account-deletion", "", ""},
		{http.MethodPost, "/auth/logout", "", token},
	} {
		if r := h.doClient(c.method, c.path, c.body, c.token, "android", "1.0.0"); r.Code == http.StatusUpgradeRequired {
			t.Errorf("%s %s gated", c.method, c.path)
		}
	}
}

func TestAppHeadersReachTheSession(t *testing.T) {
	h := newHarness(t)
	_, _, addr := h.registerUser("app-headers")
	// The body does not name a client; the headers do.
	r := h.doClient(http.MethodPost, "/auth/login", fmt.Sprintf(`{"email":%q,"password":"correct-horse-battery"}`, addr), "", "android", "1.3.0+7")
	if r.Code != http.StatusOK {
		t.Fatalf("login: %d %s", r.Code, r.Body)
	}
	var c Credentials
	json.Unmarshal(r.Body.Bytes(), &c)
	if c.RefreshToken == nil {
		t.Fatal("X-Client: android did not produce a mobile session")
	}
	version := func() string {
		var v string
		h.pool.QueryRow(context.Background(), `SELECT coalesce(app_version, '') FROM sessions WHERE id = $1`, c.SessionId).Scan(&v)
		return v
	}
	if version() != "1.3.0+7" {
		t.Fatalf("app_version: %q", version())
	}
	// After an app update the next touch records the new version.
	h.pool.Exec(context.Background(), `UPDATE sessions SET last_seen_at = NULL WHERE id = $1`, c.SessionId)
	if r := h.doClient(http.MethodGet, "/auth/me", "", c.Token, "android", "1.4.0+9"); r.Code != http.StatusOK {
		t.Fatalf("me: %d", r.Code)
	}
	if version() != "1.4.0+9" {
		t.Fatalf("app_version after update: %q", version())
	}
	// A web login with stray headers stays a web session.
	r = h.doClient(http.MethodPost, "/auth/login", fmt.Sprintf(`{"email":%q,"password":"correct-horse-battery"}`, addr), "", "web", "")
	var web Credentials
	json.Unmarshal(r.Body.Bytes(), &web)
	if r.Code != http.StatusOK || web.RefreshToken != nil {
		t.Fatal("X-Client: web produced a mobile session")
	}
}
