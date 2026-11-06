package httpapi

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestChangePassword(t *testing.T) {
	h := newHarness(t)
	old, _, email := h.registerUser("change-password")
	for _, body := range []string{`{"current_password":"wrong","password":"replacement-password-2026"}`, `{"current_password":"correct-horse-battery","password":"correct-horse-battery"}`, `{"current_password":"correct-horse-battery","password":"short"}`} {
		if r := h.do("POST", "/auth/change-password", body, old); r.Code != 400 && r.Code != 403 {
			t.Fatalf("invalid change accepted: %d", r.Code)
		}
	}
	body := `{"current_password":"correct-horse-battery","password":"replacement-password-2026"}`
	if r := h.do("POST", "/auth/change-password", body, ""); r.Code != 401 {
		t.Fatal("anonymous change accepted")
	}
	result := h.do("POST", "/auth/change-password", body, old)
	if result.Code != 200 {
		t.Fatal(result.Body)
	}
	var fresh Credentials
	json.Unmarshal(result.Body.Bytes(), &fresh)
	if r := h.do("GET", "/auth/me", "", fresh.Token); r.Code != 200 {
		t.Fatal(r.Body)
	}
	if r := h.do("GET", "/auth/me", "", old); r.Code != 401 {
		t.Fatal("old session survived")
	}
	if r := h.do("POST", "/auth/login", fmt.Sprintf(`{"email":%q,"password":"correct-horse-battery"}`, email), ""); r.Code == 200 {
		t.Fatal("old password still works")
	}
	if r := h.do("POST", "/auth/login", fmt.Sprintf(`{"email":%q,"password":"replacement-password-2026"}`, email), ""); r.Code != 200 {
		t.Fatal(r.Body)
	}
}
