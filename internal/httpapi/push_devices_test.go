package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rnm/heromail/backend/internal/push"
)

func pushBody(token string) string {
	return fmt.Sprintf(`{"token":%q,"platform":"android","locale":"ru-KZ","timezone":"Asia/Almaty","app_version":"1.0.0"}`, token)
}

func newPushToken() string { return fmt.Sprintf("fcm-test-%d", time.Now().UnixNano()) }

// pushOwner returns which session holds the token, or "" if nobody does.
func (h *harness) pushOwner(token string) string {
	h.t.Helper()
	var sid string
	h.pool.QueryRow(context.Background(), `SELECT session_id::text FROM push_devices WHERE token = $1`, token).Scan(&sid)
	return sid
}

func (h *harness) pushCount(sessionID string) int {
	h.t.Helper()
	var n int
	h.pool.QueryRow(context.Background(), `SELECT count(*) FROM push_devices WHERE session_id = $1`, sessionID).Scan(&n)
	return n
}

func TestRegisterPushDevice(t *testing.T) {
	h := newHarness(t)
	_, _, addr := h.registerUser("push-register")
	phone := h.loginAs(addr, androidClient)
	token := newPushToken()

	if r := h.do(http.MethodPut, "/devices/push", pushBody(token), ""); r.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous register: %d", r.Code)
	}
	for _, bad := range []string{`{"token":"","platform":"android"}`, `{"token":"x","platform":"web"}`, `{"token":"x","platform":"ios","provider":"apns"}`} {
		if r := h.do(http.MethodPut, "/devices/push", bad, phone.Token); r.Code != http.StatusBadRequest {
			t.Fatalf("invalid registration %s: %d", bad, r.Code)
		}
	}

	r := h.do(http.MethodPut, "/devices/push", pushBody(token), phone.Token)
	if r.Code != http.StatusOK {
		t.Fatalf("register: %d %s", r.Code, r.Body)
	}
	var d PushDevice
	json.Unmarshal(r.Body.Bytes(), &d)
	if d.SessionId != phone.SessionId || d.Platform != PushDevicePlatformAndroid || d.Provider != "fcm" || deref(d.Timezone) != "Asia/Almaty" || d.Disabled {
		t.Fatalf("registration: %+v", d)
	}
	if strings.Contains(r.Body.String(), token) {
		t.Fatal("token echoed back")
	}

	// One token per session: a new token replaces the old one in place.
	replacement := newPushToken()
	if r := h.do(http.MethodPut, "/devices/push", pushBody(replacement), phone.Token); r.Code != http.StatusOK {
		t.Fatalf("re-register: %d", r.Code)
	}
	if h.pushCount(phone.SessionId.String()) != 1 || h.pushOwner(token) != "" || h.pushOwner(replacement) != phone.SessionId.String() {
		t.Fatal("session holds more than one token")
	}

	if r := h.do(http.MethodDelete, "/devices/push", "", phone.Token); r.Code != http.StatusNoContent {
		t.Fatalf("unregister: %d", r.Code)
	}
	if h.pushCount(phone.SessionId.String()) != 0 {
		t.Fatal("token survived unregister")
	}
	if r := h.do(http.MethodDelete, "/devices/push", "", phone.Token); r.Code != http.StatusNoContent {
		t.Fatalf("second unregister: %d", r.Code)
	}
}

func TestPushTokenMovesToNewUser(t *testing.T) {
	h := newHarness(t)
	_, _, alice := h.registerUser("push-alice")
	_, _, bob := h.registerUser("push-bob")
	a := h.loginAs(alice, androidClient)
	token := newPushToken()
	if r := h.do(http.MethodPut, "/devices/push", pushBody(token), a.Token); r.Code != http.StatusOK {
		t.Fatalf("alice register: %d", r.Code)
	}

	// Bob signs in on the same phone: the token now notifies Bob only.
	b := h.loginAs(bob, androidClient)
	if r := h.do(http.MethodPut, "/devices/push", pushBody(token), b.Token); r.Code != http.StatusOK {
		t.Fatalf("bob register: %d", r.Code)
	}
	if h.pushOwner(token) != b.SessionId.String() || h.pushCount(a.SessionId.String()) != 0 {
		t.Fatal("token not moved to the new session")
	}
	var owner string
	h.pool.QueryRow(context.Background(), `SELECT u.email FROM push_devices p JOIN users u ON u.id = p.user_id WHERE p.token = $1`, token).Scan(&owner)
	if owner != bob {
		t.Fatalf("token belongs to %q, want %q", owner, bob)
	}
}

func TestRevokedSessionHasNoPushToken(t *testing.T) {
	h := newHarness(t)
	_, _, addr := h.registerUser("push-revoke")
	register := func() (Credentials, string) {
		c := h.loginAs(addr, androidClient)
		token := newPushToken()
		if r := h.do(http.MethodPut, "/devices/push", pushBody(token), c.Token); r.Code != http.StatusOK {
			t.Fatalf("register: %d %s", r.Code, r.Body)
		}
		return c, token
	}

	// Logout.
	c, token := register()
	h.do(http.MethodPost, "/auth/logout", "", c.Token)
	if h.pushOwner(token) != "" {
		t.Fatal("token survived logout")
	}

	// Revoked from another device.
	web := h.loginAs(addr, "")
	c, token = register()
	if r := h.do(http.MethodDelete, "/auth/sessions/"+c.SessionId.String(), "", web.Token); r.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d", r.Code)
	}
	if h.pushOwner(token) != "" {
		t.Fatal("token survived session revocation")
	}

	// Refresh-token reuse.
	c, token = register()
	h.refresh(*c.RefreshToken)
	h.refresh(*c.RefreshToken)
	if h.pushOwner(token) != "" {
		t.Fatal("token survived reuse detection")
	}
}

func TestDisabledPushToken(t *testing.T) {
	h := newHarness(t)
	_, userID, addr := h.registerUser("push-disabled")
	c := h.loginAs(addr, androidClient)
	token := newPushToken()
	h.do(http.MethodPut, "/devices/push", pushBody(token), c.Token)

	store := push.NewStore(h.pool)
	ctx := context.Background()
	if targets, _ := store.Targets(ctx, userID); len(targets) != 1 || targets[0].Token != token {
		t.Fatalf("targets before disable: %+v", targets)
	}
	// What the sender does when FCM answers UNREGISTERED.
	if err := store.DisableToken(ctx, token); err != nil {
		t.Fatal(err)
	}
	if targets, _ := store.Targets(ctx, userID); len(targets) != 0 {
		t.Fatalf("disabled token still targeted: %+v", targets)
	}
	// Re-registering the same token brings it back.
	r := h.do(http.MethodPut, "/devices/push", pushBody(token), c.Token)
	var d PushDevice
	json.Unmarshal(r.Body.Bytes(), &d)
	if d.Disabled {
		t.Fatal("re-registration left the device disabled")
	}
	if targets, _ := store.Targets(ctx, userID); len(targets) != 1 {
		t.Fatalf("targets after re-register: %+v", targets)
	}
}
