package fcm

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeFCM issues OAuth tokens and answers messages:send with the scripted
// statuses, in order; after the script runs out it answers 200.
type fakeFCM struct {
	tokenCalls, sendCalls int32
	script                []func(w http.ResponseWriter)
	bodies                []map[string]any
}

func newFake(t *testing.T, script ...func(w http.ResponseWriter)) (*Client, *fakeFCM) {
	t.Helper()
	f := &fakeFCM{script: script}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&f.tokenCalls, 1)
		r.ParseForm()
		parts := strings.Split(r.Form.Get("assertion"), ".")
		if len(parts) != 3 || r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			t.Errorf("bad grant: %v", r.Form)
		}
		raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var claims struct{ Iss, Scope, Sub string }
		json.Unmarshal(raw, &claims)
		if claims.Scope != Scope || claims.Iss != "sa@heromail-4dcf6.iam.gserviceaccount.com" || claims.Sub != "" {
			t.Errorf("claims: %+v", claims)
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": "ya29.test", "expires_in": 3600})
	})
	mux.HandleFunc("/v1/projects/heromail-4dcf6/messages:send", func(w http.ResponseWriter, r *http.Request) {
		n := int(atomic.AddInt32(&f.sendCalls, 1))
		if r.Header.Get("Authorization") != "Bearer ya29.test" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		json.Unmarshal(raw, &body)
		f.bodies = append(f.bodies, body)
		if n <= len(f.script) {
			f.script[n-1](w)
			return
		}
		w.Write([]byte(`{"name":"projects/heromail-4dcf6/messages/1"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	creds, _ := json.Marshal(map[string]string{"type": "service_account", "project_id": "other-project",
		"client_email": "sa@heromail-4dcf6.iam.gserviceaccount.com",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), "token_uri": srv.URL + "/token"})
	c, err := New(creds, "heromail-4dcf6")
	if err != nil {
		t.Fatal(err)
	}
	c.apiURL, c.backoff = srv.URL, time.Millisecond
	return c, f
}

func fcmFailure(status int, code, message string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
			"code": status, "message": message, "status": "X",
			"details": []map[string]string{{"@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError", "errorCode": code}},
		}})
	}
}

func TestSendUsesProjectAndCachesToken(t *testing.T) {
	c, f := newFake(t)
	msg := Message{Token: "device-1", Data: map[string]string{"message_id": "m"}}
	for i := 0; i < 2; i++ {
		if err := c.Send(context.Background(), msg); err != nil {
			t.Fatal(err)
		}
	}
	if f.tokenCalls != 1 || f.sendCalls != 2 {
		t.Fatalf("token calls %d, send calls %d", f.tokenCalls, f.sendCalls)
	}
	m := f.bodies[0]["message"].(map[string]any)
	if m["token"] != "device-1" || m["data"].(map[string]any)["message_id"] != "m" {
		t.Fatalf("body: %v", f.bodies[0])
	}
	if _, ok := m["notification"]; ok {
		t.Fatal("empty notification serialised")
	}
}

func TestSendRetriesTransientFailures(t *testing.T) {
	c, f := newFake(t, fcmFailure(503, "UNAVAILABLE", "try later"), fcmFailure(429, "QUOTA_EXCEEDED", "slow down"))
	if err := c.Send(context.Background(), Message{Token: "t"}); err != nil {
		t.Fatalf("retried send: %v", err)
	}
	if f.sendCalls != 3 {
		t.Fatalf("send calls %d, want 3", f.sendCalls)
	}

	c, f = newFake(t, fcmFailure(500, "INTERNAL", "a"), fcmFailure(500, "INTERNAL", "b"), fcmFailure(500, "INTERNAL", "c"))
	if err := c.Send(context.Background(), Message{Token: "t"}); err == nil || errors.Is(err, ErrUnregistered) {
		t.Fatalf("exhausted retries: %v", err)
	}
	if f.sendCalls != 3 {
		t.Fatalf("send calls %d, want 3", f.sendCalls)
	}
}

func TestSendReportsDeadTokens(t *testing.T) {
	for name, fail := range map[string]func(http.ResponseWriter){
		"unregistered":  fcmFailure(404, "UNREGISTERED", "Requested entity was not found."),
		"bad token":     fcmFailure(400, "INVALID_ARGUMENT", "The registration token is not a valid FCM registration token"),
		"other project": fcmFailure(403, "SENDER_ID_MISMATCH", "SenderId mismatch"),
	} {
		c, f := newFake(t, fail)
		if err := c.Send(context.Background(), Message{Token: "t"}); !errors.Is(err, ErrUnregistered) {
			t.Fatalf("%s: %v", name, err)
		}
		if f.sendCalls != 1 {
			t.Fatalf("%s: retried a dead token", name)
		}
	}
	// A malformed payload is our bug, not the device's.
	c, _ := newFake(t, fcmFailure(400, "INVALID_ARGUMENT", "Invalid value at 'message.data'"))
	if err := c.Send(context.Background(), Message{Token: "t"}); err == nil || errors.Is(err, ErrUnregistered) {
		t.Fatalf("payload error: %v", err)
	}
}

func TestNewRequiresProject(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	creds, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "sa@x",
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))})
	if _, err := New(creds, ""); err == nil {
		t.Fatal("client without a project")
	}
	if _, err := New([]byte(`{"type":"authorized_user"}`), "p"); err == nil {
		t.Fatal("non-service-account key accepted")
	}
}
