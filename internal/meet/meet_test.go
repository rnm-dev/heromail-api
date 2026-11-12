package meet

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeGoogle issues tokens only for the users in allowed and creates spaces.
func fakeGoogle(t *testing.T, allowed ...string) (*Client, *int32) {
	t.Helper()
	var tokenCalls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&tokenCalls, 1)
		r.ParseForm()
		parts := strings.Split(r.Form.Get("assertion"), ".")
		if len(parts) != 3 {
			t.Fatalf("assertion: %q", r.Form.Get("assertion"))
		}
		var claims struct{ Sub, Scope string }
		raw, _ := b64(parts[1])
		json.Unmarshal(raw, &claims)
		if claims.Scope != Scope {
			t.Fatalf("scope %q", claims.Scope)
		}
		for _, a := range allowed {
			if a == claims.Sub {
				json.NewEncoder(w).Encode(map[string]any{"access_token": "tok-" + a, "expires_in": 3600})
				return
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized_client"}`))
	})
	mux.HandleFunc("/v2/spaces", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer tok-") || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Write([]byte(`{"name":"spaces/x","meetingUri":"https://meet.google.com/abc-defg-hij","meetingCode":"abc-defg-hij"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	creds, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "sa@p.iam.gserviceaccount.com",
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), "token_uri": srv.URL + "/token"})
	c, err := New(creds, "Host@RNM.dev")
	if err != nil {
		t.Fatal(err)
	}
	c.apiURL = srv.URL + "/v2"
	return c, &tokenCalls
}

func TestCreateSpace(t *testing.T) {
	c, calls := fakeGoogle(t, "anna@rnm.dev", "host@rnm.dev")
	s, err := c.CreateSpace(t.Context(), "Anna@rnm.dev")
	if err != nil || s.URL != "https://meet.google.com/abc-defg-hij" || s.Host != "anna@rnm.dev" {
		t.Fatalf("organizer: %+v %v", s, err)
	}
	if _, err := c.CreateSpace(t.Context(), "anna@rnm.dev"); err != nil || atomic.LoadInt32(calls) != 1 {
		t.Fatalf("token not cached: %d calls, %v", *calls, err)
	}
	s, err = c.CreateSpace(t.Context(), "nogoogle@rnm.dev")
	if err != nil || s.Host != "host@rnm.dev" {
		t.Fatalf("fallback: %+v %v", s, err)
	}
}

func TestCreateSpaceNoAccount(t *testing.T) {
	c, _ := fakeGoogle(t)
	if _, err := c.CreateSpace(t.Context(), "x@rnm.dev"); !errors.Is(err, ErrNoGoogleAccount) {
		t.Fatalf("want ErrNoGoogleAccount, got %v", err)
	}
}

func TestNewRejectsBadCredentials(t *testing.T) {
	for _, raw := range []string{`{}`, `{"type":"authorized_user"}`, `{"type":"service_account","client_email":"a","private_key":"x"}`} {
		if _, err := New([]byte(raw), ""); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func b64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
