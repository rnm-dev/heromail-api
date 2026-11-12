package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testFingerprint = "14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:B2:3F:CF:44:E5"

func serveAppLink(t *testing.T, cfg AppLinks, path string) *httptest.ResponseRecorder {
	t.Helper()
	s := &Server{}
	s.SetAppLinks(cfg)
	rec := httptest.NewRecorder()
	s.appLinkFile(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("%s: %d %q", path, rec.Code, rec.Header().Get("Content-Type"))
	}
	return rec
}

var heromailApp = AppLinks{IOSTeamID: "F7KV67KV2U", IOSBundleID: "kz.heromail.mobile", AndroidPackage: "kz.heromail.mobile"}

func TestAppleAppSiteAssociation(t *testing.T) {
	var aasa struct {
		Applinks struct {
			Apps    []string `json:"apps"`
			Details []struct {
				AppIDs     []string            `json:"appIDs"`
				Components []map[string]string `json:"components"`
				AppID      string              `json:"appID"`
				Paths      []string            `json:"paths"`
			} `json:"details"`
		} `json:"applinks"`
		Webcredentials struct {
			Apps []string `json:"apps"`
		} `json:"webcredentials"`
	}
	json.Unmarshal(serveAppLink(t, heromailApp, "/.well-known/apple-app-site-association").Body.Bytes(), &aasa)
	if len(aasa.Applinks.Details) != 1 {
		t.Fatalf("details: %+v", aasa)
	}
	d := aasa.Applinks.Details[0]
	if len(d.AppIDs) != 1 || d.AppIDs[0] != "F7KV67KV2U.kz.heromail.mobile" || d.AppID != d.AppIDs[0] {
		t.Fatalf("app id: %+v", d)
	}
	var paths []string
	for _, c := range d.Components {
		paths = append(paths, c["/"])
	}
	if strings.Join(paths, " ") != "/reset-password /calendar/invite/* /mail/*" || strings.Join(d.Paths, " ") != strings.Join(paths, " ") {
		t.Fatalf("paths: %v / %v", paths, d.Paths)
	}
	if aasa.Applinks.Apps == nil || len(aasa.Webcredentials.Apps) != 1 {
		t.Fatalf("apps/webcredentials: %+v", aasa)
	}

	// Unconfigured: still a valid, empty association file.
	empty := serveAppLink(t, AppLinks{}, "/.well-known/apple-app-site-association").Body.String()
	if !strings.Contains(empty, `"details":[]`) {
		t.Fatalf("empty AASA: %s", empty)
	}
}

func TestAssetLinks(t *testing.T) {
	// No signing key yet: an empty statement list, not a 404.
	if body := strings.TrimSpace(serveAppLink(t, heromailApp, "/.well-known/assetlinks.json").Body.String()); body != "[]" {
		t.Fatalf("without fingerprint: %s", body)
	}

	cfg := heromailApp
	cfg.AndroidCertSHA256 = []string{testFingerprint}
	var statements []struct {
		Relation []string `json:"relation"`
		Target   struct {
			Namespace    string   `json:"namespace"`
			PackageName  string   `json:"package_name"`
			Fingerprints []string `json:"sha256_cert_fingerprints"`
		} `json:"target"`
	}
	json.Unmarshal(serveAppLink(t, cfg, "/.well-known/assetlinks.json").Body.Bytes(), &statements)
	if len(statements) != 1 {
		t.Fatalf("statements: %+v", statements)
	}
	st := statements[0]
	if st.Relation[0] != "delegate_permission/common.handle_all_urls" || st.Target.Namespace != "android_app" ||
		st.Target.PackageName != "kz.heromail.mobile" || len(st.Target.Fingerprints) != 1 || st.Target.Fingerprints[0] != testFingerprint {
		t.Fatalf("statement: %+v", st)
	}
}

func TestAppLinksFromEnv(t *testing.T) {
	t.Setenv("IOS_TEAM_ID", "F7KV67KV2U")
	t.Setenv("IOS_BUNDLE_ID", "kz.heromail.mobile")
	t.Setenv("ANDROID_PACKAGE", "kz.heromail.mobile")
	// keytool prints colons; the Play console may be copied without them, in any case.
	t.Setenv("ANDROID_CERT_SHA256", strings.ToLower(strings.ReplaceAll(testFingerprint, ":", ""))+", "+testFingerprint)
	cfg, err := AppLinksFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.AndroidCertSHA256) != 2 || cfg.AndroidCertSHA256[0] != testFingerprint || cfg.AndroidCertSHA256[1] != testFingerprint {
		t.Fatalf("fingerprints: %v", cfg.AndroidCertSHA256)
	}
	for _, bad := range []string{"AB:CD", "zz" + strings.Repeat("00", 31), testFingerprint + ":00"} {
		t.Setenv("ANDROID_CERT_SHA256", bad)
		if _, err := AppLinksFromEnv(); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

// Through the real router: public, no redirect, and the web client's own
// /mail and /reset-password routes are not affected (they are not API paths).
func TestAppLinksThroughRouter(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{"/.well-known/apple-app-site-association", "/.well-known/assetlinks.json"} {
		r := h.do(http.MethodGet, p, "", "")
		if r.Code != http.StatusOK || r.Header().Get("Content-Type") != "application/json" || r.Header().Get("Location") != "" {
			t.Fatalf("%s: %d %v", p, r.Code, r.Header())
		}
		if !json.Valid(r.Body.Bytes()) {
			t.Fatalf("%s: not JSON: %s", p, r.Body)
		}
	}
}
