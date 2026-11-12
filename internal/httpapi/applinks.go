package httpapi

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// AppLinkPaths are the web paths the mobile app opens instead of the browser.
// They are the web client's own routes, so a link opens the same thing in
// either: password reset, calendar invitations, and a message
// (/mail/{mailboxId}/{messageId}, also /mail/sent/...).
var AppLinkPaths = []string{"/reset-password", "/calendar/invite/*", "/mail/*"}

// AppLinks configures /.well-known/apple-app-site-association and
// /.well-known/assetlinks.json. Served by the API; nginx on the frontend host
// proxies exactly these two paths here (docs/app-links.md).
type AppLinks struct {
	IOSTeamID, IOSBundleID string
	AndroidPackage         string
	// AndroidCertSHA256 are signing-certificate fingerprints in the colon
	// form Google expects; several are allowed (upload key and Play signing
	// key). Empty means assetlinks.json answers an empty statement list.
	AndroidCertSHA256 []string
}

// AppLinksFromEnv reads IOS_TEAM_ID, IOS_BUNDLE_ID, ANDROID_PACKAGE and
// ANDROID_CERT_SHA256 (comma-separated). A malformed fingerprint is an error:
// a typo would otherwise ship a file Google silently rejects.
func AppLinksFromEnv() (AppLinks, error) {
	cfg := AppLinks{
		IOSTeamID:      strings.TrimSpace(os.Getenv("IOS_TEAM_ID")),
		IOSBundleID:    strings.TrimSpace(os.Getenv("IOS_BUNDLE_ID")),
		AndroidPackage: strings.TrimSpace(os.Getenv("ANDROID_PACKAGE")),
	}
	for _, raw := range strings.Split(os.Getenv("ANDROID_CERT_SHA256"), ",") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		fp, err := NormalizeCertFingerprint(raw)
		if err != nil {
			return cfg, err
		}
		cfg.AndroidCertSHA256 = append(cfg.AndroidCertSHA256, fp)
	}
	return cfg, nil
}

// NormalizeCertFingerprint accepts a SHA-256 fingerprint with or without
// colons, any case (as keytool or the Play console print it), and returns
// the uppercase colon-separated form.
func NormalizeCertFingerprint(raw string) (string, error) {
	compact := strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(raw))
	b, err := hex.DecodeString(compact)
	if err != nil || len(b) != 32 {
		return "", fmt.Errorf("ANDROID_CERT_SHA256: %q is not a SHA-256 fingerprint", raw)
	}
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = fmt.Sprintf("%02X", c)
	}
	return strings.Join(parts, ":"), nil
}

// SetAppLinks installs the association files' configuration.
func (s *Server) SetAppLinks(cfg AppLinks) { s.appLinks = cfg }

func (c AppLinks) appleAppSiteAssociation() any {
	details := []any{}
	webcredentials := []string{}
	if c.IOSTeamID != "" && c.IOSBundleID != "" {
		appID := c.IOSTeamID + "." + c.IOSBundleID
		components := make([]map[string]string, 0, len(AppLinkPaths))
		for _, p := range AppLinkPaths {
			components = append(components, map[string]string{"/": p})
		}
		details = append(details, map[string]any{
			// iOS 13+ reads appIDs/components; older versions read appID/paths.
			"appIDs":     []string{appID},
			"components": components,
			"appID":      appID,
			"paths":      AppLinkPaths,
		})
		webcredentials = append(webcredentials, appID)
	}
	return map[string]any{
		"applinks":       map[string]any{"apps": []string{}, "details": details},
		"webcredentials": map[string]any{"apps": webcredentials},
	}
}

func (c AppLinks) assetLinks() any {
	statements := []any{}
	if c.AndroidPackage != "" && len(c.AndroidCertSHA256) > 0 {
		statements = append(statements, map[string]any{
			"relation": []string{"delegate_permission/common.handle_all_urls", "delegate_permission/common.get_login_creds"},
			"target": map[string]any{
				"namespace":                "android_app",
				"package_name":             c.AndroidPackage,
				"sha256_cert_fingerprints": c.AndroidCertSHA256,
			},
		})
	}
	return statements
}

// appLinkFile serves one association file: JSON, never a redirect, cacheable
// for an hour (Apple's CDN and Android re-fetch on their own schedule anyway).
func (s *Server) appLinkFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body any
	if r.URL.Path == "/.well-known/assetlinks.json" {
		body = s.appLinks.assetLinks()
	} else {
		body = s.appLinks.appleAppSiteAssociation()
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(body)
}
