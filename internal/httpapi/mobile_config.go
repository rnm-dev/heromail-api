package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// Version is a parsed x.y.z[-pre][+build]. Build metadata (Flutter's
// "+45" build number) is ignored for ordering, as semver says.
type Version struct {
	Major, Minor, Patch int
	Pre                 string
}

// ParseVersion accepts "1", "1.2", "1.2.3", with optional "-pre" and "+build"
// and a leading "v". Missing parts are zero.
func ParseVersion(s string) (Version, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	var v Version
	if i := strings.IndexByte(s, '-'); i >= 0 {
		s, v.Pre = s[:i], s[i+1:]
		if v.Pre == "" {
			return Version{}, fmt.Errorf("version %q: empty pre-release", s)
		}
	}
	parts := strings.Split(s, ".")
	if s == "" || len(parts) > 3 {
		return Version{}, fmt.Errorf("version %q: want x.y.z", s)
	}
	nums := [3]int{}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || len(p) > 9 {
			return Version{}, fmt.Errorf("version %q: %q is not a number", s, p)
		}
		nums[i] = n
	}
	v.Major, v.Minor, v.Patch = nums[0], nums[1], nums[2]
	return v, nil
}

// Less orders versions; a pre-release sorts before its release.
func (v Version) Less(o Version) bool {
	if v.Major != o.Major {
		return v.Major < o.Major
	}
	if v.Minor != o.Minor {
		return v.Minor < o.Minor
	}
	if v.Patch != o.Patch {
		return v.Patch < o.Patch
	}
	switch {
	case v.Pre == o.Pre:
		return false
	case v.Pre == "":
		return false
	case o.Pre == "":
		return true
	}
	return comparePre(v.Pre, o.Pre) < 0
}

// comparePre compares dot-separated pre-release identifiers: numeric ones
// numerically and below alphanumeric ones, a shorter prefix first.
func comparePre(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		an, aErr := strconv.Atoi(as[i])
		bn, bErr := strconv.Atoi(bs[i])
		switch {
		case aErr == nil && bErr == nil:
			if an != bn {
				if an < bn {
					return -1
				}
				return 1
			}
		case aErr == nil:
			return -1
		case bErr == nil:
			return 1
		default:
			if c := strings.Compare(as[i], bs[i]); c != 0 {
				return c
			}
		}
	}
	return len(as) - len(bs)
}

func (v Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	return s
}

// PlatformConfig is one store's release policy.
type PlatformConfig struct {
	MinSupported, Latest *Version
	StoreURL             string
}

// MobilePolicy is what GET /mobile/config publishes and the version gate
// enforces. All of it comes from the environment (MobilePolicyFromEnv), so a
// forced update is a config change plus `docker compose up -d backend`.
type MobilePolicy struct {
	IOS, Android         PlatformConfig
	PrivacyURL, TermsURL string
	AccountDeletionURL   string
	Features             map[string]bool
}

// MobilePolicyFromEnv reads MOBILE_{IOS,ANDROID}_{MIN_VERSION,LATEST_VERSION,
// STORE_URL}, MOBILE_PRIVACY_URL, MOBILE_TERMS_URL,
// MOBILE_ACCOUNT_DELETION_URL and MOBILE_FEATURES ("name=true,other=false";
// a bare name means true). Malformed versions are an error: a typo in the
// minimum must not silently disable the gate.
func MobilePolicyFromEnv() (MobilePolicy, error) {
	cfg := MobilePolicy{
		PrivacyURL:         strings.TrimSpace(os.Getenv("MOBILE_PRIVACY_URL")),
		TermsURL:           strings.TrimSpace(os.Getenv("MOBILE_TERMS_URL")),
		AccountDeletionURL: strings.TrimSpace(os.Getenv("MOBILE_ACCOUNT_DELETION_URL")),
		Features:           map[string]bool{},
	}
	for _, p := range []struct {
		prefix string
		into   *PlatformConfig
	}{{"MOBILE_IOS", &cfg.IOS}, {"MOBILE_ANDROID", &cfg.Android}} {
		for _, f := range []struct {
			name string
			into **Version
		}{{"_MIN_VERSION", &p.into.MinSupported}, {"_LATEST_VERSION", &p.into.Latest}} {
			raw := strings.TrimSpace(os.Getenv(p.prefix + f.name))
			if raw == "" {
				continue
			}
			v, err := ParseVersion(raw)
			if err != nil {
				return cfg, fmt.Errorf("%s%s: %w", p.prefix, f.name, err)
			}
			*f.into = &v
		}
		if min, latest := p.into.MinSupported, p.into.Latest; min != nil && latest != nil && latest.Less(*min) {
			return cfg, fmt.Errorf("%s: latest version %s is below the minimum %s", p.prefix, latest, min)
		}
		p.into.StoreURL = strings.TrimSpace(os.Getenv(p.prefix + "_STORE_URL"))
	}
	for _, item := range strings.Split(os.Getenv("MOBILE_FEATURES"), ",") {
		name, value, hasValue := strings.Cut(strings.TrimSpace(item), "=")
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		on := true
		if hasValue {
			b, err := strconv.ParseBool(strings.TrimSpace(value))
			if err != nil {
				return cfg, fmt.Errorf("MOBILE_FEATURES: %q is not true/false", item)
			}
			on = b
		}
		cfg.Features[name] = on
	}
	return cfg, nil
}

// SetMobilePolicy installs the release policy for /mobile/config and the gate.
func (s *Server) SetMobilePolicy(cfg MobilePolicy) { s.mobile = cfg }

func (c MobilePolicy) platform(client string) (*PlatformConfig, bool) {
	switch strings.ToLower(strings.TrimSpace(client)) {
	case "ios":
		return &c.IOS, true
	case "android":
		return &c.Android, true
	}
	return nil, false
}

func versionString(v *Version) *string {
	if v == nil {
		return nil
	}
	s := v.String()
	return &s
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func platformToAPI(p PlatformConfig) MobilePlatformConfig {
	return MobilePlatformConfig{MinSupportedVersion: versionString(p.MinSupported),
		LatestVersion: versionString(p.Latest), StoreUrl: optional(p.StoreURL)}
}

func (s *Server) GetMobileConfig(_ context.Context, _ GetMobileConfigRequestObject) (GetMobileConfigResponseObject, error) {
	c := s.mobile
	features := c.Features
	if features == nil {
		features = map[string]bool{}
	}
	return GetMobileConfig200JSONResponse{
		Ios: platformToAPI(c.IOS), Android: platformToAPI(c.Android), Features: features,
		PrivacyPolicyUrl: optional(c.PrivacyURL), TermsUrl: optional(c.TermsURL),
		AccountDeletionUrl: optional(c.AccountDeletionURL),
	}, nil
}

// updateExempt are the paths an outdated app still needs to explain itself:
// fetch the config, sign in and out (so a session can be ended), see who is
// signed in and delete the account, plus the public non-API files.
func updateExempt(path string) bool {
	switch path {
	case "/health", "/mobile/config", "/auth/login", "/auth/logout", "/auth/refresh", "/auth/me", "/account-deletion":
		return true
	}
	return strings.HasPrefix(path, "/.well-known/")
}

// requireSupportedVersion answers 426 app_update_required to a mobile app
// (X-Client: ios|android) whose X-App-Version is below that platform's
// minimum. Requests without the headers — the web client, API keys, mail
// protocols' HTTP neighbours — and unparseable versions pass untouched.
func (s *Server) requireSupportedVersion(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		client, raw := r.Header.Get("X-Client"), r.Header.Get("X-App-Version")
		p, mobile := s.mobile.platform(client)
		if !mobile || raw == "" || p.MinSupported == nil || updateExempt(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		v, err := ParseVersion(raw)
		if err != nil || !v.Less(*p.MinSupported) {
			next.ServeHTTP(w, r)
			return
		}
		log.Printf("httpapi: 426 for %s %s from %s %s (minimum %s)", r.Method, r.URL.Path, client, raw, p.MinSupported)
		body := errorBody("app_update_required", "Эта версия приложения больше не поддерживается. Обновите Heromail.")
		details := map[string]any{"platform": strings.ToLower(client), "current_version": v.String(),
			"min_supported_version": p.MinSupported.String()}
		if p.Latest != nil {
			details["latest_version"] = p.Latest.String()
		}
		if p.StoreURL != "" {
			details["store_url"] = p.StoreURL
		}
		body.Error.Details = details
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusUpgradeRequired)
		json.NewEncoder(w).Encode(body)
	})
}
