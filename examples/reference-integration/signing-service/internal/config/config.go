// Package config loads the reference signing service's run profile from the environment
// (12-factor) and fails fast on an invalid/half-configured profile.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Mode selects credential-free fixtures vs live Cleverbase.
type Mode string

// Supported run modes.
const (
	ModeFixtures Mode = "fixtures"
	ModeLive     Mode = "live"
)

// Profile is the validated run configuration (data-model: RunProfile).
type Profile struct {
	Mode         Mode
	Environment  string // "acceptance" | "production"
	CscAPI       string // "v1_rsa" | "v2_ecdsa"
	ClientID     string
	ClientSecret string
	RedirectURI  string
	TsaURL       string
	TsaAuth      string
	TsaPolicy    string

	// UpstreamBaseURL is the mock upstream's base in fixtures mode. The SDK emits URLs against the
	// real Cleverbase host; in fixtures mode the service rewrites server-side effect requests to this
	// base. Empty in live.
	UpstreamBaseURL string
	// PublicUpstreamBaseURL is the browser-reachable base used to rewrite the authorization redirect
	// URLs handed back to the frontend (an internal compose/k8s hostname is not resolvable from the
	// user's browser). Defaults to UpstreamBaseURL. Empty in live (no rewrite).
	PublicUpstreamBaseURL string

	APIKey      string // bearer API key for the service's own REST API
	AuthEnabled bool

	DefaultConformance string // "B-B" | "B-T" when a request omits conformanceLevel
	SessionTTL         time.Duration
	Listen             string
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// Load reads and validates the profile from REFSVC_* environment variables.
func Load() (*Profile, error) {
	p := &Profile{
		Mode:                  Mode(env("REFSVC_MODE", string(ModeFixtures))),
		Environment:           env("REFSVC_ENV", "acceptance"),
		CscAPI:                env("REFSVC_CSC_API", "v1_rsa"),
		ClientID:              os.Getenv("REFSVC_CLIENT_ID"),
		ClientSecret:          os.Getenv("REFSVC_CLIENT_SECRET"),
		RedirectURI:           os.Getenv("REFSVC_REDIRECT_URI"),
		TsaURL:                os.Getenv("REFSVC_TSA_URL"),
		TsaAuth:               os.Getenv("REFSVC_TSA_AUTH"),
		TsaPolicy:             os.Getenv("REFSVC_TSA_POLICY"),
		UpstreamBaseURL:       os.Getenv("REFSVC_BASE_URL"),
		PublicUpstreamBaseURL: os.Getenv("REFSVC_PUBLIC_BASE_URL"),
		APIKey:                os.Getenv("REFSVC_API_KEY"),
		DefaultConformance:    env("REFSVC_DEFAULT_CONFORMANCE", "B-B"),
		Listen:                env("REFSVC_LISTEN", ":8080"),
	}

	ttlStr := env("REFSVC_SESSION_TTL", "15m")
	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid REFSVC_SESSION_TTL %q: %w", ttlStr, err)
	}
	p.SessionTTL = ttl

	// API auth is ON by default: require a key unless explicitly disabled for local runs.
	authDisabled := strings.EqualFold(os.Getenv("REFSVC_AUTH_DISABLED"), "true")
	switch {
	case p.APIKey != "":
		p.AuthEnabled = true
	case authDisabled:
		p.AuthEnabled = false
	default:
		return nil, fmt.Errorf("API auth is on by default: set REFSVC_API_KEY, or REFSVC_AUTH_DISABLED=true for local fixtures runs")
	}

	if p.DefaultConformance != "B-B" && p.DefaultConformance != "B-T" {
		return nil, fmt.Errorf("invalid REFSVC_DEFAULT_CONFORMANCE %q (B-B|B-T)", p.DefaultConformance)
	}

	switch p.Mode {
	case ModeFixtures:
		if p.UpstreamBaseURL == "" {
			return nil, fmt.Errorf("fixtures mode requires REFSVC_BASE_URL (the mock upstream URL)")
		}
		// The SDK requires a non-empty client_id/redirect_uri even though the mock ignores them;
		// supply harmless defaults so fixtures runs need no Cleverbase credentials.
		if p.ClientID == "" {
			p.ClientID = "refsvc-fixtures"
		}
		if p.ClientSecret == "" {
			p.ClientSecret = "fixtures"
		}
		if p.RedirectURI == "" {
			p.RedirectURI = "http://localhost:8080/return"
		}
		// B-T fixtures: the mock serves an RFC 3161 TSA at /tsr.
		if p.TsaURL == "" {
			p.TsaURL = strings.TrimRight(p.UpstreamBaseURL, "/") + "/tsr"
		}
		// Browser-facing redirect rewrites default to the internal base unless a public one is set.
		if p.PublicUpstreamBaseURL == "" {
			p.PublicUpstreamBaseURL = p.UpstreamBaseURL
		}
	case ModeLive:
		var missing []string
		if p.ClientID == "" {
			missing = append(missing, "REFSVC_CLIENT_ID")
		}
		if p.ClientSecret == "" {
			missing = append(missing, "REFSVC_CLIENT_SECRET")
		}
		if p.RedirectURI == "" {
			missing = append(missing, "REFSVC_REDIRECT_URI")
		}
		if p.DefaultConformance == "B-T" && p.TsaURL == "" {
			missing = append(missing, "REFSVC_TSA_URL (B-T)")
		}
		if len(missing) > 0 {
			return nil, fmt.Errorf("live mode requires: %s", strings.Join(missing, ", "))
		}
	default:
		return nil, fmt.Errorf("invalid REFSVC_MODE %q (fixtures|live)", p.Mode)
	}

	return p, nil
}
