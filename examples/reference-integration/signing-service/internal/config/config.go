// Package config loads the reference signing service's run profile from the environment
// (12-factor) and fails fast on an invalid/half-configured profile.
package config

import (
	"errors"
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

// Supported PAdES conformance levels (a request may override the profile default).
const (
	ConformanceBB = "B-B"
	ConformanceBT = "B-T"
)

// Harmless placeholders so a fixtures run needs no Cleverbase credentials: the SDK requires a
// non-empty client_id/secret/redirect_uri even though the mock upstream ignores them.
const (
	fixturesClientID    = "refsvc-fixtures"
	fixturesSecret      = "fixtures"
	fixturesRedirectURI = "http://localhost:8080/return"
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
		DefaultConformance:    env("REFSVC_DEFAULT_CONFORMANCE", ConformanceBB),
		Listen:                env("REFSVC_LISTEN", ":8080"),
	}

	ttlStr := env("REFSVC_SESSION_TTL", "15m")
	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid REFSVC_SESSION_TTL %q: %w", ttlStr, err)
	}
	p.SessionTTL = ttl

	if err := p.resolveAuth(); err != nil {
		return nil, err
	}
	if p.DefaultConformance != ConformanceBB && p.DefaultConformance != ConformanceBT {
		return nil, fmt.Errorf("invalid REFSVC_DEFAULT_CONFORMANCE %q (%s|%s)", p.DefaultConformance, ConformanceBB, ConformanceBT)
	}

	switch p.Mode {
	case ModeFixtures:
		if err := p.applyFixturesDefaults(); err != nil {
			return nil, err
		}
	case ModeLive:
		if err := p.validateLive(); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid REFSVC_MODE %q (%s|%s)", p.Mode, ModeFixtures, ModeLive)
	}

	return p, nil
}

// resolveAuth applies the auth policy: a key turns auth on; auth is on by default and may only be
// turned off by an explicit opt-out, and that opt-out is honored in fixtures mode ONLY. API-key auth
// is mandatory in live mode: a live deployment with REFSVC_AUTH_DISABLED=true is a fatal config error
// (it would expose the signing REST API with no authentication).
func (p *Profile) resolveAuth() error {
	authDisabled := strings.EqualFold(os.Getenv("REFSVC_AUTH_DISABLED"), "true")
	if authDisabled && p.Mode == ModeLive {
		return errors.New("REFSVC_AUTH_DISABLED is not allowed in live mode: API-key auth (REFSVC_API_KEY) is mandatory")
	}
	switch {
	case p.APIKey != "":
		p.AuthEnabled = true
	case authDisabled:
		p.AuthEnabled = false
	default:
		return errors.New("API auth is on by default: set REFSVC_API_KEY, or REFSVC_AUTH_DISABLED=true for local fixtures runs")
	}
	return nil
}

// applyFixturesDefaults fills the credential-free defaults for fixtures mode and points the TSA +
// redirect rewrites at the mock upstream.
func (p *Profile) applyFixturesDefaults() error {
	if p.UpstreamBaseURL == "" {
		return errors.New("fixtures mode requires REFSVC_BASE_URL (the mock upstream URL)")
	}
	if p.ClientID == "" {
		p.ClientID = fixturesClientID
	}
	if p.ClientSecret == "" {
		p.ClientSecret = fixturesSecret
	}
	if p.RedirectURI == "" {
		p.RedirectURI = fixturesRedirectURI
	}
	// B-T fixtures: the mock serves an RFC 3161 TSA at /tsr.
	if p.TsaURL == "" {
		p.TsaURL = strings.TrimRight(p.UpstreamBaseURL, "/") + "/tsr"
	}
	// Browser-facing redirect rewrites default to the internal base unless a public one is set.
	if p.PublicUpstreamBaseURL == "" {
		p.PublicUpstreamBaseURL = p.UpstreamBaseURL
	}
	return nil
}

// validateLive fails fast on a half-configured live profile (missing credentials / B-T TSA).
func (p *Profile) validateLive() error {
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
	// Conformance is per-request overridable, so a live profile that defaults to B-B can still
	// receive a B-T request and would otherwise fail late (mid-flow) for want of a TSA. Require the
	// TSA up front regardless of the default: a live deployment must always be able to serve B-T.
	if p.TsaURL == "" {
		missing = append(missing, "REFSVC_TSA_URL")
	}
	if len(missing) > 0 {
		return fmt.Errorf("live mode requires: %s", strings.Join(missing, ", "))
	}
	return nil
}
