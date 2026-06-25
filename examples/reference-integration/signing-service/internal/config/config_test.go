package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// knownEnvKeys is every REFSVC_* variable config.Load reads. setEnv clears them all before applying a
// scenario so a test that runs multiple scenarios cannot inherit stale values from a previous one.
var knownEnvKeys = []string{
	"REFSVC_API_KEY", "REFSVC_AUTH_DISABLED", "REFSVC_BASE_URL", "REFSVC_CLIENT_ID",
	"REFSVC_CLIENT_SECRET", "REFSVC_CSC_API", "REFSVC_DEFAULT_CONFORMANCE", "REFSVC_ENV",
	"REFSVC_LISTEN", "REFSVC_LIVE_AUTHORIZER", "REFSVC_LIVE_CA_BUNDLE", "REFSVC_MODE",
	"REFSVC_PUBLIC_BASE_URL", "REFSVC_REDIRECT_URI", "REFSVC_SESSION_TTL", "REFSVC_TSA_AUTH",
	"REFSVC_TSA_POLICY", "REFSVC_TSA_URL",
}

// setEnv sets env vars for a test (restored afterward by t.Setenv), clearing every known REFSVC_* key
// first so each scenario starts from a clean, hermetic environment. config.Load treats "" as unset.
func setEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for _, k := range knownEnvKeys {
		t.Setenv(k, "")
	}
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

func fixturesEnv() map[string]string {
	return map[string]string{
		"REFSVC_MODE":     "fixtures",
		"REFSVC_BASE_URL": "http://mock:9000",
		"REFSVC_API_KEY":  "test-key",
	}
}

func TestLoadFixturesDefaults(t *testing.T) {
	setEnv(t, fixturesEnv())
	p, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if p.Mode != ModeFixtures || p.UpstreamBaseURL != "http://mock:9000" {
		t.Fatalf("unexpected profile: %+v", p)
	}
	if p.Environment != "acceptance" || p.CscAPI != "v1_rsa" || p.DefaultConformance != "B-B" {
		t.Fatalf("unexpected defaults: %+v", p)
	}
	if p.SessionTTL != 15*time.Minute {
		t.Fatalf("default TTL = %v, want 15m", p.SessionTTL)
	}
	if !p.AuthEnabled {
		t.Fatal("auth should be enabled when API key is set")
	}
}

func TestFixturesRequiresBaseURL(t *testing.T) {
	setEnv(t, map[string]string{"REFSVC_MODE": "fixtures", "REFSVC_API_KEY": "k"})
	if _, err := Load(); err == nil {
		t.Fatal("expected error: fixtures mode needs REFSVC_BASE_URL")
	}
}

func TestAuthOnByDefault(t *testing.T) {
	setEnv(t, map[string]string{"REFSVC_MODE": "fixtures", "REFSVC_BASE_URL": "http://m"})
	if _, err := Load(); err == nil {
		t.Fatal("expected error: API key required unless auth explicitly disabled")
	}
	// Explicitly disabling auth is allowed for local runs.
	setEnv(t, map[string]string{"REFSVC_MODE": "fixtures", "REFSVC_BASE_URL": "http://m", "REFSVC_AUTH_DISABLED": "true"})
	p, err := Load()
	if err != nil {
		t.Fatalf("load with auth disabled: %v", err)
	}
	if p.AuthEnabled {
		t.Fatal("auth should be disabled")
	}
}

func TestLiveModeRejectsAuthDisabled(t *testing.T) {
	// API-key auth is mandatory in live: the fixtures-only opt-out must be a fatal error here, even
	// with an otherwise fully-configured live profile (so a LIVE deployment can never run unauthed).
	setEnv(t, map[string]string{
		"REFSVC_MODE": "live", "REFSVC_AUTH_DISABLED": "true",
		"REFSVC_CLIENT_ID": "c", "REFSVC_CLIENT_SECRET": "s", "REFSVC_REDIRECT_URI": "https://a/cb",
		"REFSVC_TSA_URL": "https://tsa.example/tsr",
	})
	if _, err := Load(); err == nil {
		t.Fatal("expected live-mode REFSVC_AUTH_DISABLED to be a fatal config error")
	}
	// A contradictory live config (an API key AND the opt-out) must also fail fast, not silently
	// ignore the opt-out.
	setEnv(t, map[string]string{
		"REFSVC_MODE": "live", "REFSVC_AUTH_DISABLED": "true", "REFSVC_API_KEY": "k",
		"REFSVC_CLIENT_ID": "c", "REFSVC_CLIENT_SECRET": "s", "REFSVC_REDIRECT_URI": "https://a/cb",
		"REFSVC_TSA_URL": "https://tsa.example/tsr",
	})
	if _, err := Load(); err == nil {
		t.Fatal("expected live-mode REFSVC_AUTH_DISABLED=true to fail even with an API key set")
	}
}

func TestInvalidTTLAndConformance(t *testing.T) {
	e := fixturesEnv()
	e["REFSVC_SESSION_TTL"] = "not-a-duration"
	setEnv(t, e)
	if _, err := Load(); err == nil {
		t.Fatal("expected TTL parse error")
	}
	e = fixturesEnv()
	e["REFSVC_DEFAULT_CONFORMANCE"] = "B-X"
	setEnv(t, e)
	if _, err := Load(); err == nil {
		t.Fatal("expected conformance validation error")
	}
}

func TestInvalidMode(t *testing.T) {
	setEnv(t, map[string]string{"REFSVC_MODE": "nope", "REFSVC_API_KEY": "k"})
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid-mode error")
	}
}

func TestMalformedURLsFailFast(t *testing.T) {
	// A URL-shaped var with no scheme/host must fail Load() rather than pass and break at runtime
	// (e.g. upstream.Rewrite silently falling back). Exercise each URL-shaped var with a value that is
	// syntactically a URL but not an absolute one.
	cases := []struct {
		name string
		env  map[string]string
	}{
		{"REFSVC_BASE_URL", map[string]string{"REFSVC_MODE": "fixtures", "REFSVC_API_KEY": "k", "REFSVC_BASE_URL": "mock:9000"}},
		{"REFSVC_PUBLIC_BASE_URL", map[string]string{"REFSVC_MODE": "fixtures", "REFSVC_API_KEY": "k", "REFSVC_BASE_URL": "http://mock:9000", "REFSVC_PUBLIC_BASE_URL": "no-scheme-host"}},
		{"REFSVC_REDIRECT_URI", map[string]string{
			"REFSVC_MODE": "live", "REFSVC_API_KEY": "k",
			"REFSVC_CLIENT_ID": "c", "REFSVC_CLIENT_SECRET": "s", "REFSVC_REDIRECT_URI": "//missing-scheme/cb",
			"REFSVC_TSA_URL": "https://tsa.example/tsr",
		}},
		{"REFSVC_TSA_URL", map[string]string{
			"REFSVC_MODE": "live", "REFSVC_API_KEY": "k",
			"REFSVC_CLIENT_ID": "c", "REFSVC_CLIENT_SECRET": "s", "REFSVC_REDIRECT_URI": "https://a/cb",
			"REFSVC_TSA_URL": "tsa.example/tsr",
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			setEnv(t, c.env)
			if _, err := Load(); err == nil {
				t.Fatalf("expected malformed %s to fail Load()", c.name)
			}
		})
	}
	// A well-formed absolute URL for every var still loads (guards against over-rejecting).
	setEnv(t, map[string]string{
		"REFSVC_MODE": "fixtures", "REFSVC_API_KEY": "k",
		"REFSVC_BASE_URL": "http://mock:9000", "REFSVC_PUBLIC_BASE_URL": "https://public.example",
		"REFSVC_REDIRECT_URI": "https://a/cb", "REFSVC_TSA_URL": "https://tsa.example/tsr",
	})
	if _, err := Load(); err != nil {
		t.Fatalf("well-formed URLs should load: %v", err)
	}
}

// validLiveEnv is a fully-configured live profile (loads OK). Cases mutate a copy.
func validLiveEnv() map[string]string {
	return map[string]string{
		"REFSVC_MODE": "live", "REFSVC_API_KEY": "k", "REFSVC_DEFAULT_CONFORMANCE": "B-B",
		"REFSVC_CLIENT_ID": "c", "REFSVC_CLIENT_SECRET": "s", "REFSVC_REDIRECT_URI": "https://a/cb",
		"REFSVC_TSA_URL": "https://tsa.example/tsr",
	}
}

func TestLiveAuthorizerDefaultAndValidation(t *testing.T) {
	// Default: an unset REFSVC_LIVE_AUTHORIZER resolves to "interactive".
	setEnv(t, validLiveEnv())
	p, err := Load()
	if err != nil {
		t.Fatalf("valid live profile should load: %v", err)
	}
	if p.LiveAuthorizer != AuthorizerInteractive {
		t.Fatalf("default LiveAuthorizer = %q, want %q", p.LiveAuthorizer, AuthorizerInteractive)
	}
	if p.LiveCABundle != "" {
		t.Fatalf("LiveCABundle should default empty, got %q", p.LiveCABundle)
	}
	// "headless" is an accepted value.
	e := validLiveEnv()
	e["REFSVC_LIVE_AUTHORIZER"] = "headless"
	setEnv(t, e)
	p, err = Load()
	if err != nil {
		t.Fatalf("headless authorizer should load: %v", err)
	}
	if p.LiveAuthorizer != AuthorizerHeadless {
		t.Fatalf("LiveAuthorizer = %q, want %q", p.LiveAuthorizer, AuthorizerHeadless)
	}
	// An unknown authorizer mode must fail fast.
	e = validLiveEnv()
	e["REFSVC_LIVE_AUTHORIZER"] = "robot"
	setEnv(t, e)
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid REFSVC_LIVE_AUTHORIZER to fail Load()")
	}
}

func TestLiveCABundleValidation(t *testing.T) {
	// A REFSVC_LIVE_CA_BUNDLE pointing at a missing file must fail fast.
	e := validLiveEnv()
	e["REFSVC_LIVE_CA_BUNDLE"] = filepath.Join(t.TempDir(), "does-not-exist.pem")
	setEnv(t, e)
	if _, err := Load(); err == nil {
		t.Fatal("expected a missing REFSVC_LIVE_CA_BUNDLE file to fail Load()")
	}
	// An existing file loads and is recorded on the profile.
	bundle := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(bundle, []byte("-----BEGIN CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e = validLiveEnv()
	e["REFSVC_LIVE_CA_BUNDLE"] = bundle
	setEnv(t, e)
	p, err := Load()
	if err != nil {
		t.Fatalf("existing CA bundle should load: %v", err)
	}
	if p.LiveCABundle != bundle {
		t.Fatalf("LiveCABundle = %q, want %q", p.LiveCABundle, bundle)
	}
	// The live-only knobs are not validated in fixtures mode (an unknown value is irrelevant there).
	fe := fixturesEnv()
	fe["REFSVC_LIVE_AUTHORIZER"] = "robot"
	fe["REFSVC_LIVE_CA_BUNDLE"] = filepath.Join(t.TempDir(), "nope.pem")
	setEnv(t, fe)
	if _, err := Load(); err != nil {
		t.Fatalf("fixtures mode must ignore live-only knobs, got: %v", err)
	}
}

func TestLiveModeFailFast(t *testing.T) {
	// Missing all live credentials.
	setEnv(t, map[string]string{"REFSVC_MODE": "live", "REFSVC_API_KEY": "k"})
	if _, err := Load(); err == nil {
		t.Fatal("expected live-mode fail-fast for missing credentials")
	}
	// B-T live without a TSA must fail fast.
	setEnv(t, map[string]string{
		"REFSVC_MODE": "live", "REFSVC_API_KEY": "k",
		"REFSVC_CLIENT_ID": "c", "REFSVC_CLIENT_SECRET": "s", "REFSVC_REDIRECT_URI": "https://a/cb",
		"REFSVC_DEFAULT_CONFORMANCE": "B-T",
	})
	if _, err := Load(); err == nil {
		t.Fatal("expected B-T-without-TSA fail-fast")
	}
	// A live profile defaulting to B-B but lacking a TSA must also fail fast: conformance is
	// per-request overridable, so such a deployment could still receive B-T and fail mid-flow.
	setEnv(t, map[string]string{
		"REFSVC_MODE": "live", "REFSVC_API_KEY": "k", "REFSVC_DEFAULT_CONFORMANCE": "B-B",
		"REFSVC_CLIENT_ID": "c", "REFSVC_CLIENT_SECRET": "s", "REFSVC_REDIRECT_URI": "https://a/cb",
	})
	if _, err := Load(); err == nil {
		t.Fatal("expected B-B-without-TSA fail-fast (live must always be able to serve B-T)")
	}
	// Fully configured live profile loads (explicit B-B so a prior subtest's B-T does not bleed).
	setEnv(t, map[string]string{
		"REFSVC_MODE": "live", "REFSVC_API_KEY": "k", "REFSVC_DEFAULT_CONFORMANCE": "B-B",
		"REFSVC_CLIENT_ID": "c", "REFSVC_CLIENT_SECRET": "s", "REFSVC_REDIRECT_URI": "https://a/cb",
		"REFSVC_TSA_URL": "https://tsa.example/tsr",
	})
	if _, err := Load(); err != nil {
		t.Fatalf("valid live profile should load: %v", err)
	}
}
