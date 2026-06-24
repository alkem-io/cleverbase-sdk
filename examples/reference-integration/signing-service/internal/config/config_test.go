package config

import (
	"testing"
	"time"
)

// setEnv sets env vars for a test and clears them afterward.
func setEnv(t *testing.T, kv map[string]string) {
	t.Helper()
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
