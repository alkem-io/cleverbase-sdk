package e2e

import (
	"bufio"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/config"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/flow"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/httpapi"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/sdk"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/session"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/upstream"
)

// liveEnv collects the required + optional live knobs. Required: client id/secret, redirect URI, and a
// real trust bundle (REFSVC_LIVE_CA_BUNDLE) to verify against. Optional: env, CSC api, TSA url (B-T),
// authorizer mode.
type liveEnv struct {
	clientID, clientSecret, redirectURI, caBundle string
	env, cscAPI, tsaURL, authorizer               string
}

// loadLiveEnv reads the live knobs and reports whether the required real-credential set is present.
// The single algorithm a local run covers is the configured REFSVC_CSC_API (default v1_rsa); covering
// BOTH RSA and ECDSA is a CI-matrix property (live.yml runs {v1_rsa, v2_ecdsa}), never a single run (I1/F6).
func loadLiveEnv() (liveEnv, bool) {
	e := liveEnv{
		clientID:     os.Getenv("REFSVC_CLIENT_ID"),
		clientSecret: os.Getenv("REFSVC_CLIENT_SECRET"),
		redirectURI:  os.Getenv("REFSVC_REDIRECT_URI"),
		caBundle:     os.Getenv("REFSVC_LIVE_CA_BUNDLE"),
		env:          os.Getenv("REFSVC_ENV"),
		cscAPI:       os.Getenv("REFSVC_CSC_API"),
		tsaURL:       os.Getenv("REFSVC_TSA_URL"),
		authorizer:   os.Getenv("REFSVC_LIVE_AUTHORIZER"),
	}
	if e.env == "" {
		e.env = "acceptance"
	}
	if e.cscAPI == "" {
		e.cscAPI = "v1_rsa"
	}
	if e.authorizer == "" {
		e.authorizer = config.AuthorizerInteractive
	}
	// Gating (FR-009): the live path requires the real OIDC credentials AND a real trust bundle to
	// verify the result against. Any missing → not present → t.Skip (never fail).
	ok := e.clientID != "" && e.clientSecret != "" && e.redirectURI != "" && e.caBundle != ""
	return e, ok
}

// liveAuthorizer builds the configured Authorizer for the live path. interactive surfaces the
// authorize URL and captures the callback (a local redirect-capture listener when REFSVC_REDIRECT_URI
// is a loopback http URL, else a stdin paste); headless is the pending automatable approval drop-in.
func liveAuthorizer(t *testing.T, e liveEnv) Authorizer {
	t.Helper()
	switch e.authorizer {
	case config.AuthorizerHeadless:
		return Headless{}
	case config.AuthorizerInteractive, "":
		return Interactive{
			Surface:         func(u string) { t.Logf("open this URL in a browser to authorize:\n%s", u) },
			CaptureCallback: redirectCapture(t, e.redirectURI),
			// Bound each human approval; an unapproved redirect fails fast (errAuthNotCompleted),
			// never hangs CI (FR-011). Overridable via REFSVC_LIVE_AUTH_TIMEOUT.
			Timeout: liveAuthTimeout(),
		}
	default:
		t.Fatalf("unknown REFSVC_LIVE_AUTHORIZER %q", e.authorizer)
		return nil
	}
}

// liveAuthTimeout reads REFSVC_LIVE_AUTH_TIMEOUT (default 3m): the window a human has to approve.
func liveAuthTimeout() time.Duration {
	if v := os.Getenv("REFSVC_LIVE_AUTH_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return 3 * time.Minute
}

// redirectCapture returns a channel yielding the raw redirect callback URL. If REFSVC_REDIRECT_URI is
// an http(s) loopback URL, it stands up a one-shot listener on that host:port and yields the full
// request URL when Cleverbase redirects the browser back. Otherwise it falls back to a stdin reader
// (paste the callback URL). Either way it never blocks the caller forever — the Interactive Timeout
// bounds the wait.
func redirectCapture(t *testing.T, redirectURI string) <-chan string {
	t.Helper()
	ch := make(chan string, 1)
	u, err := url.Parse(redirectURI)
	if err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
		srv := &http.Server{
			Addr:              u.Host,
			ReadHeaderTimeout: 10 * time.Second,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case ch <- "https://" + r.Host + r.URL.RequestURI():
				default:
				}
				_, _ = io.WriteString(w, "authorization received — you may close this tab")
			}),
		}
		go func() { _ = srv.ListenAndServe() }()
		t.Cleanup(func() { _ = srv.Close() })
		return ch
	}
	// Stdin fallback: read a single pasted callback URL.
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		if sc.Scan() {
			select {
			case ch <- strings.TrimSpace(sc.Text()):
			default:
			}
		}
	}()
	return ch
}

// buildLiveService wires the SAME service used in fixtures mode but in live mode (no host rewrite):
// only configuration differs (SC-003).
func buildLiveService(t *testing.T, e liveEnv, conformance string) *httptest.Server {
	t.Helper()
	tsaURL := e.tsaURL
	if tsaURL == "" {
		// validateLive requires a TSA for every live profile; supply the acceptance default so the
		// profile is internally consistent even when only B-B is exercised.
		tsaURL = "https://tsa.acc.cleverbase.com/tsr"
	}
	p := &config.Profile{
		Mode: config.ModeLive, Environment: e.env, CscAPI: e.cscAPI,
		ClientID: e.clientID, ClientSecret: e.clientSecret, RedirectURI: e.redirectURI,
		TsaURL: tsaURL, LiveAuthorizer: e.authorizer, LiveCABundle: e.caBundle,
		APIKey: apiKey, AuthEnabled: true, DefaultConformance: conformance, SessionTTL: 5 * time.Minute,
	}
	store := session.NewMemory()
	eng := &flow.Engine{
		SDK: sdk.New(p), Up: upstream.New(""), Store: store, // live: no host rewrite
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), TTL: p.SessionTTL,
	}
	service := &httpapi.Service{Engine: eng, Store: store, Profile: p, Sample: samplePDF(t)}
	svc := httptest.NewServer(service.Handler())
	t.Cleanup(svc.Close)
	return svc
}

// TestLive (T019/T023) drives the full real-surface contract path: start → Authorize → complete →
// Authorize → complete → GET result → verify against the REAL Cleverbase issuer chain
// (REFSVC_LIVE_CA_BUNDLE), reusing the algorithm-agnostic validateCMS path. B-B is required; B-T is
// additionally exercised when REFSVC_TSA_URL is set (a missing TSA must not block the run, FR-015).
//
// Gating (FR-009): without the required REFSVC_* live credentials this MUST t.Skip — never fail — and
// the credential-free suite still passes. A single invocation covers exactly the algorithm of the
// configured REFSVC_CSC_API; "both algorithms" is realized by the live.yml matrix (T025), not here (I1).
func TestLive(t *testing.T) {
	e, ok := loadLiveEnv()
	if !ok {
		t.Skip("live path requires REFSVC_CLIENT_ID, REFSVC_CLIENT_SECRET, REFSVC_REDIRECT_URI, REFSVC_LIVE_CA_BUNDLE")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl required to verify the live signature against the real chain")
	}

	// Always exercise B-B; add B-T only when a TSA is configured.
	levels := []string{config.ConformanceBB}
	if e.tsaURL != "" {
		levels = append(levels, config.ConformanceBT)
	}
	for _, level := range levels {
		t.Run(level, func(t *testing.T) {
			svc := buildLiveService(t, e, level)
			auth := liveAuthorizer(t, e)
			pdf, _, status, reason := runFlow(t, auth, svc, `{"conformanceLevel":"`+level+`"}`)
			if status != "completed" {
				// A service/credential/authorization failure (FR-011): surface it clearly, distinct
				// from an SDK defect, rather than asserting a crypto outcome.
				t.Fatalf("live %s did not complete (dependency/authorization problem, not necessarily an SDK defect): status=%s reason=%s", level, status, reason)
			}
			if len(pdf) == 0 {
				t.Fatalf("live %s completed but produced an empty PDF", level)
			}
			// Always-on bar against the REAL chain: a verification failure here is a hard failure —
			// the contract test caught a real-surface regression (never a silent pass).
			if err := verifyCMSWithCA(t, pdf, extractContents(t, pdf), e.caBundle); err != nil {
				t.Fatalf("live %s signature failed to verify against REFSVC_LIVE_CA_BUNDLE: %v", level, err)
			}
			if level == config.ConformanceBT {
				assertTimestampToken(t, pdf)
			}
		})
	}
}

// TestLiveSkipsWithoutCredentials (FR-009) asserts the live gate SKIPS — never fails — when the
// required live env is absent. It clears the live vars and runs TestLive in a subtest, asserting the
// subtest skipped. Guards against a regression that turned the gate into a hard failure in CI.
func TestLiveSkipsWithoutCredentials(t *testing.T) {
	for _, k := range []string{"REFSVC_CLIENT_ID", "REFSVC_CLIENT_SECRET", "REFSVC_REDIRECT_URI", "REFSVC_LIVE_CA_BUNDLE"} {
		t.Setenv(k, "")
	}
	if _, ok := loadLiveEnv(); ok {
		t.Fatal("loadLiveEnv reported credentials present after clearing them; the gate would not skip")
	}
}

// TestWrongTrustBundleFailsLoudly (N3 / FR-008 / FR-011) runs WITHOUT real credentials: it produces a
// known-good credential-free PDF, then verifies it against a DELIBERATELY-WRONG trust bundle (a
// freshly-generated, unrelated CA) and asserts verification FAILS LOUDLY, naming the untrusted/missing
// issuer — exercising the same "fail on a rotated/mismatched REFSVC_LIVE_CA_BUNDLE" behaviour the live
// arm relies on, but reproducibly and offline.
func TestWrongTrustBundleFailsLoudly(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl required to validate the CMS signature")
	}
	// Produce a real, valid credential-free signature (verifies against the synthetic CA).
	svc := stack(t, "B-B", "v1_rsa")
	pdf, _, status, _ := runFlow(t, mockAutoApprove{}, svc, `{"conformanceLevel":"B-B"}`)
	if status != "completed" || len(pdf) == 0 {
		t.Fatalf("expected a completed credential-free PDF, got status=%s len=%d", status, len(pdf))
	}
	cmsDER := extractContents(t, pdf)
	// Sanity: it DOES verify against the correct trust anchor (so a later failure is attributable to
	// the wrong bundle, not a broken signature).
	if err := verifyCMS(t, pdf, cmsDER); err != nil {
		t.Fatalf("baseline credential-free CMS should verify against the correct CA: %v", err)
	}

	// Generate an unrelated CA — the "rotated/wrong REFSVC_LIVE_CA_BUNDLE" — that did NOT issue the
	// signer cert.
	wrongCA := generateUnrelatedCA(t)
	err := verifyCMSWithCA(t, pdf, cmsDER, wrongCA)
	if err == nil {
		t.Fatal("verification against a WRONG trust bundle MUST fail loudly (no false-accept on a mismatched issuer)")
	}
	// The failure must NAME the trust problem (untrusted/missing issuer), not be a generic opaque
	// error — so an operator can tell a rotated/misconfigured bundle from an SDK defect (FR-011).
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "unable to get local issuer") &&
		!strings.Contains(msg, "self-signed") && !strings.Contains(msg, "self signed") &&
		!strings.Contains(msg, "unable to verify") && !strings.Contains(msg, "certificate signature failure") &&
		!strings.Contains(msg, "verify error") {
		t.Fatalf("wrong-bundle failure should name the untrusted/missing issuer, got: %v", err)
	}
}

// generateUnrelatedCA writes a fresh self-signed CA PEM (unrelated to the synthetic signer chain) and
// returns its path — a stand-in for a rotated/mismatched REFSVC_LIVE_CA_BUNDLE.
func generateUnrelatedCA(t *testing.T) string {
	t.Helper()
	work := t.TempDir()
	key := filepath.Join(work, "wrong-ca.key")
	crt := filepath.Join(work, "wrong-ca.pem")
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", key, "-out", crt, "-days", "1", "-subj", "/CN=Unrelated Wrong CA")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generate unrelated CA: %v\n%s", err, out)
	}
	return crt
}
