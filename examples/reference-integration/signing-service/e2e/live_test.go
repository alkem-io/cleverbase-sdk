package e2e

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
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
// authorize URL and captures the callback via a local redirect-capture listener on the loopback
// REFSVC_REDIRECT_URI; headless is the pending automatable approval drop-in.
func liveAuthorizer(t *testing.T, e liveEnv) Authorizer {
	t.Helper()
	switch e.authorizer {
	case config.AuthorizerHeadless:
		return Headless{}
	case config.AuthorizerInteractive, "":
		// Per-leg capture: runFlow calls Authorize twice (service-scope, then SCAL2). Each call must
		// stand up its OWN one-shot capture so a leg-1 callback (state=S1) can never be read by leg-2
		// and trip the CSRF guard. liveInteractive builds a fresh Interactive (fresh listener) per
		// Authorize call.
		return &liveInteractive{
			t:           t,
			redirectURI: e.redirectURI,
			surface:     func(u string) { t.Logf("open this URL in a browser to authorize:\n%s", u) },
			// Bound each human approval; an unapproved redirect fails fast (errAuthNotCompleted),
			// never hangs CI (FR-011). Overridable via REFSVC_LIVE_AUTH_TIMEOUT.
			timeout: liveAuthTimeout(),
		}
	default:
		t.Fatalf("unknown REFSVC_LIVE_AUTHORIZER %q", e.authorizer)
		return nil
	}
}

// liveInteractive is the live-harness Authorizer that wraps Interactive with a fresh per-call capture.
// runFlow drives two redirects (service-scope, then SCAL2) by calling Authorize twice; a single shared
// buffered capture channel would let a stale leg-1 callback be read by leg-2, tripping the CSRF
// state-mismatch guard. liveInteractive instead stands up a brand-new one-shot capture on each call so
// every leg sees only its own callback, and it surfaces a listener/bind failure promptly (rather than
// blaming the signer for a timeout).
type liveInteractive struct {
	t           *testing.T
	redirectURI string
	surface     func(authorizeURL string)
	timeout     time.Duration
}

// Authorize stands up a fresh one-shot redirect capture for THIS leg, then delegates to Interactive.
// A listener/bind failure is surfaced immediately as a distinct error (never waited out as a signer
// timeout). The capture is bound to the call's context so its listener is closed (no leak) on timeout.
func (l *liveInteractive) Authorize(ctx context.Context, authorizeURL, expectState string) (code, state string, err error) {
	// Bind/start the capture before surfacing the URL so a bind failure fails fast (FR-011) rather than
	// after the human has already been pointed at the authorize URL.
	capCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch, bindErr := startRedirectCapture(capCtx, l.t, l.redirectURI)
	if bindErr != nil {
		return "", "", bindErr
	}
	i := Interactive{Surface: l.surface, CaptureCallback: ch, Timeout: l.timeout}
	return i.Authorize(ctx, authorizeURL, expectState)
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

// startRedirectCapture stands up a fresh ONE-SHOT capture for a single Authorize leg. It binds a
// loopback HTTP listener on REFSVC_REDIRECT_URI's host:port and returns a channel that yields the full
// callback request URL — reconstructed with the request's ACTUAL scheme (http for a loopback listener,
// so it matches reality) — when Cleverbase redirects the browser back.
//
// The loopback listener is the only supported capture path: a non-loopback / non-http(s) redirect URI,
// or a bind failure, is returned synchronously as a distinct error so the caller fails FAST (a silent
// no-callback would otherwise be misread as "the signer did not approve in time", FR-011). The listener
// is closed when ctx is done (the leg's timeout) or at test cleanup, so nothing leaks — there is no
// uninterruptible stdin reader to strand.
func startRedirectCapture(ctx context.Context, t *testing.T, redirectURI string) (<-chan string, error) {
	t.Helper()
	u, err := url.Parse(redirectURI)
	if err != nil {
		return nil, fmt.Errorf("REFSVC_REDIRECT_URI is not a valid URL: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("redirect-capture requires an http(s) loopback REFSVC_REDIRECT_URI with a host (got scheme %q, host %q)", u.Scheme, u.Host)
	}
	// Bind eagerly so a bind error surfaces NOW (a distinct listener error), not as a silent timeout the
	// signer gets blamed for.
	ln, lerr := net.Listen("tcp", u.Host)
	if lerr != nil {
		return nil, fmt.Errorf("redirect-capture listener bind failed on %s: %w", u.Host, lerr)
	}
	ch := make(chan string, 1)
	srv := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			select {
			case ch <- scheme + "://" + r.Host + r.URL.RequestURI():
			default:
			}
			_, _ = io.WriteString(w, "authorization received — you may close this tab")
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	t.Cleanup(func() { _ = srv.Close() })
	return ch, nil
}

// buildLiveService wires the SAME service used in fixtures mode but in live mode (no host rewrite):
// only configuration differs (SC-003).
func buildLiveService(t *testing.T, e liveEnv, conformance string) *httptest.Server {
	t.Helper()
	// Use the configured TSA only (REFSVC_TSA_URL → B-T covered); otherwise leave it empty and do B-B
	// only. NEVER hardcode a real Cleverbase TSA host: that would be an undeclared external dependency
	// and conflict with FR-015 (a missing TSA must not block B-B). This Profile is constructed directly
	// (not via config.Load), so config.validateLive — which governs the deployed service — does not run
	// here; an empty TSA is therefore valid for a B-B-only live run.
	p := &config.Profile{
		Mode: config.ModeLive, Environment: e.env, CscAPI: e.cscAPI,
		ClientID: e.clientID, ClientSecret: e.clientSecret, RedirectURI: e.redirectURI,
		TsaURL: e.tsaURL, LiveAuthorizer: e.authorizer, LiveCABundle: e.caBundle,
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

	// Headless approval is a PENDING external dependency (U1): the Headless authorizer ships as the
	// interface drop-in but fails fast with errHeadlessNotConfigured until an automatable Cleverbase
	// test-credential approval is wired. live.yml runs CI unattended with REFSVC_LIVE_AUTHORIZER=headless,
	// so probe the configured authorizer once up front; if it reports "not configured", SKIP cleanly
	// (never fail) — the leg goes green now and runs for real the moment the mechanism exists (FR-009).
	// The probe is safe because Headless.Authorize is a pure, side-effect-free stub. The interactive
	// authorizer is NOT probed (its Authorize has real side effects: it surfaces a URL and waits).
	auth := liveAuthorizer(t, e)
	if e.authorizer == config.AuthorizerHeadless {
		if _, _, err := auth.Authorize(context.Background(), "", ""); errors.Is(err, errHeadlessNotConfigured) {
			t.Skip("headless approval mechanism not yet available — pending external dependency")
		}
	}

	// Always exercise B-B; add B-T only when a TSA is configured.
	levels := []string{config.ConformanceBB}
	if e.tsaURL != "" {
		levels = append(levels, config.ConformanceBT)
	}
	for _, level := range levels {
		t.Run(level, func(t *testing.T) {
			svc := buildLiveService(t, e, level)
			// Per-leg authorizer: liveInteractive stands up a fresh capture on each Authorize call, so a
			// new instance per conformance level keeps each level's captures fully independent.
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
// required live env is absent. It clears the live vars and actually RUNS TestLive in a subtest,
// asserting the subtest reports skipped (not failed). Guards against a regression that turned the gate
// into a hard failure in CI.
func TestLiveSkipsWithoutCredentials(t *testing.T) {
	for _, k := range []string{"REFSVC_CLIENT_ID", "REFSVC_CLIENT_SECRET", "REFSVC_REDIRECT_URI", "REFSVC_LIVE_CA_BUNDLE"} {
		t.Setenv(k, "")
	}
	// Run TestLive for real against the cleared env. With no credentials it must hit the FR-009 gate and
	// t.Skip. t.Run returns false only when the subtest FAILED; a skip returns true. The regression this
	// guards against is the gate turning into a hard failure, so a false return is the failure signal.
	if ok := t.Run("TestLive", TestLive); !ok {
		t.Fatal("TestLive reported FAILED with no credentials; the FR-009 gate must SKIP, never fail")
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
