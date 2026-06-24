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
	"sync"
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
//
// The interactive authorizer binds ONE redirect-capture listener for the ENTIRE TestLive run (across
// both conformance levels AND both redirect legs) — see liveInteractive. So this is called ONCE at
// TestLive (parent t) scope and the returned Authorizer is reused for every Authorize; building a
// fresh one per level would re-Listen on the same fixed REFSVC_REDIRECT_URI port and race the previous
// level's asynchronous close (EADDRINUSE).
func liveAuthorizer(t *testing.T, e liveEnv) Authorizer {
	t.Helper()
	switch e.authorizer {
	case config.AuthorizerHeadless:
		return Headless{}
	case config.AuthorizerInteractive, "":
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

// liveInteractive is the live-harness Authorizer that wraps Interactive. The whole TestLive run drives
// MANY redirects: two legs (service-scope, then SCAL2) per conformance level, across B-B and B-T. ONE
// redirect-capture listener is bound for the ENTIRE run (lazily, on the first Authorize) and reused by
// every leg of every level. This is the single fix for BOTH defects:
//
//   - Per-level/per-leg EADDRINUSE rebind race — never re-Listen on the fixed REFSVC_REDIRECT_URI port,
//     so there is no async-close-vs-rebind race. The listener is closed once, at TestLive's t.Cleanup.
//   - Cross-leg CSRF poisoning — the capture records each callback keyed by its OWN state and each leg
//     waits for ONLY the state it expects (see redirectCapture.waitForState), so a duplicate/stale
//     leg-1 callback (state=S1) arriving while leg-2 waits is dropped (its state != leg-2's expectState).
//
// A listener/bind failure is surfaced promptly as a distinct error (rather than blaming the signer for
// a timeout). Because the same liveInteractive is reused across the whole run, binding is guarded so the
// listener is established exactly once even if Authorize is somehow entered concurrently.
type liveInteractive struct {
	t           *testing.T
	redirectURI string
	surface     func(authorizeURL string)
	timeout     time.Duration

	bindOnce sync.Once
	cap      *redirectCapture // bound once for the whole run and reused across every level + leg
	bindErr  error            // a bind failure captured by bindOnce, surfaced on every Authorize
}

// Authorize binds the single shared redirect-capture listener once (on the first call across the whole
// TestLive run), then delegates to Interactive with the capture's state-matched waiter for THIS leg's
// expectState. A bind failure is surfaced before the URL is surfaced so it fails fast (FR-011) rather
// than being waited out as a signer timeout.
func (l *liveInteractive) Authorize(ctx context.Context, authorizeURL, expectState string) (code, state string, err error) {
	l.bindOnce.Do(func() { l.cap, l.bindErr = startRedirectCapture(l.t, l.redirectURI) })
	if l.bindErr != nil {
		return "", "", l.bindErr
	}
	// State-matched waiter: Interactive blocks until the capture observes a callback whose state ==
	// expectState, ignoring every other (duplicate/stale leg) callback — so no cross-leg CSRF poisoning.
	i := Interactive{Surface: l.surface, WaitForCallback: l.cap.waitForState, Timeout: l.timeout}
	return i.Authorize(ctx, authorizeURL, expectState)
}

// redirectCapture owns the single, long-lived loopback HTTP listener for the whole TestLive run and
// records every browser callback keyed by its OWN state. Each leg's Authorize calls waitForState with
// the state it expects and is woken only by a callback carrying that exact state; callbacks for any
// other state sit harmlessly in the map and are never delivered to a non-matching waiter. This kills
// both the per-leg/per-level rebind race (the listener is bound once, never re-Listened) and cross-leg
// CSRF poisoning (a stale leg-1 callback can never satisfy leg-2's wait).
type redirectCapture struct {
	mu      sync.Mutex
	cond    *sync.Cond        // broadcast when a new state lands, so waiters re-check the map
	byState map[string]string // state -> full captured callback URL (the first wins per state)
}

// record stores a captured callback URL under its state (first writer per state wins, so a duplicate
// callback for an already-seen state cannot clobber it) and wakes any waiter that may now match.
func (c *redirectCapture) record(state, callbackURL string) {
	c.mu.Lock()
	if _, seen := c.byState[state]; !seen {
		c.byState[state] = callbackURL
	}
	c.cond.Broadcast()
	c.mu.Unlock()
}

// waitForState blocks until a callback whose state == expectState has been recorded (returning its raw
// URL), or ctx is done (returning errAuthNotCompleted, never a hang). Callbacks for any other state are
// ignored: they are recorded but a waiter for expectState only ever returns its OWN state's callback, so
// a duplicate/stale leg-1 callback (state=S1) cannot satisfy a leg-2 wait (expectState=S2). A context
// cancel/timeout broadcasts the cond so the blocked waiter wakes and observes ctx.Err().
func (c *redirectCapture) waitForState(ctx context.Context, expectState string) (string, error) {
	// Wake the cond when ctx fires so a parked Wait() returns promptly (sync.Cond is not ctx-aware).
	stop := context.AfterFunc(ctx, func() {
		c.mu.Lock()
		c.cond.Broadcast()
		c.mu.Unlock()
	})
	defer stop()

	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		if raw, ok := c.byState[expectState]; ok {
			return raw, nil
		}
		if err := ctx.Err(); err != nil {
			return "", fmt.Errorf("%w: %w (signer did not approve within the window)", errAuthNotCompleted, err)
		}
		c.cond.Wait()
	}
}

// isLoopbackHost reports whether host is a loopback target: localhost, or an IP in 127.0.0.0/8 or ::1.
// A non-loopback host (e.g. 0.0.0.0 / all interfaces, or a routable address) is rejected so the capture
// listener is never exposed off-box.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// startRedirectCapture binds the single long-lived loopback HTTP listener on REFSVC_REDIRECT_URI's
// host:port and returns a redirectCapture that records each callback keyed by its own state. The
// handler reconstructs the full callback URL with the request's ACTUAL scheme (http for a loopback
// listener, so it matches reality) and stores it under its state so a leg waiting on that state can
// claim it; a callback with no state is recorded under "" (an empty expectState would match it).
//
// The loopback listener is the only supported capture path: a non-loopback host, a non-http(s) scheme,
// or a bind failure is returned synchronously as a distinct error so the caller fails FAST (a silent
// no-callback would otherwise be misread as "the signer did not approve in time", FR-011). The listener
// is closed at test cleanup, so nothing leaks.
func startRedirectCapture(t *testing.T, redirectURI string) (*redirectCapture, error) {
	t.Helper()
	u, err := url.Parse(redirectURI)
	if err != nil {
		return nil, errors.New("REFSVC_REDIRECT_URI is not a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("redirect-capture requires an http(s) loopback REFSVC_REDIRECT_URI (got scheme %q)", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("redirect-capture requires an http(s) loopback REFSVC_REDIRECT_URI with a host")
	}
	// Enforce loopback: scheme + non-empty host is NOT enough — 0.0.0.0 (all interfaces) or a routable
	// host would expose the capture listener off-box. Only a loopback host may be bound.
	if !isLoopbackHost(u.Hostname()) {
		return nil, fmt.Errorf("redirect-capture requires a LOOPBACK host (127.0.0.0/8, ::1, or localhost), got %q", u.Hostname())
	}
	// Bind eagerly so a bind error surfaces NOW (a distinct listener error), not as a silent timeout the
	// signer gets blamed for.
	ln, lerr := net.Listen("tcp", u.Host)
	if lerr != nil {
		return nil, fmt.Errorf("redirect-capture listener bind failed on %s: %w", u.Host, lerr)
	}
	c := &redirectCapture{byState: make(map[string]string)}
	c.cond = sync.NewCond(&c.mu)
	srv := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			// Only a real OIDC callback carries a `code` or an `error`. Ignore everything else (favicon,
			// preflight, stray probes) so a non-callback request can never be recorded as a callback and
			// be claimed by a waiter (A4 capture-handler poisoning).
			if q.Get("code") == "" && q.Get("error") == "" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			// Record keyed by the callback's OWN state. A duplicate/stale leg-1 callback (state=S1) is
			// therefore filed under S1 and can never satisfy a leg-2 wait (expectState=S2): cross-leg
			// poisoning is impossible. The first callback per state wins (record drops later duplicates).
			c.record(q.Get("state"), scheme+"://"+r.Host+r.URL.RequestURI())
			_, _ = io.WriteString(w, "authorization received — you may close this tab")
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return c, nil
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
			// REUSE the single parent-scope authorizer across BOTH levels: its interactive variant binds
			// ONE redirect-capture listener (lazily, on the first Authorize) on the fixed
			// REFSVC_REDIRECT_URI port and keeps it for the whole run, closed once at the parent t's
			// Cleanup. Building a fresh one per level would re-Listen on that same port and race the prior
			// level's async close (EADDRINUSE). State-matched routing keeps each leg's callback isolated.
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
