package e2e

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// freeLoopbackHostPort grabs a free 127.0.0.1 port by binding then immediately releasing it, returning
// "127.0.0.1:<port>". The port is then re-bindable by startRedirectCapture; this mirrors how the live
// harness binds a known loopback REFSVC_REDIRECT_URI host:port.
func freeLoopbackHostPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// deliverCallback posts a browser-style redirect callback (GET) to the capture listener at hostPort and
// returns the HTTP status code, so a test can assert the handler accepted/ignored it.
func deliverCallback(t *testing.T, hostPort, rawQuery string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+hostPort+"/cb?"+rawQuery, nil)
	if err != nil {
		t.Fatalf("build callback request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("deliver callback: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// waitListening dials hostPort until it answers (the capture server's goroutine may not have begun
// Serve immediately), so a test delivers callbacks only once the listener is live.
func waitListening(t *testing.T, hostPort string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", hostPort, 50*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("capture listener at %s never came up", hostPort)
}

// TestLiveInteractiveTwoSequentialCapturesNoRebind (regression for the per-leg listener rebind race):
// runFlow drives Authorize twice on the SAME REFSVC_REDIRECT_URI host:port. The prior implementation
// re-bound a fresh listener per leg, racing leg-1's asynchronous close and hitting EADDRINUSE on leg-2.
// This drives liveInteractive through TWO sequential Authorize legs on the same redirect URI and asserts
// BOTH bind and capture their own callback — proving the listener is bound once and reused (no rebind).
func TestLiveInteractiveTwoSequentialCapturesNoRebind(t *testing.T) {
	hostPort := freeLoopbackHostPort(t)
	redirectURI := "http://" + hostPort + "/cb"
	li := &liveInteractive{
		t:           t,
		redirectURI: redirectURI,
		surface:     func(string) {},
		timeout:     2 * time.Second,
	}

	// Two legs, each with its own state, driven sequentially (as runFlow does: service-scope then SCAL2).
	for leg, st := range []string{"state-leg-1", "state-leg-2"} {
		var (
			gotCode, gotState string
			gotErr            error
			done              = make(chan struct{})
		)
		go func() {
			gotCode, gotState, gotErr = li.Authorize(context.Background(), "https://issuer.example/authorize?state="+st, st)
			close(done)
		}()

		// The listener is bound synchronously by the first Authorize; for both legs it is up by the time
		// the goroutine reaches the capture wait. Poll until it answers, then deliver this leg's callback.
		waitListening(t, hostPort)
		if code := deliverCallback(t, hostPort, "code=auth-code-"+st+"&state="+st); code != http.StatusOK {
			t.Fatalf("leg %d: callback delivery returned %d, want 200 (listener must accept the real callback)", leg+1, code)
		}

		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatalf("leg %d: Authorize hung — the per-leg capture never received the callback (rebind/EADDRINUSE?)", leg+1)
		}
		if gotErr != nil {
			t.Fatalf("leg %d: Authorize errored (rebind failure would surface here): %v", leg+1, gotErr)
		}
		if gotCode != "auth-code-"+st || gotState != st {
			t.Fatalf("leg %d: got (code=%q,state=%q), want (auth-code-%s,%s)", leg+1, gotCode, gotState, st, st)
		}
	}
}

// TestRedirectCaptureIgnoresNonCallbackRequests (A4 capture-handler poisoning): a stray request with
// neither a `code` nor an `error` (favicon/preflight/probe) MUST NOT win the buffered capture channel
// and feed a code-less callback that drops the real one. It asserts such a request is ignored (204) and
// the subsequently-delivered REAL callback is the one captured.
func TestRedirectCaptureIgnoresNonCallbackRequests(t *testing.T) {
	hostPort := freeLoopbackHostPort(t)
	rc, err := startRedirectCapture(t, "http://"+hostPort+"/cb")
	if err != nil {
		t.Fatalf("startRedirectCapture: %v", err)
	}
	ch := rc.nextLeg()
	waitListening(t, hostPort)

	// A favicon-style stray request: no code, no error. Must be ignored (204), not buffered.
	if code := deliverCallback(t, hostPort, "favicon=1"); code != http.StatusNoContent {
		t.Fatalf("stray non-callback request returned %d, want 204 (it must be ignored, not captured)", code)
	}
	// The channel must still be empty — the stray request did not poison it.
	select {
	case raw := <-ch:
		t.Fatalf("stray non-callback request poisoned the capture channel with %q", raw)
	default:
	}

	// The REAL callback (carries a code) is captured and wins the channel.
	if code := deliverCallback(t, hostPort, "code=REAL&state=s"); code != http.StatusOK {
		t.Fatalf("real callback returned %d, want 200", code)
	}
	select {
	case raw := <-ch:
		if !strings.Contains(raw, "code=REAL") || !strings.Contains(raw, "state=s") {
			t.Fatalf("captured callback missing code/state: %q", raw)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("real callback was not captured (the channel was poisoned or dropped)")
	}
}

// TestRedirectCaptureCapturesErrorCallback asserts a callback carrying an OIDC `error` (no code) is
// still captured (the handler must let a decline through, only stray no-code/no-error requests are
// ignored).
func TestRedirectCaptureCapturesErrorCallback(t *testing.T) {
	hostPort := freeLoopbackHostPort(t)
	rc, err := startRedirectCapture(t, "http://"+hostPort+"/cb")
	if err != nil {
		t.Fatalf("startRedirectCapture: %v", err)
	}
	ch := rc.nextLeg()
	waitListening(t, hostPort)

	if code := deliverCallback(t, hostPort, "error=access_denied&state=s"); code != http.StatusOK {
		t.Fatalf("error callback returned %d, want 200", code)
	}
	select {
	case raw := <-ch:
		if !strings.Contains(raw, "error=access_denied") {
			t.Fatalf("captured callback missing error param: %q", raw)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("error callback was not captured")
	}
}

// TestStartRedirectCaptureRejectsNonLoopback (A3): scheme + non-empty host is NOT enough — an
// all-interfaces (0.0.0.0) or routable host MUST be rejected with a distinct LOOPBACK error and never
// bound, so the capture listener is never exposed off-box.
func TestStartRedirectCaptureRejectsNonLoopback(t *testing.T) {
	for _, uri := range []string{
		"http://0.0.0.0:8080/cb",     // all interfaces
		"http://192.0.2.1:8080/cb",   // routable (TEST-NET-1)
		"http://example.com:8080/cb", // routable host name
		"http://[::]:8080/cb",        // IPv6 all interfaces
	} {
		t.Run(uri, func(t *testing.T) {
			_, err := startRedirectCapture(t, uri)
			if err == nil {
				t.Fatalf("non-loopback redirect URI %q was accepted; it MUST be rejected", uri)
			}
			if !strings.Contains(strings.ToLower(err.Error()), "loopback") {
				t.Fatalf("rejection for %q should name the LOOPBACK requirement, got: %v", uri, err)
			}
		})
	}
}

// TestStartRedirectCaptureAcceptsLoopback asserts the loopback forms (127.x, ::1, localhost) are
// accepted and bound.
func TestStartRedirectCaptureAcceptsLoopback(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "[::1]", "localhost"} {
		t.Run(host, func(t *testing.T) {
			// Use port 0 to get a free loopback port for each host form, then format the URI.
			ln, err := net.Listen("tcp", host+":0")
			if err != nil {
				t.Skipf("loopback host %s not bindable in this environment: %v", host, err)
			}
			port := ln.Addr().(*net.TCPAddr).Port
			_ = ln.Close()
			uri := fmt.Sprintf("http://%s:%d/cb", host, port)
			if _, err := startRedirectCapture(t, uri); err != nil {
				t.Fatalf("loopback redirect URI %q should be accepted, got: %v", uri, err)
			}
		})
	}
}

// TestStartRedirectCaptureRejectsBadSchemeAndHost covers the non-http(s) scheme and missing-host
// branches.
func TestStartRedirectCaptureRejectsBadSchemeAndHost(t *testing.T) {
	if _, err := startRedirectCapture(t, "ftp://127.0.0.1:8080/cb"); err == nil ||
		!strings.Contains(err.Error(), "http(s)") {
		t.Fatalf("non-http(s) scheme should be rejected naming http(s), got: %v", err)
	}
	if _, err := startRedirectCapture(t, "http:///cb"); err == nil ||
		!strings.Contains(err.Error(), "host") {
		t.Fatalf("empty host should be rejected naming the missing host, got: %v", err)
	}
	if _, err := startRedirectCapture(t, "://bad::url"); err == nil {
		t.Fatal("a malformed URL should be rejected")
	}
}

// TestStartRedirectCaptureBindFailureIsDistinct asserts a bind failure (port already in use) surfaces a
// distinct listener error, not a silent timeout — so the signer is never blamed for a bind problem.
func TestStartRedirectCaptureBindFailureIsDistinct(t *testing.T) {
	// Hold a loopback port so the capture cannot bind it.
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hold listen: %v", err)
	}
	defer func() { _ = held.Close() }()
	uri := "http://" + held.Addr().String() + "/cb"
	if _, err := startRedirectCapture(t, uri); err == nil ||
		!strings.Contains(err.Error(), "bind failed") {
		t.Fatalf("a bind collision should surface a distinct 'bind failed' error, got: %v", err)
	}
}

// TestLiveInteractiveBindFailureFailsFast asserts liveInteractive.Authorize surfaces a bind failure
// immediately (FR-011) rather than waiting out the timeout as a signer no-show.
func TestLiveInteractiveBindFailureFailsFast(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hold listen: %v", err)
	}
	defer func() { _ = held.Close() }()
	li := &liveInteractive{
		t:           t,
		redirectURI: "http://" + held.Addr().String() + "/cb",
		surface:     func(string) { t.Fatal("URL must NOT be surfaced when the listener cannot bind") },
		timeout:     time.Minute, // long: the test would hang if the bind error were not surfaced fast
	}
	start := time.Now()
	if _, _, err := li.Authorize(context.Background(), "https://issuer.example/authorize?state=s", "s"); err == nil ||
		!strings.Contains(err.Error(), "bind failed") {
		t.Fatalf("bind failure should fail fast with a 'bind failed' error, got: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("bind failure took %v — it must fail fast, not wait out the timeout", elapsed)
	}
}

// TestCodeStateFromLocationNoCodeLeak (A2 / FR-010): a malformed Location MUST yield a structural-only
// error — the raw URL (which embeds code=<secret>) must NEVER appear in the returned error.
func TestCodeStateFromLocationNoCodeLeak(t *testing.T) {
	// A control character makes url.Parse fail; the raw string carries a secret code.
	bad := "https://app.example/cb?code=SUPERSECRETCODE&state=ST\x7f\n"
	_, _, err := codeStateFromLocation(bad)
	if err == nil {
		t.Fatal("malformed Location should error")
	}
	if strings.Contains(err.Error(), "SUPERSECRETCODE") || strings.Contains(err.Error(), bad) {
		t.Fatalf("FR-010 leak: error embeds the raw URL/code: %v", err)
	}
	if !strings.Contains(err.Error(), "malformed URL") {
		t.Fatalf("expected a structural-only 'malformed URL' error, got: %v", err)
	}
}

// TestParseCapturedCallbackNoCodeLeak (A2 / FR-010): a bare query string that fails url.ParseQuery MUST
// yield a structural-only error with no raw query/code/state.
func TestParseCapturedCallbackNoCodeLeak(t *testing.T) {
	// An invalid %-escape makes url.ParseQuery fail; the fragment carries part of a secret.
	bad := "code=SECRET%ZZ&state=ST"
	_, _, err := parseCapturedCallback(bad)
	if err == nil {
		t.Fatal("malformed query should error")
	}
	if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "%ZZ") {
		t.Fatalf("FR-010 leak: error embeds the raw query/code: %v", err)
	}
	if !strings.Contains(err.Error(), "malformed query string") {
		t.Fatalf("expected a structural-only 'malformed query string' error, got: %v", err)
	}
}

// TestInteractiveStateMismatchNoStateLeak (A5 / FR-010): the CSRF state-mismatch error MUST NOT
// interpolate the raw got/expected state values (a per-session secret) — only redacted lengths.
func TestInteractiveStateMismatchNoStateLeak(t *testing.T) {
	const attacker = "ATTACKERSTATEVALUE"
	const expected = "EXPECTEDSTATEVALUE"
	ch := make(chan string, 1)
	ch <- "https://app.example/cb?code=c&state=" + attacker
	auth := Interactive{CaptureCallback: ch, Timeout: time.Second}
	_, _, err := auth.Authorize(context.Background(), "https://issuer.example/authorize?state="+expected, expected)
	if err == nil || !strings.Contains(err.Error(), "state mismatch") {
		t.Fatalf("expected a state-mismatch error, got %v", err)
	}
	if strings.Contains(err.Error(), attacker) || strings.Contains(err.Error(), expected) {
		t.Fatalf("FR-010 leak: state-mismatch error embeds a raw state value: %v", err)
	}
}
