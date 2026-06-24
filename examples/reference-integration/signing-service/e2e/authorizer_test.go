package e2e

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingAuthorizer is a stub Authorizer that records every Authorize call (the URL + expected
// state) and the (code,state) it returns, then delegates to mockAutoApprove so the credential-free
// flow actually completes. It lets the harness assert the seam is loop-agnostic: Authorize is called
// exactly once per redirect and its return is fed into /v1/sign/complete unchanged.
type recordingAuthorizer struct {
	mu       sync.Mutex
	calls    int
	returned [][2]string // (code, state) per call, in order
}

func (r *recordingAuthorizer) Authorize(ctx context.Context, authorizeURL, expectState string) (code, state string, err error) {
	code, state, err = mockAutoApprove{}.Authorize(ctx, authorizeURL, expectState)
	r.mu.Lock()
	r.calls++
	r.returned = append(r.returned, [2]string{code, state})
	r.mu.Unlock()
	return code, state, err
}

// spyComplete wraps a signing service, recording the raw body of every POST /v1/sign/complete so the
// test can assert the Authorizer's (code,state) reaches /complete byte-for-byte unchanged.
func spyComplete(t *testing.T, target *httptest.Server, bodies *[]string, mu *sync.Mutex) *httptest.Server {
	t.Helper()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/sign/complete") {
			mu.Lock()
			*bodies = append(*bodies, string(body))
			mu.Unlock()
		}
		req, err := http.NewRequest(r.Method, target.URL+r.URL.RequestURI(), strings.NewReader(string(body)))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		req.Header = r.Header.Clone()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(proxy.Close)
	return proxy
}

// TestAuthorizerCalledTwiceFedUnchanged (T018): runFlow MUST call Authorize exactly once per redirect
// — twice per signing flow (service-scope, then SCAL2) — and feed each returned (code,state) into
// POST /v1/sign/complete unchanged. Proves the authorizer seam is loop-agnostic (contracts/authorizer.md).
func TestAuthorizerCalledTwiceFedUnchanged(t *testing.T) {
	svc := stack(t, "B-B", "v1_rsa")
	var mu sync.Mutex
	var completeBodies []string
	spy := spyComplete(t, svc, &completeBodies, &mu)

	rec := &recordingAuthorizer{}
	_, _, status, _ := runFlow(t, rec, spy, `{"conformanceLevel":"B-B"}`)
	if status != "completed" {
		t.Fatalf("expected completed, got %s", status)
	}

	rec.mu.Lock()
	calls, returned := rec.calls, rec.returned
	rec.mu.Unlock()
	if calls != 2 {
		t.Fatalf("Authorize called %d times, want exactly 2 (one per redirect)", calls)
	}

	mu.Lock()
	bodies := append([]string(nil), completeBodies...)
	mu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("expected 2 /v1/sign/complete calls, got %d", len(bodies))
	}
	// Each Authorize return (code,state) must appear verbatim in the matching /complete body — the
	// loop forwards them untouched.
	for i, cs := range returned {
		code, state := cs[0], cs[1]
		if code == "" || state == "" {
			t.Fatalf("call %d returned empty code/state (%q,%q)", i, code, state)
		}
		if !strings.Contains(bodies[i], `"code":"`+code+`"`) || !strings.Contains(bodies[i], `"state":"`+state+`"`) {
			t.Fatalf("complete body %d did not carry the Authorizer's (code,state) unchanged: body=%s code=%s state=%s", i, bodies[i], code, state)
		}
	}
}

// TestInteractiveTimeoutDoesNotHang (T020 / F4): an Interactive Authorizer whose human never approves
// MUST fail fast with a clear "authorization not completed" error within its window — never hang.
func TestInteractiveTimeoutDoesNotHang(t *testing.T) {
	auth := Interactive{
		CaptureCallback: make(chan string), // never fed
		Timeout:         50 * time.Millisecond,
	}
	done := make(chan struct{})
	var code, state string
	var err error
	go func() {
		code, state, err = auth.Authorize(context.Background(), "https://issuer.example/authorize?state=abc", "abc")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Interactive.Authorize hung past its timeout (runFlow would hang)")
	}
	if err == nil {
		t.Fatalf("expected a timeout error, got (code=%q,state=%q,nil)", code, state)
	}
	if !errors.Is(err, errAuthNotCompleted) {
		t.Fatalf("timeout error should be errAuthNotCompleted, got %v", err)
	}
	if !strings.Contains(err.Error(), "authorization not completed") {
		t.Fatalf("timeout error message should be clear/specific, got %q", err.Error())
	}
}

// TestInteractiveContextCancelDoesNotHang asserts a cancelled parent context (no per-call Timeout)
// also fails fast rather than blocking on the capture channel.
func TestInteractiveContextCancelDoesNotHang(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	auth := Interactive{CaptureCallback: make(chan string)}
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	_, _, err := auth.Authorize(ctx, "https://issuer.example/authorize?state=x", "x")
	if !errors.Is(err, errAuthNotCompleted) {
		t.Fatalf("cancelled context should surface errAuthNotCompleted, got %v", err)
	}
}

// TestInteractiveDeclined (T020 / F4): a callback carrying error=access_denied surfaces a clear,
// specific "declined" error distinct from an SDK defect (FR-011).
func TestInteractiveDeclined(t *testing.T) {
	ch := make(chan string, 1)
	ch <- "https://app.example/cb?error=access_denied&state=abc"
	auth := Interactive{CaptureCallback: ch, Timeout: time.Second}
	_, _, err := auth.Authorize(context.Background(), "https://issuer.example/authorize?state=abc", "abc")
	if !errors.Is(err, errAuthDeclined) {
		t.Fatalf("access_denied should surface errAuthDeclined, got %v", err)
	}
}

// TestInteractiveSuccessAndSurface drives the happy path: a surfaced URL + a captured callback yields
// the (code,state), and a Surface hook is invoked with the authorize URL.
func TestInteractiveSuccessAndSurface(t *testing.T) {
	ch := make(chan string, 1)
	ch <- "https://app.example/cb?code=AUTHCODE&state=expected"
	var surfaced string
	auth := Interactive{
		Surface:         func(u string) { surfaced = u },
		CaptureCallback: ch,
		Timeout:         time.Second,
	}
	code, state, err := auth.Authorize(context.Background(), "https://issuer.example/authorize?state=expected", "expected")
	if err != nil {
		t.Fatalf("happy path: %v", err)
	}
	if code != "AUTHCODE" || state != "expected" {
		t.Fatalf("got (code=%q,state=%q), want (AUTHCODE,expected)", code, state)
	}
	if surfaced != "https://issuer.example/authorize?state=expected" {
		t.Fatalf("Surface got %q", surfaced)
	}
}

// TestInteractiveStateMismatch asserts a callback whose state differs from the expected CSRF nonce is
// rejected loudly, never silently accepted (contracts/authorizer.md).
func TestInteractiveStateMismatch(t *testing.T) {
	ch := make(chan string, 1)
	ch <- "https://app.example/cb?code=c&state=attacker"
	auth := Interactive{CaptureCallback: ch, Timeout: time.Second}
	_, _, err := auth.Authorize(context.Background(), "https://issuer.example/authorize?state=expected", "expected")
	if err == nil || !strings.Contains(err.Error(), "state mismatch") {
		t.Fatalf("expected a CSRF state-mismatch error, got %v", err)
	}
}

// TestInteractiveBareQueryAndClosedChannel covers the bare-query-string capture form and a closed
// capture channel (the human aborted) — both must produce a clear error, not a panic/hang.
func TestInteractiveBareQueryAndClosedChannel(t *testing.T) {
	ch := make(chan string, 1)
	ch <- "code=Q&state=s"
	if code, state, err := (Interactive{CaptureCallback: ch, Timeout: time.Second}).
		Authorize(context.Background(), "https://i/authorize?state=s", "s"); err != nil || code != "Q" || state != "s" {
		t.Fatalf("bare-query capture: code=%q state=%q err=%v", code, state, err)
	}
	closed := make(chan string)
	close(closed)
	if _, _, err := (Interactive{CaptureCallback: closed, Timeout: time.Second}).
		Authorize(context.Background(), "https://i/authorize?state=s", "s"); !errors.Is(err, errAuthNotCompleted) {
		t.Fatalf("closed channel should surface errAuthNotCompleted, got %v", err)
	}
}

// TestHeadlessNotConfigured (T024 / U1-r4): selecting the Headless authorizer without the automatable
// approval mechanism wired returns the specific "headless approval not configured" error — never a
// hang or panic — covering the shipped drop-in branch.
func TestHeadlessNotConfigured(t *testing.T) {
	_, _, err := Headless{}.Authorize(context.Background(), "https://issuer.example/authorize", "state")
	if !errors.Is(err, errHeadlessNotConfigured) {
		t.Fatalf("Headless should fail fast with errHeadlessNotConfigured, got %v", err)
	}
	if !strings.Contains(err.Error(), "headless approval not configured") {
		t.Fatalf("error message should be specific, got %q", err.Error())
	}
}

// TestMockAutoApproveDeclined ensures the credential-free authorizer also maps an access_denied
// Location to a decline (defensive: the mock auto-approves, but the mapping must be correct).
func TestMockAutoApproveDeclined(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://app.example/cb?error=access_denied")
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	_, _, err := mockAutoApprove{}.Authorize(context.Background(), srv.URL, "")
	if !errors.Is(err, errAuthDeclined) {
		t.Fatalf("expected errAuthDeclined, got %v", err)
	}
}

// TestCodeStateFromLocationNonAccessDeniedError covers the non-access_denied OIDC error branch in
// codeStateFromLocation (authorizer.go:79): a callback whose `error=` is NOT access_denied (e.g.
// server_error, invalid_request) MUST surface a clear "authorization error: <code>" — never be
// mistaken for a success (empty code/state, nil err). The interpolated value is the bounded OIDC
// error code only (not a secret). This guards the silent-success regression where an OIDC error
// would be POSTed to /complete as an empty (code,state).
func TestCodeStateFromLocationNonAccessDeniedError(t *testing.T) {
	for _, code := range []string{"server_error", "invalid_request", "temporarily_unavailable"} {
		t.Run(code, func(t *testing.T) {
			loc := "https://app.example/cb?error=" + code + "&state=somestate"
			gotCode, gotState, err := codeStateFromLocation(loc)
			if err == nil {
				t.Fatalf("non-access_denied error %q must NOT be a success; got (code=%q,state=%q,nil) — empty would be POSTed to /complete", code, gotCode, gotState)
			}
			// It must NOT be the access_denied decline path — that's a distinct outcome.
			if errors.Is(err, errAuthDeclined) {
				t.Fatalf("error %q wrongly mapped to errAuthDeclined: %v", code, err)
			}
			if !strings.Contains(err.Error(), "authorization error") || !strings.Contains(err.Error(), code) {
				t.Fatalf("expected an 'authorization error: %s' message, got %q", code, err.Error())
			}
			if gotCode != "" || gotState != "" {
				t.Fatalf("an OIDC error must return empty (code,state), got (code=%q,state=%q)", gotCode, gotState)
			}
		})
	}
}

// TestParseCapturedCallbackNonAccessDeniedError covers the non-access_denied OIDC error branch in
// parseCapturedCallback (authorizer.go:183) via the bare-query-string path (so it exercises the
// branch in parseCapturedCallback itself, not its delegation to codeStateFromLocation): a bare
// `error=<code>` query whose code is NOT access_denied MUST surface "authorization error: <code>",
// never a silent success.
func TestParseCapturedCallbackNonAccessDeniedError(t *testing.T) {
	for _, code := range []string{"server_error", "invalid_request"} {
		t.Run(code, func(t *testing.T) {
			// A bare query string (no "://", no leading "/") routes through parseCapturedCallback's own
			// url.ParseQuery branch rather than delegating to codeStateFromLocation.
			gotCode, gotState, err := parseCapturedCallback("error=" + code + "&state=somestate")
			if err == nil {
				t.Fatalf("non-access_denied error %q must NOT be a success; got (code=%q,state=%q,nil)", code, gotCode, gotState)
			}
			if errors.Is(err, errAuthDeclined) {
				t.Fatalf("error %q wrongly mapped to errAuthDeclined: %v", code, err)
			}
			if !strings.Contains(err.Error(), "authorization error") || !strings.Contains(err.Error(), code) {
				t.Fatalf("expected an 'authorization error: %s' message, got %q", code, err.Error())
			}
			if gotCode != "" || gotState != "" {
				t.Fatalf("an OIDC error must return empty (code,state), got (code=%q,state=%q)", gotCode, gotState)
			}
		})
	}
}

// TestInteractiveNonAccessDeniedError drives the non-access_denied OIDC error end-to-end through the
// Interactive Authorizer's capture path: a captured callback carrying ?error=server_error MUST yield
// a clear "authorization error" rather than completing the leg with an empty (code,state).
func TestInteractiveNonAccessDeniedError(t *testing.T) {
	ch := make(chan string, 1)
	ch <- "https://app.example/cb?error=server_error&state=abc"
	auth := Interactive{CaptureCallback: ch, Timeout: time.Second}
	code, state, err := auth.Authorize(context.Background(), "https://issuer.example/authorize?state=abc", "abc")
	if err == nil {
		t.Fatalf("server_error callback must NOT complete the leg; got (code=%q,state=%q,nil)", code, state)
	}
	if errors.Is(err, errAuthDeclined) {
		t.Fatalf("server_error wrongly mapped to errAuthDeclined: %v", err)
	}
	if !strings.Contains(err.Error(), "authorization error") || !strings.Contains(err.Error(), "server_error") {
		t.Fatalf("expected an 'authorization error: server_error' message, got %q", err.Error())
	}
	if code != "" || state != "" {
		t.Fatalf("an OIDC error must return empty (code,state), got (code=%q,state=%q)", code, state)
	}
}

// TestCodeStateFromLocationNoLocation covers the empty-Location branch in codeStateFromLocation
// (authorizer.go:66): when the authorize response carries no Location redirect, the function MUST
// return the specific "authorize response carried no Location redirect" error — never a false
// success with empty (code,state) that would be POSTed to /complete (the silent-success regression).
func TestCodeStateFromLocationNoLocation(t *testing.T) {
	gotCode, gotState, err := codeStateFromLocation("")
	if err == nil {
		t.Fatalf("an empty Location must NOT be a success; got (code=%q,state=%q,nil) — empty would be POSTed to /complete", gotCode, gotState)
	}
	if !strings.Contains(err.Error(), "carried no Location redirect") {
		t.Fatalf("expected the specific 'authorize response carried no Location redirect' error, got %q", err.Error())
	}
	if gotCode != "" || gotState != "" {
		t.Fatalf("a no-Location response must return empty (code,state), got (code=%q,state=%q)", gotCode, gotState)
	}
}
