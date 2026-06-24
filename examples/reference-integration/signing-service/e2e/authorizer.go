// Package e2e drives the reference signing service end-to-end. This file holds the pluggable
// Authorizer seam used by both the credential-free flow (mockAutoApprove) and the gated live flow
// (Interactive / Headless) — the only thing that differs between those runs (contracts/authorizer.md).
package e2e

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Authorizer completes one Cleverbase redirect (service-scope, then credential-scope/SCAL2) and
// returns the OIDC callback parameters. It is the only thing that differs between credential-free and
// live runs, and between human-in-the-loop and headless live runs: the driving loop only needs
// (code, state) to call POST /v1/sign/complete, so swapping authorizers changes nothing in the
// core/flow (FR-013, contracts/authorizer.md).
type Authorizer interface {
	// Authorize is given the authorize URL the flow produced and the CSRF state it expects back. It
	// returns the (code, state) to feed into POST /v1/sign/complete, or an error.
	Authorize(ctx context.Context, authorizeURL, expectState string) (code, state string, err error)
}

// errAuthNotCompleted is the sentinel for "the human/automation did not finish authorization within
// the window" — the live path maps it to a clear, non-defect outcome (FR-011, Edge Cases).
var errAuthNotCompleted = errors.New("authorization not completed")

// errAuthDeclined is the sentinel for a signer decline / OIDC access_denied.
var errAuthDeclined = errors.New("authorization declined")

// errHeadlessNotConfigured is returned by Headless until an automatable Cleverbase test-credential
// approval exists (a pending external dependency — see spec Dependencies / U1). The drop-in type
// ships now; it fails fast with this specific error rather than hanging or panicking.
var errHeadlessNotConfigured = errors.New("headless approval not configured: no automatable Cleverbase test-credential approval is wired (set REFSVC_LIVE_AUTHORIZER=interactive)")

// mockAutoApprove is the credential-free Authorizer: it GETs the mock upstream's auto-approving
// authorize endpoint (without following the redirect) and returns the code+state from the Location.
// This is the refactored former followRedirect, now satisfying the Authorizer seam so the
// credential-free loop is authorizer-agnostic.
type mockAutoApprove struct{}

func (mockAutoApprove) Authorize(ctx context.Context, authorizeURL, _ string) (code, state string, err error) {
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authorizeURL, nil)
	if err != nil {
		return "", "", fmt.Errorf("build authorize request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("authorize GET: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return codeStateFromLocation(resp.Header.Get("Location"))
}

// codeStateFromLocation parses an OIDC redirect Location, returning (code, state) — or a declined
// error when the callback carries error=access_denied (mapped distinctly from an SDK defect, FR-011).
//
// FR-010: the callback URL carries the live OIDC `code` (a secret). Errors here MUST NOT interpolate
// the raw Location — only the structural parse failure is reported (no code/state values leak to logs).
func codeStateFromLocation(loc string) (code, state string, err error) {
	if loc == "" {
		return "", "", errors.New("authorize response carried no Location redirect")
	}
	u, err := url.Parse(loc)
	if err != nil {
		return "", "", fmt.Errorf("parse redirect callback: %w", err)
	}
	q := u.Query()
	if e := q.Get("error"); e != "" {
		if e == "access_denied" {
			return "", "", fmt.Errorf("%w: %s", errAuthDeclined, e)
		}
		return "", "", fmt.Errorf("authorization error: %s", e)
	}
	return q.Get("code"), q.Get("state"), nil
}

// Interactive is the default live Authorizer: it surfaces the authorize URL to a human and captures
// the redirect callback. Capture is via a callback channel (CaptureCallback) fed by a redirect-capture
// listener or a stdin paste; Timeout bounds the wait so an unapproved authorization fails fast with a
// clear "authorization not completed" error instead of hanging (FR-011, Edge Cases).
type Interactive struct {
	// Surface is called with the authorize URL the human must open (e.g. print it / open a browser).
	// If nil, the URL is not surfaced (the caller is expected to have arranged capture out of band).
	Surface func(authorizeURL string)
	// CaptureCallback yields the raw redirect callback URL (or query string) once the human completes
	// the journey — typically fed by a local redirect-capture HTTP listener at REFSVC_REDIRECT_URI or
	// a stdin reader. It MUST be supplied; without it Authorize cannot complete and times out.
	CaptureCallback <-chan string
	// Timeout bounds the wait for the callback. Zero means "use the caller's context deadline only".
	Timeout time.Duration
}

// Authorize surfaces the authorize URL (if a Surface hook is set), then waits — bounded by Timeout
// and the caller's context — for the captured redirect callback, returning its (code, state). A
// timeout/cancel yields errAuthNotCompleted (never a hang); access_denied yields errAuthDeclined; a
// state that does not match expectState is rejected as a possible CSRF.
func (i Interactive) Authorize(ctx context.Context, authorizeURL, expectState string) (code, state string, err error) {
	if i.Surface != nil {
		i.Surface(authorizeURL)
	}
	// Bound the wait: the context deadline AND (when set) the per-call Timeout, whichever is sooner.
	if i.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, i.Timeout)
		defer cancel()
	}
	if i.CaptureCallback == nil {
		// No capture mechanism: wait out the deadline rather than block forever, then fail clearly.
		<-ctx.Done()
		return "", "", fmt.Errorf("%w: no redirect-capture mechanism configured", errAuthNotCompleted)
	}
	select {
	case <-ctx.Done():
		return "", "", fmt.Errorf("%w: %w (signer did not approve within the window)", errAuthNotCompleted, ctx.Err())
	case raw, ok := <-i.CaptureCallback:
		if !ok {
			return "", "", fmt.Errorf("%w: capture channel closed before a callback arrived", errAuthNotCompleted)
		}
		code, state, err = parseCapturedCallback(raw)
		if err != nil {
			return "", "", err
		}
		// CSRF: Cleverbase must echo back the state the flow issued. A mismatch is surfaced loudly,
		// never silently accepted (contracts/authorizer.md).
		if expectState != "" && state != expectState {
			return "", "", fmt.Errorf("authorize state mismatch: got %q, expected %q (possible CSRF)", state, expectState)
		}
		return code, state, nil
	}
}

// parseCapturedCallback accepts either a full redirect URL or a bare query string and extracts
// (code, state), surfacing access_denied as a decline.
func parseCapturedCallback(raw string) (code, state string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", fmt.Errorf("%w: empty callback", errAuthNotCompleted)
	}
	if strings.Contains(raw, "://") || strings.HasPrefix(raw, "/") {
		return codeStateFromLocation(raw)
	}
	// FR-010: the raw query carries the live `code`/`state` (secrets) — report only the parse failure,
	// never the raw query string.
	q, perr := url.ParseQuery(strings.TrimPrefix(raw, "?"))
	if perr != nil {
		return "", "", fmt.Errorf("parse callback query: %w", perr)
	}
	if e := q.Get("error"); e != "" {
		if e == "access_denied" {
			return "", "", fmt.Errorf("%w: %s", errAuthDeclined, e)
		}
		return "", "", fmt.Errorf("authorization error: %s", e)
	}
	return q.Get("code"), q.Get("state"), nil
}

// Headless is the opt-in live Authorizer selected by REFSVC_LIVE_AUTHORIZER=headless. It is the
// interface drop-in for an automatable Cleverbase test-credential approval (U1). The approval
// mechanism is a pending external dependency; until it is wired, Authorize fails fast with the
// specific errHeadlessNotConfigured error (never a hang/panic), keeping the shipped branch covered
// and the interactive path unaffected.
type Headless struct{}

// Authorize fails fast with errHeadlessNotConfigured until an automatable Cleverbase test-credential
// approval is wired (a pending external dependency).
func (Headless) Authorize(context.Context, string, string) (code, state string, err error) {
	return "", "", errHeadlessNotConfigured
}
