// Package flow drives the SDK's sans-IO begin/resume state machine: it performs the emitted HTTP
// effects, advances across the two authorization redirects, maps terminal SDK outcomes to a
// frontend-facing status, and emits structured, secret-redacted logs of every effect and transition.
//
// The SDK and the HTTP effector are injected as interfaces so this package's unit tests run without
// cgo; the real adapters live in internal/sdk and internal/upstream.
package flow

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/session"
)

// Options carries the optional request inputs (the expected-signer binding, FR-014).
type Options struct {
	ExpectedSignerMatchOn string
	ExpectedSignerValue   string
}

// Result is one SDK step: the updated opaque handle and the decoded Step map.
type Result struct {
	Handle []byte
	Step   map[string]any
}

// SDK is the subset of the binding the flow drives.
type SDK interface {
	Begin(document []byte, conformance string, opts *Options) (Result, error)
	ResumeRedirect(handle []byte, code, state string) (Result, error)
	ResumeRedirectError(handle []byte, oauthError, state string) (Result, error)
	ResumeHTTP(handle []byte, status int, body []byte) (Result, error)
}

// Effector performs a single HTTP effect (the upstream client rewrites the host internally in
// fixtures mode).
type Effector interface {
	Do(method, rawURL string, headers [][2]string, body []byte) (int, []byte, error)
}

// ErrTerminal is returned when an already-terminal session is advanced again.
var ErrTerminal = errors.New("session already terminal")

// SDK step kinds emitted across the begin/resume state machine.
const (
	stepKindPerformHTTP = "perform_http"
	stepKindRedirect    = "redirect"
	stepKindDone        = "done"
	stepKindFailed      = "failed"
)

// outcomeDeclined is the terminal evidence outcome for a signer-declined flow.
const outcomeDeclined = "declined"

// Service-operational failure reasons this engine emits on a `failed` status, alongside the SDK's
// SigningOutcome failure codes (passed through verbatim from the evidence `outcome`). These are the
// single authoritative spelling for the snake_case wire codes; they MUST stay in sync with the
// `failed` reason set documented in specs/002-reference-integration/contracts/reference-service-api.md
// (the authoritative API definition). The session store emits one further code, "session_expired",
// on TTL expiry (see internal/session/store.go).
const (
	reasonUpstreamError = "upstream_error" // an upstream HTTP call failed
	reasonResumeError   = "resume_error"   // the SDK could not advance the state machine
	reasonUnknown       = "unknown"        // defensive catch-all for an unmapped/future SDK outcome
)

// Engine ties the SDK, effector, and session store together.
type Engine struct {
	SDK   SDK
	Up    Effector
	Store *session.Memory
	Log   *slog.Logger
	TTL   time.Duration
	// RedirectRewrite rewrites the authorization redirect URLs handed to the frontend to a
	// browser-reachable host (fixtures mode). Nil = identity (live mode / tests).
	RedirectRewrite func(string) string
}

func (e *Engine) rewriteRedirect(u string) string {
	if e.RedirectRewrite != nil {
		return e.RedirectRewrite(u)
	}
	return u
}

// drive runs the perform-http loop until the next redirect or a terminal step.
func (e *Engine) drive(s *session.Session, res Result) (status session.Status, redirectURL, reason string, err error) {
	for {
		handle := res.Handle
		e.Store.Update(s, func() { s.Handle = handle })
		switch stepKind(res.Step) {
		case stepKindPerformHTTP:
			ef := stepHTTP(res.Step)
			e.Log.Info("effect.perform_http", "method", ef.method, "url", redact(ef.rawURL))
			httpStatus, respBody, doErr := e.Up.Do(ef.method, ef.rawURL, ef.headers, ef.body)
			if doErr != nil {
				e.fail(s, session.StatusFailed, reasonUpstreamError, nil)
				e.Log.Error("effect.http_error", "url", redact(ef.rawURL), "err", doErr.Error())
				return session.StatusFailed, "", reasonUpstreamError, nil
			}
			e.Log.Info("effect.http_result", "status", httpStatus)
			next, resumeErr := e.SDK.ResumeHTTP(handle, httpStatus, respBody)
			if resumeErr != nil {
				// Scrub + de-index now rather than letting the handle linger until the TTL.
				e.fail(s, session.StatusFailed, reasonResumeError, nil)
				return "", "", "", fmt.Errorf("resume http: %w", resumeErr)
			}
			res = next
		case stepKindRedirect:
			rawURL, state := stepRedirect(res.Step)
			e.Store.SetState(s, state)
			e.Store.Update(s, func() { s.Status = session.StatusAuthorizing })
			e.Log.Info("transition.redirect", "state", redactState(state))
			return session.StatusAuthorizing, e.rewriteRedirect(rawURL), "", nil
		case stepKindDone:
			pdf, evidence := stepDone(res.Step)
			e.Store.Update(s, func() {
				s.Status = session.StatusCompleted
				s.ResultPDF = pdf
				s.Evidence = evidence
			})
			e.Store.Finalize(s)
			e.Log.Info("transition.done", "pdf_bytes", len(pdf))
			return session.StatusCompleted, "", "", nil
		case stepKindFailed:
			failStatus, failReason := mapFailed(res.Step)
			e.fail(s, failStatus, failReason, stepEvidence(res.Step))
			e.Log.Info("transition.failed", "reason", failReason)
			return failStatus, "", failReason, nil
		default:
			e.fail(s, session.StatusFailed, reasonResumeError, nil)
			return "", "", "", fmt.Errorf("unexpected step kind %q", stepKind(res.Step))
		}
	}
}

func (e *Engine) fail(s *session.Session, status session.Status, reason string, evidence []byte) {
	e.Store.Update(s, func() {
		s.Status = status
		s.Reason = reason
		if evidence != nil {
			s.Evidence = evidence
		}
	})
	e.Store.Finalize(s)
}

// Begin starts a session, stores the handle, and returns the (rewritten) service-auth redirect URL.
func (e *Engine) Begin(corr string, document []byte, conformance string, opts *Options) (string, error) {
	res, err := e.SDK.Begin(document, conformance, opts)
	if err != nil {
		return "", err
	}
	if kind := stepKind(res.Step); kind != stepKindRedirect {
		// begin always emits the service-scope redirect; anything else is a hard error.
		return "", fmt.Errorf("begin produced unexpected step %q", kind)
	}
	rawURL, state := stepRedirect(res.Step)
	s := e.Store.New(corr, state, conformance, e.TTL)
	e.Store.Update(s, func() {
		s.Handle = res.Handle
		s.Status = session.StatusAuthorizing
	})
	e.Log.Info("begin", "correlation_id", corr)
	return e.rewriteRedirect(rawURL), nil
}

// Complete advances a session after a redirect return with code+state.
func (e *Engine) Complete(s *session.Session, code, state string) (status session.Status, redirectURL, reason string, err error) {
	terminal, handle := e.Store.ResumeView(s) // read terminal + handle under the store lock
	if terminal {
		return "", "", "", ErrTerminal
	}
	res, err := e.SDK.ResumeRedirect(handle, code, state)
	if err != nil {
		e.fail(s, session.StatusFailed, reasonResumeError, nil)
		return "", "", "", err
	}
	return e.drive(s, res)
}

// CompleteError advances a session after a redirect return carrying an OAuth error.
func (e *Engine) CompleteError(s *session.Session, oauthError, state string) (status session.Status, redirectURL, reason string, err error) {
	terminal, handle := e.Store.ResumeView(s)
	if terminal {
		return "", "", "", ErrTerminal
	}
	res, err := e.SDK.ResumeRedirectError(handle, oauthError, state)
	if err != nil {
		e.fail(s, session.StatusFailed, reasonResumeError, nil)
		return "", "", "", err
	}
	return e.drive(s, res)
}

// --- Step parsing helpers ---

// mapString reads a string-typed field from a decoded step/evidence map, returning "" when the key
// is absent or holds a non-string. Centralizing the checked assertion keeps the per-field extraction
// uniform (and avoids scattering bare `v, _ := m[k].(string)` casts across the package).
func mapString(m map[string]any, key string) string {
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}

// stepKind returns the step's "kind" discriminator (or "" if absent/wrong-typed).
func stepKind(step map[string]any) string { return mapString(step, "kind") }

func stepRedirect(step map[string]any) (rawURL, state string) {
	return mapString(step, "url"), mapString(step, "state")
}

// httpEffect is the decoded shape of a perform_http step.
type httpEffect struct {
	method  string
	rawURL  string
	headers [][2]string
	body    []byte
}

func stepHTTP(step map[string]any) httpEffect {
	ef := httpEffect{method: mapString(step, "method"), rawURL: mapString(step, "url")}
	if hs, ok := step["headers"].([]any); ok {
		ef.headers = make([][2]string, 0, len(hs))
		for _, h := range hs {
			pair, ok := h.([]any)
			if !ok || len(pair) != 2 {
				continue
			}
			k, kok := pair[0].(string)
			v, vok := pair[1].(string)
			if kok && vok {
				ef.headers = append(ef.headers, [2]string{k, v})
			}
		}
	}
	if b, ok := step["body"].([]byte); ok {
		ef.body = b
	}
	return ef
}

func stepDone(step map[string]any) (pdf, evidence []byte) {
	if signed, ok := step["signed"].(map[string]any); ok {
		if p, ok := signed["pdf"].([]byte); ok {
			pdf = p
		}
	}
	return pdf, stepEvidence(step)
}

func stepEvidence(step map[string]any) []byte {
	ev, ok := step["evidence"]
	if !ok {
		return nil
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return nil
	}
	return b
}

func mapFailed(step map[string]any) (session.Status, string) {
	outcome := ""
	if ev, ok := step["evidence"].(map[string]any); ok {
		outcome = mapString(ev, "outcome")
	}
	if outcome == outcomeDeclined {
		return session.StatusDeclined, outcomeDeclined
	}
	if outcome == "" {
		outcome = reasonUnknown
	}
	return session.StatusFailed, outcome
}

// redact returns scheme://host/path of a URL, dropping the query (which can carry the document hash
// or an OAuth code) so logs never leak sensitive material.
func redact(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "(unparseable)"
	}
	return u.Scheme + "://" + u.Host + u.Path
}

// redactState keeps only a short prefix of the CSRF state for correlation in logs.
func redactState(state string) string {
	if len(state) > 6 {
		return state[:6] + "…"
	}
	return state
}
