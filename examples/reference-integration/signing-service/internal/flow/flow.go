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
func (e *Engine) drive(s *session.Session, res Result) (session.Status, string, string, error) {
	for {
		handle := res.Handle
		e.Store.Update(s, func() { s.Handle = handle })
		kind, _ := res.Step["kind"].(string)
		switch kind {
		case "perform_http":
			method, rawURL, headers, body := stepHTTP(res.Step)
			e.Log.Info("effect.perform_http", "method", method, "url", redact(rawURL))
			status, respBody, err := e.Up.Do(method, rawURL, headers, body)
			if err != nil {
				e.fail(s, session.StatusFailed, "upstream_error", nil)
				e.Log.Error("effect.http_error", "url", redact(rawURL), "err", err.Error())
				return session.StatusFailed, "", "upstream_error", nil
			}
			e.Log.Info("effect.http_result", "status", status)
			next, err := e.SDK.ResumeHTTP(handle, status, respBody)
			if err != nil {
				// Scrub + de-index now rather than letting the handle linger until the TTL.
				e.fail(s, session.StatusFailed, "resume_error", nil)
				return "", "", "", fmt.Errorf("resume http: %w", err)
			}
			res = next
		case "redirect":
			rawURL, state := stepRedirect(res.Step)
			e.Store.SetState(s, state)
			e.Store.Update(s, func() { s.Status = session.StatusAuthorizing })
			e.Log.Info("transition.redirect", "state", redactState(state))
			return session.StatusAuthorizing, e.rewriteRedirect(rawURL), "", nil
		case "done":
			pdf, evidence := stepDone(res.Step)
			e.Store.Update(s, func() {
				s.Status = session.StatusCompleted
				s.ResultPDF = pdf
				s.Evidence = evidence
			})
			e.Store.Finalize(s)
			e.Log.Info("transition.done", "pdf_bytes", len(pdf))
			return session.StatusCompleted, "", "", nil
		case "failed":
			status, reason := mapFailed(res.Step)
			e.fail(s, status, reason, stepEvidence(res.Step))
			e.Log.Info("transition.failed", "reason", reason)
			return status, "", reason, nil
		default:
			e.fail(s, session.StatusFailed, "resume_error", nil)
			return "", "", "", fmt.Errorf("unexpected step kind %q", kind)
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
	kind, _ := res.Step["kind"].(string)
	if kind != "redirect" {
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
func (e *Engine) Complete(s *session.Session, code, state string) (session.Status, string, string, error) {
	terminal, handle := e.Store.ResumeView(s) // read terminal + handle under the store lock
	if terminal {
		return "", "", "", ErrTerminal
	}
	res, err := e.SDK.ResumeRedirect(handle, code, state)
	if err != nil {
		e.fail(s, session.StatusFailed, "resume_error", nil)
		return "", "", "", err
	}
	return e.drive(s, res)
}

// CompleteError advances a session after a redirect return carrying an OAuth error.
func (e *Engine) CompleteError(s *session.Session, oauthError, state string) (session.Status, string, string, error) {
	terminal, handle := e.Store.ResumeView(s)
	if terminal {
		return "", "", "", ErrTerminal
	}
	res, err := e.SDK.ResumeRedirectError(handle, oauthError, state)
	if err != nil {
		e.fail(s, session.StatusFailed, "resume_error", nil)
		return "", "", "", err
	}
	return e.drive(s, res)
}

// --- Step parsing helpers ---

func stepRedirect(step map[string]any) (rawURL, state string) {
	rawURL, _ = step["url"].(string)
	state, _ = step["state"].(string)
	return
}

func stepHTTP(step map[string]any) (method, rawURL string, headers [][2]string, body []byte) {
	method, _ = step["method"].(string)
	rawURL, _ = step["url"].(string)
	if hs, ok := step["headers"].([]any); ok {
		for _, h := range hs {
			if pair, ok := h.([]any); ok && len(pair) == 2 {
				k, _ := pair[0].(string)
				v, _ := pair[1].(string)
				headers = append(headers, [2]string{k, v})
			}
		}
	}
	if b, ok := step["body"].([]byte); ok {
		body = b
	}
	return
}

func stepDone(step map[string]any) (pdf, evidence []byte) {
	if signed, ok := step["signed"].(map[string]any); ok {
		if p, ok := signed["pdf"].([]byte); ok {
			pdf = p
		}
	}
	evidence = stepEvidence(step)
	return
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
		outcome, _ = ev["outcome"].(string)
	}
	if outcome == "declined" {
		return session.StatusDeclined, "declined"
	}
	if outcome == "" {
		outcome = "unknown"
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
