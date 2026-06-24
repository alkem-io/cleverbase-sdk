package flow

import (
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/session"
)

// scriptedSDK returns a fixed sequence of Results, one per SDK call.
type scriptedSDK struct {
	steps []Result
	i     int
}

func (s *scriptedSDK) next() (Result, error) {
	if s.i >= len(s.steps) {
		return Result{}, io.EOF
	}
	r := s.steps[s.i]
	s.i++
	return r, nil
}
func (s *scriptedSDK) Begin([]byte, string, *Options) (Result, error)        { return s.next() }
func (s *scriptedSDK) ResumeRedirect([]byte, string, string) (Result, error) { return s.next() }
func (s *scriptedSDK) ResumeRedirectError([]byte, string, string) (Result, error) {
	return s.next()
}
func (s *scriptedSDK) ResumeHTTP([]byte, int, []byte) (Result, error) { return s.next() }

type fakeEffector struct {
	rewritePrefix string
	calls         []string
}

func (f *fakeEffector) Do(_, rawURL string, _ [][2]string, _ []byte) (int, []byte, error) {
	f.calls = append(f.calls, rawURL)
	return 200, []byte("{}"), nil
}
func (f *fakeEffector) Rewrite(u string) string {
	if f.rewritePrefix == "" {
		return u
	}
	return f.rewritePrefix + u
}

func redirect(url, state string) Result {
	return Result{Handle: []byte("h"), Step: map[string]any{"kind": "redirect", "url": url, "state": state}}
}
func performHTTP(url string) Result {
	return Result{Handle: []byte("h"), Step: map[string]any{"kind": "perform_http", "method": "POST", "url": url, "headers": []any{}, "body": []byte("{}")}}
}
func done(pdf []byte) Result {
	return Result{Handle: []byte("h"), Step: map[string]any{"kind": "done",
		"signed":   map[string]any{"pdf": pdf},
		"evidence": map[string]any{"outcome": "signed", "request_digest": "abcd"}}}
}
func failed(outcome string) Result {
	return Result{Handle: []byte("h"), Step: map[string]any{"kind": "failed",
		"evidence": map[string]any{"outcome": outcome, "failure_reason": "x"}}}
}

func newEngine(steps []Result) (*Engine, *fakeEffector) {
	up := &fakeEffector{}
	return &Engine{
		SDK:   &scriptedSDK{steps: steps},
		Up:    up,
		Store: session.NewMemory(),
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		TTL:   time.Minute,
	}, up
}

func TestFullHappyFlow(t *testing.T) {
	e, up := newEngine([]Result{
		redirect("https://cb/oauth2/authorize?scope=service", "s1"), // begin
		performHTTP("https://cb/oauth2/token"),                      // resume(code,s1)
		performHTTP("https://cb/csc/v1/credentials/list"),
		performHTTP("https://cb/csc/v1/credentials/info"),
		redirect("https://cb/oauth2/authorize?scope=credential&hash=SECRET", "s2"),
		performHTTP("https://cb/oauth2/token"), // resume(code,s2)
		performHTTP("https://cb/csc/v1/signatures/signHash"),
		done([]byte("%PDF-signed")),
	})

	url, err := e.Begin("corr-1", []byte("%PDF"), "B-B", nil)
	if err != nil || url == "" {
		t.Fatalf("begin: %v url=%q", err, url)
	}
	s, _ := e.Store.GetByState("s1")
	if s == nil || s.Status != session.StatusAuthorizing {
		t.Fatalf("session not stored at s1")
	}

	st, url2, _, err := e.Complete(s, "code1", "s1")
	if err != nil || st != session.StatusAuthorizing || url2 == "" {
		t.Fatalf("first complete: st=%s url=%q err=%v", st, url2, err)
	}
	if s.OAuthState != "s2" {
		t.Fatalf("state should be re-indexed to s2, got %q", s.OAuthState)
	}

	st, _, _, err = e.Complete(s, "code2", "s2")
	if err != nil || st != session.StatusCompleted {
		t.Fatalf("second complete: st=%s err=%v", st, err)
	}
	if string(s.ResultPDF) != "%PDF-signed" {
		t.Fatalf("result pdf missing: %q", s.ResultPDF)
	}
	if s.Handle != nil {
		t.Fatal("handle should be scrubbed on completion")
	}
	if len(up.calls) != 5 { // token, list, info, sad, signHash
		t.Fatalf("expected 5 upstream calls, got %d", len(up.calls))
	}
}

func TestOutcomeMappingAllDistinct(t *testing.T) {
	cases := map[string]struct {
		status session.Status
		reason string
	}{
		"declined":                   {session.StatusDeclined, "declined"},
		"authorization_expired":      {session.StatusFailed, "authorization_expired"},
		"credential_unavailable":     {session.StatusFailed, "credential_unavailable"},
		"identity_mismatch":          {session.StatusFailed, "identity_mismatch"},
		"invalid_document":           {session.StatusFailed, "invalid_document"},
		"timestamp_failed":           {session.StatusFailed, "timestamp_failed"},
		"appearance_placement_error": {session.StatusFailed, "appearance_placement_error"},
		"signature_invalid":          {session.StatusFailed, "signature_invalid"},
	}
	seen := map[string]bool{}
	for outcome, want := range cases {
		e, _ := newEngine([]Result{
			redirect("https://cb/oauth2/authorize", "s1"),
			failed(outcome),
		})
		_, _ = e.Begin("c", []byte("%PDF"), "B-B", nil)
		s, _ := e.Store.GetByState("s1")
		st, _, reason, err := e.Complete(s, "code", "s1")
		if err != nil {
			t.Fatalf("%s: %v", outcome, err)
		}
		if st != want.status || reason != want.reason {
			t.Fatalf("%s → %s/%s, want %s/%s", outcome, st, reason, want.status, want.reason)
		}
		key := string(st) + "/" + reason
		if seen[key] {
			t.Fatalf("outcome %s collapses to a non-distinct %s", outcome, key)
		}
		seen[key] = true
	}
}

type errEffector struct{}

func (errEffector) Do(string, string, [][2]string, []byte) (int, []byte, error) {
	return 0, nil, io.ErrUnexpectedEOF
}
func (errEffector) Rewrite(u string) string { return u }

func TestCompleteErrorDeclined(t *testing.T) {
	e, _ := newEngine([]Result{redirect("https://cb/a", "s1"), failed("declined")})
	_, _ = e.Begin("c", []byte("%PDF"), "B-B", nil)
	s, _ := e.Store.GetByState("s1")
	st, _, reason, err := e.CompleteError(s, "access_denied", "s1")
	if err != nil || st != session.StatusDeclined || reason != "declined" {
		t.Fatalf("decline: st=%s reason=%s err=%v", st, reason, err)
	}
	if _, _, _, err := e.CompleteError(s, "x", "s1"); !errors.Is(err, ErrTerminal) {
		t.Fatalf("expected ErrTerminal on terminal CompleteError")
	}
}

func TestUpstreamErrorBecomesFailed(t *testing.T) {
	e := &Engine{
		SDK:   &scriptedSDK{steps: []Result{redirect("https://cb/a", "s1"), performHTTP("https://cb/token")}},
		Up:    errEffector{},
		Store: session.NewMemory(),
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		TTL:   time.Minute,
	}
	_, _ = e.Begin("c", []byte("%PDF"), "B-B", nil)
	s, _ := e.Store.GetByState("s1")
	st, _, reason, err := e.Complete(s, "code", "s1")
	if err != nil || st != session.StatusFailed || reason != "upstream_error" {
		t.Fatalf("upstream error: st=%s reason=%s err=%v", st, reason, err)
	}
}

func TestBeginUnexpectedStepIsError(t *testing.T) {
	e, _ := newEngine([]Result{performHTTP("https://cb/x")})
	if _, err := e.Begin("c", []byte("%PDF"), "B-B", nil); err == nil {
		t.Fatal("begin with a non-redirect first step should error")
	}
}

func TestBeginWithExpectedSignerOption(t *testing.T) {
	e, _ := newEngine([]Result{redirect("https://cb/a", "s1")})
	opts := &Options{ExpectedSignerMatchOn: "certificate_serial_number", ExpectedSignerValue: "PNONL-123"}
	if _, err := e.Begin("c", []byte("%PDF"), "B-B", opts); err != nil {
		t.Fatalf("begin with opts: %v", err)
	}
}

func TestRedactHandlesBadURL(t *testing.T) {
	if got := redact("://bad url"); got == "" {
		t.Fatalf("redact should not return empty, got %q", got)
	}
	if got := redactState("short"); got != "short" {
		t.Fatalf("short state should be unredacted, got %q", got)
	}
}

func TestStepHelpers(t *testing.T) {
	method, url, headers, body := stepHTTP(map[string]any{
		"method": "POST", "url": "u",
		"headers": []any{[]any{"K", "V"}, "bad", []any{"only-one"}},
		"body":    []byte("b"),
	})
	if method != "POST" || url != "u" || len(headers) != 1 || headers[0] != [2]string{"K", "V"} || string(body) != "b" {
		t.Fatalf("stepHTTP: %s %s %v %q", method, url, headers, body)
	}
	if stepEvidence(map[string]any{}) != nil {
		t.Fatal("missing evidence should be nil")
	}
	st, reason := mapFailed(map[string]any{"evidence": map[string]any{}})
	if st != session.StatusFailed || reason != "unknown" {
		t.Fatalf("empty outcome → %s/%s, want failed/unknown", st, reason)
	}
	if redactState("abcdefgh") != "abcdef…" {
		t.Fatalf("long state should be truncated, got %q", redactState("abcdefgh"))
	}
}

func TestResumeErrorsPropagate(t *testing.T) {
	// Begin SDK error (empty script → io.EOF).
	e, _ := newEngine(nil)
	if _, err := e.Begin("c", []byte("%PDF"), "B-B", nil); err == nil {
		t.Fatal("begin SDK error should propagate")
	}
	// Complete resume error (begin redirect, then exhausted).
	e2, _ := newEngine([]Result{redirect("https://cb/a", "s1")})
	_, _ = e2.Begin("c", []byte("%PDF"), "B-B", nil)
	s2, _ := e2.Store.GetByState("s1")
	if _, _, _, err := e2.Complete(s2, "code", "s1"); err == nil {
		t.Fatal("complete resume error should propagate")
	}
	// ResumeHTTP error inside drive (begin redirect, one perform_http, then exhausted).
	e3, _ := newEngine([]Result{redirect("https://cb/a", "s1"), performHTTP("https://cb/t")})
	_, _ = e3.Begin("c", []byte("%PDF"), "B-B", nil)
	s3, _ := e3.Store.GetByState("s1")
	if _, _, _, err := e3.Complete(s3, "code", "s1"); err == nil {
		t.Fatal("resume-http error should propagate")
	}
	// CompleteError resume error.
	e4, _ := newEngine([]Result{redirect("https://cb/a", "s1")})
	_, _ = e4.Begin("c", []byte("%PDF"), "B-B", nil)
	s4, _ := e4.Store.GetByState("s1")
	if _, _, _, err := e4.CompleteError(s4, "x", "s1"); err == nil {
		t.Fatal("complete-error resume error should propagate")
	}
}

func TestCompleteOnTerminalRejected(t *testing.T) {
	e, _ := newEngine([]Result{redirect("https://cb/a", "s1"), failed("invalid_document")})
	_, _ = e.Begin("c", []byte("%PDF"), "B-B", nil)
	s, _ := e.Store.GetByState("s1")
	_, _, _, _ = e.Complete(s, "code", "s1") // → terminal failed
	if _, _, _, err := e.Complete(s, "code", "s1"); !errors.Is(err, ErrTerminal) {
		t.Fatalf("expected ErrTerminal, got %v", err)
	}
}
