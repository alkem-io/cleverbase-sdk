// Package httpapi exposes the reference signing service's REST API (contracts/reference-service-api.md):
// start/complete/status/result + health, behind an optional API-key gate. It holds all secrets and
// the SDK session handle server-side.
package httpapi

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/config"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/flow"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/session"
)

// keyStatus is the JSON field name carrying a session's status in API responses.
const keyStatus = "status"

// Request/document size caps for /v1/sign/start. The endpoint accepts a base64-encoded PDF inside a
// JSON envelope; without a bound, a client could force huge allocations decoding the body.
const (
	// maxPDFBytes caps the decoded document. 20 MiB comfortably covers realistic signable PDFs while
	// bounding per-request memory.
	maxPDFBytes = 20 << 20 // 20 MiB
	// maxStartBodyBytes caps the raw JSON request body read before decoding. The document travels
	// base64-encoded (~4/3 expansion) inside JSON, so the body cap is maxPDFBytes*4/3 plus a small
	// slack for the surrounding JSON fields.
	maxStartBodyBytes = maxPDFBytes*4/3 + (1 << 16) // base64 expansion + 64 KiB JSON slack
	// maxCompleteBodyBytes caps /v1/sign/complete bodies, which carry only short OAuth code/state/error
	// fields — no document — so a small cap suffices and bounds the decode allocation.
	maxCompleteBodyBytes = 1 << 16 // 64 KiB
)

// Service holds the engine + store + profile and serves the REST API.
type Service struct {
	Engine  *flow.Engine
	Store   *session.Memory
	Profile *config.Profile
	// Sample is the bundled PDF used when a start request omits a document.
	Sample []byte
	// Log records server-side errors whose details must not reach the client. Defaults to a
	// discard logger when nil so handlers never panic on a partially-wired Service (tests).
	Log *slog.Logger
}

// log returns the configured logger, or a no-op discard logger when none was wired.
func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Handler returns the routed, auth-wrapped HTTP handler.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sign/start", s.handleStart)
	mux.HandleFunc("POST /v1/sign/complete", s.handleComplete)
	mux.HandleFunc("GET /v1/sign/status", s.handleStatus)
	mux.HandleFunc("GET /v1/sign/result", s.handleResult)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleHealth)
	return s.authMiddleware(mux)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	// Keep ampersands literal in redirect URLs (the default JSON HTML-escaping would mangle them).
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, code int, errCode, msg string) {
	writeJSON(w, code, map[string]string{"error": errCode, "message": msg})
}

// newCorrelationID returns a 128-bit random correlation ID. It propagates a failed RNG read
// instead of silently returning a predictable/zero ID (a degraded RNG must fail the request,
// not hand out a guessable correlation handle).
func newCorrelationID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate correlation id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// expectedSignerInput binds the request to a signer identity (FR-014).
type expectedSignerInput struct {
	MatchOn string `json:"matchOn"`
	Value   string `json:"value"`
}

type startRequest struct {
	Document         string               `json:"document"` // base64 PDF; omit to use the bundled sample
	ConformanceLevel string               `json:"conformanceLevel"`
	ExpectedSigner   *expectedSignerInput `json:"expectedSigner"`
}

func (s *Service) handleStart(w http.ResponseWriter, r *http.Request) {
	// Bound the body before reading it so a client cannot force a huge allocation decoding the JSON
	// (which carries the base64 document). MaxBytesReader trips the decode with an *http.MaxBytesError
	// once the cap is exceeded.
	r.Body = http.MaxBytesReader(w, r.Body, maxStartBodyBytes)
	var req startRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeErr(w, http.StatusRequestEntityTooLarge, "payload_too_large", "request body too large")
			return
		}
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	doc := s.Sample
	if req.Document != "" {
		// The request body is already bounded by MaxBytesReader (maxStartBodyBytes) above, so decoding
		// allocates at most that many bytes — bounded. Decode, then enforce the EXACT decoded-PDF cap
		// (a pre-decode base64 DecodedLen check over-rejects by up to 2 bytes at the boundary).
		b, err := base64.StdEncoding.DecodeString(req.Document)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "document is not valid base64")
			return
		}
		if len(b) > maxPDFBytes {
			writeErr(w, http.StatusRequestEntityTooLarge, "payload_too_large", "document exceeds the size limit")
			return
		}
		doc = b
	}
	if len(doc) == 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "no document and no bundled sample")
		return
	}
	conformance := req.ConformanceLevel
	if conformance == "" {
		conformance = s.Profile.DefaultConformance
	}
	var opts *flow.Options
	if req.ExpectedSigner != nil {
		opts = &flow.Options{
			ExpectedSignerMatchOn: req.ExpectedSigner.MatchOn,
			ExpectedSignerValue:   req.ExpectedSigner.Value,
		}
	}
	corr, err := newCorrelationID()
	if err != nil {
		s.log().Error("correlation id generation failed", "err", err.Error())
		writeErr(w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	redirectURL, err := s.Engine.Begin(corr, doc, conformance, opts)
	if err != nil {
		// Do not surface the upstream/SDK error text to the client (it can leak internal/session
		// detail); log it server-side and return a stable generic message with the same status.
		s.log().Error("begin failed", "correlation_id", corr, "err", err.Error())
		writeErr(w, http.StatusInternalServerError, "begin_failed", "could not start signing session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"redirectUrl": redirectURL, "correlationId": corr})
}

type completeRequest struct {
	Code  string `json:"code"`
	Error string `json:"error"`
	State string `json:"state"`
}

func (s *Service) handleComplete(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxCompleteBodyBytes)
	var req completeRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		writeErr(w, http.StatusRequestEntityTooLarge, "payload_too_large", "request body too large")
		return
	}
	if err != nil || req.State == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid body or missing state")
		return
	}
	sess, err := s.Store.GetByState(req.State)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "unknown_state", "no pending session for that state")
		return
	}
	var (
		status      session.Status
		redirectURL string
		reason      string
	)
	switch {
	case req.Error != "":
		status, redirectURL, reason, err = s.Engine.CompleteError(r.Context(), sess, req.Error, req.State)
	case req.Code != "":
		status, redirectURL, reason, err = s.Engine.Complete(r.Context(), sess, req.Code, req.State)
	default:
		writeErr(w, http.StatusBadRequest, "bad_request", "neither code nor error present")
		return
	}
	if err != nil {
		// A terminal session is already de-indexed by its state, so GetByState (above) returns
		// "unknown_state" for a re-complete; any error here is an internal resume failure. Do not
		// surface the SDK/upstream error text to the client; log it and return a generic message.
		s.log().Error("resume failed", "err", err.Error())
		writeErr(w, http.StatusInternalServerError, "resume_failed", "could not complete signing session")
		return
	}
	resp := map[string]any{keyStatus: string(status)}
	if redirectURL != "" {
		resp["redirectUrl"] = redirectURL
	}
	// Per the API contract, `reason` is present only for a failed status.
	if status == session.StatusFailed && reason != "" {
		resp["reason"] = reason
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Service) handleStatus(w http.ResponseWriter, r *http.Request) {
	corr := r.URL.Query().Get("correlationId")
	v, err := s.Store.ViewByID(corr) // race-free snapshot (the flow engine may be writing concurrently)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "unknown correlation id")
		return
	}
	resp := map[string]any{keyStatus: string(v.Status)}
	// Per the API contract, `reason` is present only for a failed status.
	if v.Status == session.StatusFailed && v.Reason != "" {
		resp["reason"] = v.Reason
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Service) handleResult(w http.ResponseWriter, r *http.Request) {
	corr := r.URL.Query().Get("correlationId")
	v, err := s.Store.ViewByID(corr)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "unknown correlation id")
		return
	}
	if v.Status != session.StatusCompleted {
		writeErr(w, http.StatusConflict, "not_completed", "session is not completed")
		return
	}
	if len(v.Evidence) > 0 {
		w.Header().Set("X-Signature-Evidence", base64.StdEncoding.EncodeToString(v.Evidence))
	}
	w.Header().Set("content-type", "application/pdf")
	w.WriteHeader(http.StatusOK)
	// The body is the SDK-produced signed PDF served as application/pdf (not HTML); no XSS surface.
	_, _ = w.Write(v.ResultPDF)
}

func (*Service) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{keyStatus: "ok"})
}
