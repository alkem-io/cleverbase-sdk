package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/config"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/flow"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/session"
)

// --- test doubles (implement flow.SDK / flow.Effector, cgo-free) ---

type scriptSDK struct {
	steps []flow.Result
	i     int
}

func (s *scriptSDK) next() (flow.Result, error) {
	if s.i >= len(s.steps) {
		return flow.Result{}, io.EOF
	}
	r := s.steps[s.i]
	s.i++
	return r, nil
}
func (s *scriptSDK) Begin([]byte, string, *flow.Options) (flow.Result, error)        { return s.next() }
func (s *scriptSDK) ResumeRedirect([]byte, string, string) (flow.Result, error)      { return s.next() }
func (s *scriptSDK) ResumeRedirectError([]byte, string, string) (flow.Result, error) { return s.next() }
func (s *scriptSDK) ResumeHTTP([]byte, int, []byte) (flow.Result, error)             { return s.next() }

type nopEffector struct{}

func (nopEffector) Do(string, string, [][2]string, []byte) (int, []byte, error) {
	return 200, []byte("{}"), nil
}
func (nopEffector) Rewrite(u string) string { return u }

func redirect(url, state string) flow.Result {
	return flow.Result{Handle: []byte("HANDLE-SECRET"), Step: map[string]any{"kind": "redirect", "url": url, "state": state}}
}
func performHTTP(url string) flow.Result {
	return flow.Result{Handle: []byte("HANDLE-SECRET"), Step: map[string]any{"kind": "perform_http", "method": "POST", "url": url, "headers": []any{}, "body": []byte("{}")}}
}
func done(pdf []byte) flow.Result {
	return flow.Result{Handle: []byte("HANDLE-SECRET"), Step: map[string]any{"kind": "done",
		"signed":   map[string]any{"pdf": pdf},
		"evidence": map[string]any{"outcome": "signed", "request_digest": "abcd"}}}
}

func happySteps() []flow.Result {
	return []flow.Result{
		redirect("https://cb/oauth2/authorize?scope=service", "s1"),
		performHTTP("https://cb/oauth2/token"),
		performHTTP("https://cb/csc/v1/credentials/list"),
		performHTTP("https://cb/csc/v1/credentials/info"),
		redirect("https://cb/oauth2/authorize?scope=credential", "s2"),
		performHTTP("https://cb/oauth2/token"),
		performHTTP("https://cb/csc/v1/signatures/signHash"),
		done([]byte("%PDF-signed")),
	}
}

func newService(steps []flow.Result, auth bool) *Service {
	store := session.NewMemory()
	eng := &flow.Engine{
		SDK:   &scriptSDK{steps: steps},
		Up:    nopEffector{},
		Store: store,
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		TTL:   time.Minute,
	}
	return &Service{
		Engine:  eng,
		Store:   store,
		Profile: &config.Profile{AuthEnabled: auth, APIKey: "test-key", DefaultConformance: "B-B"},
		Sample:  []byte("%PDF-sample"),
	}
}

func do(t *testing.T, h http.Handler, method, target, body, key string) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, r)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAuthRequiredAndHealthOpen(t *testing.T) {
	h := newService(happySteps(), true).Handler()
	if rec := do(t, h, "POST", "/v1/sign/start", "{}", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing key should 401, got %d", rec.Code)
	}
	if rec := do(t, h, "POST", "/v1/sign/start", "{}", "wrong"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key should 401, got %d", rec.Code)
	}
	if rec := do(t, h, "GET", "/healthz", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("health should be open, got %d", rec.Code)
	}
}

func TestFullFlowOverHTTP(t *testing.T) {
	svc := newService(happySteps(), true)
	h := svc.Handler()

	rec := do(t, h, "POST", "/v1/sign/start", `{"conformanceLevel":"B-B"}`, "test-key")
	if rec.Code != http.StatusOK {
		t.Fatalf("start: %d %s", rec.Code, rec.Body)
	}
	var sr map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &sr); err != nil || sr["redirectUrl"] == "" || sr["correlationId"] == "" {
		t.Fatalf("start response: %s (%v)", rec.Body, err)
	}
	corr := sr["correlationId"]
	// First redirect return → drives token/list/info → second redirect.
	rec = do(t, h, "POST", "/v1/sign/complete", `{"code":"c1","state":"s1"}`, "test-key")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"authorizing"`) || !strings.Contains(rec.Body.String(), `"redirectUrl"`) {
		t.Fatalf("first complete: %d %s", rec.Code, rec.Body)
	}
	// Second redirect return → SAD + signHash → completed.
	rec = do(t, h, "POST", "/v1/sign/complete", `{"code":"c2","state":"s2"}`, "test-key")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"completed"`) {
		t.Fatalf("second complete: %d %s", rec.Code, rec.Body)
	}
	// Result fetch returns the signed PDF + evidence header.
	rec = do(t, h, "GET", "/v1/sign/result?correlationId="+corr, "", "test-key")
	if rec.Code != http.StatusOK || rec.Body.String() != "%PDF-signed" {
		t.Fatalf("result: %d %q", rec.Code, rec.Body)
	}
	if rec.Header().Get("X-Signature-Evidence") == "" {
		t.Fatal("missing evidence header")
	}
	// Status reports completed.
	rec = do(t, h, "GET", "/v1/sign/status?correlationId="+corr, "", "test-key")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"completed"`) {
		t.Fatalf("status: %d %s", rec.Code, rec.Body)
	}
}

func TestStartErrors(t *testing.T) {
	h := newService(happySteps(), false).Handler()
	if rec := do(t, h, "POST", "/v1/sign/start", "{not json", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad json should 400, got %d", rec.Code)
	}
	if rec := do(t, h, "POST", "/v1/sign/start", `{"document":"!!!notb64"}`, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad base64 should 400, got %d", rec.Code)
	}
	// No document and no bundled sample.
	svc := newService(happySteps(), false)
	svc.Sample = nil
	if rec := do(t, svc.Handler(), "POST", "/v1/sign/start", `{}`, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty doc+sample should 400, got %d", rec.Code)
	}
}

func TestStartRejectsOversizeBody(t *testing.T) {
	h := newService(happySteps(), false).Handler()

	// 1) A raw JSON body above the MaxBytesReader cap → 413 (trips during decode, before any
	//    document allocation).
	bigBody := `{"document":"` + strings.Repeat("A", maxStartBodyBytes+1) + `"}`
	if rec := do(t, h, "POST", "/v1/sign/start", bigBody, ""); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize body should 413, got %d", rec.Code)
	}

	// 2) A body within the raw cap but whose decoded document exceeds maxPDFBytes → 413. Use valid
	//    base64 (a repeated 'A' is base64 for 0x00 triples) just over the decoded limit.
	overB64Len := base64.StdEncoding.EncodedLen(maxPDFBytes + 3)
	if overB64Len >= maxStartBodyBytes {
		t.Fatalf("test invariant: oversized-document base64 (%d) must fit under the raw body cap (%d)", overB64Len, maxStartBodyBytes)
	}
	overDoc := `{"document":"` + strings.Repeat("A", overB64Len) + `"}`
	if rec := do(t, h, "POST", "/v1/sign/start", overDoc, ""); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize decoded document should 413, got %d", rec.Code)
	}
}

func TestStartDefaultsAndExpectedSigner(t *testing.T) {
	h := newService(happySteps(), false).Handler()
	// Omitted conformanceLevel → profile default; explicit document (base64 of "%PDF").
	body := `{"document":"JVBERg==","expectedSigner":{"matchOn":"certificate_serial_number","value":"PNONL-1"}}`
	if rec := do(t, h, "POST", "/v1/sign/start", body, ""); rec.Code != http.StatusOK {
		t.Fatalf("start with options: %d %s", rec.Code, rec.Body)
	}
}

func TestCompleteErrorDeclinedHTTP(t *testing.T) {
	steps := make([]flow.Result, 0, 2)
	steps = append(steps, redirect("https://cb/a", "s1"))
	steps = append(steps, flow.Result{Handle: []byte("h"), Step: map[string]any{"kind": "failed",
		"evidence": map[string]any{"outcome": "declined"}}})
	h := newService(steps, false).Handler()
	_ = do(t, h, "POST", "/v1/sign/start", `{}`, "")
	rec := do(t, h, "POST", "/v1/sign/complete", `{"error":"access_denied","state":"s1"}`, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"declined"`) {
		t.Fatalf("decline: %d %s", rec.Code, rec.Body)
	}
	// Per the contract, a non-failed status (declined) carries no `reason`.
	if strings.Contains(rec.Body.String(), `"reason"`) {
		t.Fatalf("declined response must not include a reason: %s", rec.Body)
	}
	// A complete with neither code nor error is a 400.
	if rec := do(t, h, "POST", "/v1/sign/complete", `{"state":"s1"}`, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty complete should 400, got %d", rec.Code)
	}
}

func TestResultNotCompleted(t *testing.T) {
	svc := newService([]flow.Result{redirect("https://cb/a", "s1")}, false) // stays authorizing
	h := svc.Handler()
	rec := do(t, h, "POST", "/v1/sign/start", `{}`, "")
	var sr map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &sr)
	if rec := do(t, h, "GET", "/v1/sign/result?correlationId="+sr["correlationId"], "", ""); rec.Code != http.StatusConflict {
		t.Fatalf("result of a non-completed session should 409, got %d", rec.Code)
	}
	if rec := do(t, h, "GET", "/v1/sign/result?correlationId=nope", "", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("result of unknown id should 404, got %d", rec.Code)
	}
}

func TestStartBeginAndResumeErrors(t *testing.T) {
	// Begin error → 500 (empty script).
	if rec := do(t, newService(nil, false).Handler(), "POST", "/v1/sign/start", `{}`, ""); rec.Code != http.StatusInternalServerError {
		t.Fatalf("begin error should 500, got %d", rec.Code)
	}
	// Resume error → 500 (begin redirect, then exhausted script).
	h := newService([]flow.Result{redirect("https://cb/a", "s1")}, false).Handler()
	_ = do(t, h, "POST", "/v1/sign/start", `{}`, "")
	if rec := do(t, h, "POST", "/v1/sign/complete", `{"code":"c","state":"s1"}`, ""); rec.Code != http.StatusInternalServerError {
		t.Fatalf("resume error should 500, got %d", rec.Code)
	}
}

func TestStatusReportsReason(t *testing.T) {
	steps := []flow.Result{redirect("https://cb/a", "s1"),
		{Handle: []byte("h"), Step: map[string]any{"kind": "failed", "evidence": map[string]any{"outcome": "invalid_document"}}}}
	h := newService(steps, false).Handler()
	rec := do(t, h, "POST", "/v1/sign/start", `{}`, "")
	var sr map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &sr)
	cr := do(t, h, "POST", "/v1/sign/complete", `{"code":"c","state":"s1"}`, "")
	if !strings.Contains(cr.Body.String(), `"reason":"invalid_document"`) {
		t.Fatalf("complete should include reason: %s", cr.Body)
	}
	st := do(t, h, "GET", "/v1/sign/status?correlationId="+sr["correlationId"], "", "")
	if !strings.Contains(st.Body.String(), `"invalid_document"`) {
		t.Fatalf("status should include reason: %s", st.Body)
	}
}

func TestStatusAndResultErrors(t *testing.T) {
	h := newService(happySteps(), false).Handler() // auth disabled
	if rec := do(t, h, "GET", "/v1/sign/status?correlationId=nope", "", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown status should 404, got %d", rec.Code)
	}
	if rec := do(t, h, "POST", "/v1/sign/complete", `{"code":"c","state":"nope"}`, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown state should 400, got %d", rec.Code)
	}
}
