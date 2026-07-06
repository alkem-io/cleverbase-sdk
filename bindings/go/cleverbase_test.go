package cleverbase

import (
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func testEntropy() []byte {
	e := make([]byte, 16)
	for i := range e {
		e[i] = byte(i)
	}
	return e
}

func testConfig() Config {
	return Config{
		Environment:  "acceptance",
		CscAPI:       "v1_rsa",
		ClientID:     "client-123",
		ClientSecret: "secret",
		RedirectURI:  "https://app.example/cb",
	}
}

func TestBeginReturnsServiceRedirect(t *testing.T) {
	sess, err := BeginSigning([]byte("%PDF-1.7\nminimal"), testConfig(), "B-B", nil, 1_700_000_000, testEntropy())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if sess.Step["kind"] != "redirect" {
		t.Fatalf("expected redirect, got %v", sess.Step["kind"])
	}
	url, _ := sess.Step["url"].(string)
	if !strings.Contains(url, "scope=service") {
		t.Fatalf("expected service scope, got %s", url)
	}
}

func TestResumeRedirectEmitsTokenExchange(t *testing.T) {
	sess, err := BeginSigning([]byte("%PDF-1.7\nminimal"), testConfig(), "B-B", nil, 1_700_000_000, testEntropy())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	state, _ := sess.Step["state"].(string)
	if state == "" {
		t.Fatal("missing state")
	}
	sess2, err := ResumeRedirect(sess.Handle, "code-xyz", state, 1_700_000_000, testEntropy())
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if sess2.Step["kind"] != "perform_http" {
		t.Fatalf("expected perform_http, got %v", sess2.Step["kind"])
	}
	url, _ := sess2.Step["url"].(string)
	if !strings.HasSuffix(url, "/oauth2/token") {
		t.Fatalf("expected token endpoint, got %s", url)
	}
}

func TestBeginWithRequestOptions(t *testing.T) {
	opts := &RequestOptions{
		ExpectedSigner: &ExpectedSigner{MatchOn: "certificate_serial_number", Value: "PNONL-123"},
		Appearance: &Appearance{
			Page: 1,
			Rect: Rect{X: 50, Y: 50, W: 200, H: 80},
			Show: AppearanceShow{SignerName: true, SigningTime: true},
		},
		SignatureMeta: &SignatureMeta{Reason: "Approval", Location: "NL"},
	}
	// Confirms the option structs serialize to the shape the core expects (a wrong CBOR shape would
	// fail to deserialize and return an error here).
	sess, err := BeginSigning([]byte("%PDF-1.7\nminimal"), testConfig(), "B-B", opts, 1_700_000_000, testEntropy())
	if err != nil {
		t.Fatalf("begin with options: %v", err)
	}
	if sess.Step["kind"] != "redirect" {
		t.Fatalf("expected redirect, got %v", sess.Step["kind"])
	}
}

func TestExpectedSignerDefaultMatchOn(t *testing.T) {
	// Setting only Value (MatchOn empty) must use the core default, not send match_on:"" (which the
	// core would reject) — confirms the omitempty tag works end-to-end.
	opts := &RequestOptions{ExpectedSigner: &ExpectedSigner{Value: "PNONL-123"}}
	sess, err := BeginSigning([]byte("%PDF-1.7\nminimal"), testConfig(), "B-B", opts, 1_700_000_000, testEntropy())
	if err != nil {
		t.Fatalf("begin with default match_on: %v", err)
	}
	if sess.Step["kind"] != "redirect" {
		t.Fatalf("expected redirect, got %v", sess.Step["kind"])
	}
}

func TestResumeRedirectErrorYieldsDeclined(t *testing.T) {
	sess, err := BeginSigning([]byte("%PDF-1.7\nminimal"), testConfig(), "B-B", nil, 1_700_000_000, testEntropy())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	state, _ := sess.Step["state"].(string)
	sess2, err := ResumeRedirectError(sess.Handle, "access_denied", state, 1_700_000_000, testEntropy())
	if err != nil {
		t.Fatalf("resume error: %v", err)
	}
	if sess2.Step["kind"] != "failed" {
		t.Fatalf("expected failed, got %v", sess2.Step["kind"])
	}
	evidence, _ := sess2.Step["evidence"].(map[string]any)
	if evidence["outcome"] != "declined" {
		t.Fatalf("expected declined, got %v", evidence["outcome"])
	}
}

func TestResumeHTTPAdvancesFlow(t *testing.T) {
	sess, err := BeginSigning([]byte("%PDF-1.7\nminimal"), testConfig(), "B-B", nil, 1_700_000_000, testEntropy())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	state, _ := sess.Step["state"].(string)
	sess2, err := ResumeRedirect(sess.Handle, "code", state, 1_700_000_000, testEntropy())
	if err != nil {
		t.Fatalf("resume redirect: %v", err)
	}
	if sess2.Step["kind"] != "perform_http" {
		t.Fatalf("expected token-exchange perform_http, got %v", sess2.Step["kind"])
	}
	// Feed the token-exchange HTTP response; the flow advances to the next perform_http (list).
	body := []byte(`{"access_token":"bearer","token_type":"Bearer"}`)
	sess3, err := ResumeHTTP(sess2.Handle, 200, body, 1_700_000_000, testEntropy())
	if err != nil {
		t.Fatalf("resume http: %v", err)
	}
	if sess3.Step["kind"] != "perform_http" {
		t.Fatalf("expected credentials/list perform_http, got %v", sess3.Step["kind"])
	}
}

func TestBeginWithTsaConfigEmitsRedirect(t *testing.T) {
	// A B-T request needs a TSA configured. Setting TsaURL, TsaAuth, and TsaPolicy exercises the
	// whole `if cfg.TsaURL != ""` block (including the nested auth / policy_oid appends) in
	// BeginSigning; the core accepts the shape and returns the service-auth redirect Step. A wrong
	// CBOR spelling for any TSA field would fail to deserialize and surface as an error here.
	cfg := testConfig()
	cfg.TsaURL = "https://tsa.example/rfc3161"
	cfg.TsaAuth = "Bearer tsa-token"
	cfg.TsaPolicy = "1.3.6.1.4.1.601.10.3.1"
	sess, err := BeginSigning([]byte("%PDF-1.7\nminimal"), cfg, "B-T", nil, 1_700_000_000, testEntropy())
	if err != nil {
		t.Fatalf("begin with TSA config: %v", err)
	}
	if sess.Step["kind"] != "redirect" {
		t.Fatalf("expected redirect, got %v", sess.Step["kind"])
	}
	url, _ := sess.Step["url"].(string)
	if !strings.Contains(url, "scope=service") {
		t.Fatalf("expected service scope, got %s", url)
	}
}

func TestBeginBTWithoutTsaReturnsError(t *testing.T) {
	// A B-T request with no TSA configured makes the core return MissingTsaConfig → WireResult::Err,
	// which dispatch surfaces as a Go error (the resp.Result.Err != nil arm).
	sess, err := BeginSigning([]byte("%PDF-1.7\nminimal"), testConfig(), "B-T", nil, 1_700_000_000, testEntropy())
	if err == nil {
		t.Fatalf("expected an error for B-T without a TSA, got session %+v", sess)
	}
}

func TestBeginWithBadConfigReturnsError(t *testing.T) {
	// An empty client_id makes the core return InvalidConfig → WireResult::Err → a Go error.
	cfg := testConfig()
	cfg.ClientID = ""
	_, err := BeginSigning([]byte("%PDF-1.7\nminimal"), cfg, "B-B", nil, 1_700_000_000, testEntropy())
	if err == nil {
		t.Fatal("expected an error for empty client_id")
	}
}

func TestProcessRejectsEmptyInput(t *testing.T) {
	if _, err := process(nil); err == nil {
		t.Fatal("expected an error for empty input")
	}
}

func TestInvalidDocumentFails(t *testing.T) {
	sess, err := BeginSigning([]byte("not a pdf"), testConfig(), "B-B", nil, 1_700_000_000, testEntropy())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if sess.Step["kind"] != "failed" {
		t.Fatalf("expected failed, got %v", sess.Step["kind"])
	}
	evidence, _ := sess.Step["evidence"].(map[string]any)
	if evidence["outcome"] != "invalid_document" {
		t.Fatalf("expected invalid_document, got %v", evidence["outcome"])
	}
}

// ---- EUDI attestation surface (CBOR-in / CBOR-out) ----------------------------------------------

// attestationVerifyResponse decodes a VerifyResponse envelope (attestation schema version 5). The
// externally-tagged `outcome` is `{ok:{result:{...}}}` for a completed verification (any verdict) or
// `{err:{message}}` for a malformed request.
type attestationVerifyResponse struct {
	SchemaVersion int `cbor:"schema_version"`
	Outcome       struct {
		Ok *struct {
			Result struct {
				Valid bool `cbor:"valid"`
			} `cbor:"result"`
		} `cbor:"ok"`
		Err *struct {
			Message string `cbor:"message"`
		} `cbor:"err"`
	} `cbor:"outcome"`
}

func TestAttestationVerifyRoundTripReachesTheVerifier(t *testing.T) {
	// A well-formed VerifyRequest with a bogus SD-JWT presentation and NO trust anchors: the verifier
	// runs and returns an INVALID VerificationResult (Ok outcome) — proving the full FFI round-trip
	// (marshal in → verifier → marshal out), not merely a malformed-envelope reject.
	req := map[string]any{
		"schema_version": 5,
		"presentation":   map[string]any{"sd_jwt_vc": map[string]any{"presentation": "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJ4In0.AAAA~"}},
		"policy":         map[string]any{"formats": []any{}, "qualified_gate": false, "status_reachability": "fail_closed"},
		"anchors":        []any{},
		"context":        map[string]any{"now_unix": 0, "role": "pid", "statuses": []any{"no_status"}},
	}
	in, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	out, err := AttestationVerify(in)
	if err != nil {
		t.Fatalf("AttestationVerify FFI error: %v", err)
	}
	var resp attestationVerifyResponse
	if err := decMode().Unmarshal(out, &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.SchemaVersion != 5 {
		t.Fatalf("schema_version = %d, want 5", resp.SchemaVersion)
	}
	if (resp.Outcome.Ok == nil) == (resp.Outcome.Err == nil) {
		t.Fatal("exactly one of ok/err must be present")
	}
	if resp.Outcome.Ok == nil {
		t.Fatalf("a well-formed request must produce an ok outcome, got err: %v", resp.Outcome.Err)
	}
	if resp.Outcome.Ok.Result.Valid {
		t.Fatal("a bogus presentation with no trust anchors must verify INVALID")
	}
}

func TestAttestationVerifyMalformedRequestIsErr(t *testing.T) {
	// A well-formed CBOR value that is not a VerifyRequest map fails the envelope decode → an `err`
	// outcome (never a status code — the schema version is still surfaced).
	in, err := cbor.Marshal(0)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err := AttestationVerify(in)
	if err != nil {
		t.Fatalf("AttestationVerify FFI error: %v", err)
	}
	var resp attestationVerifyResponse
	if err := decMode().Unmarshal(out, &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.SchemaVersion != 5 {
		t.Fatalf("schema_version = %d, want 5", resp.SchemaVersion)
	}
	if resp.Outcome.Err == nil {
		t.Fatal("a malformed VerifyRequest must yield an err outcome")
	}
}

func TestAttestationIssuanceMalformedRequestIsErr(t *testing.T) {
	// A malformed IssuanceRequest fails closed to an `err` outcome under the issuance schema version 1,
	// proving the issuance round-trip is wired.
	out, err := AttestationIssuance([]byte{0xff, 0x00})
	if err != nil {
		t.Fatalf("AttestationIssuance FFI error: %v", err)
	}
	var resp struct {
		SchemaVersion int `cbor:"schema_version"`
		Outcome       struct {
			Err *struct {
				Message string `cbor:"message"`
			} `cbor:"err"`
		} `cbor:"outcome"`
	}
	if err := decMode().Unmarshal(out, &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.SchemaVersion != 1 {
		t.Fatalf("schema_version = %d, want 1", resp.SchemaVersion)
	}
	if resp.Outcome.Err == nil {
		t.Fatal("a malformed IssuanceRequest must yield an err outcome")
	}
}
