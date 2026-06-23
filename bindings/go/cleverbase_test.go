package cleverbase

import (
	"strings"
	"testing"
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
	evidence, _ := sess2.Step["evidence"].(map[string]interface{})
	if evidence["outcome"] != "declined" {
		t.Fatalf("expected declined, got %v", evidence["outcome"])
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
	evidence, _ := sess.Step["evidence"].(map[string]interface{})
	if evidence["outcome"] != "invalid_document" {
		t.Fatalf("expected invalid_document, got %v", evidence["outcome"])
	}
}
