package sdk

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/config"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/flow"
)

// TestAdapterBeginAndResumeGlue exercises the cgo adapter: a real begin (which produces the service
// authorization redirect) plus the resume wrappers. The resume results are not asserted — the point
// is to cover the thin glue that converts binding sessions to flow.Result. The full signing flow is
// validated by the credential-free E2E.
func TestAdapterBeginAndResumeGlue(t *testing.T) {
	sample, err := os.ReadFile(filepath.Join("..", "..", "cmd", "refsvc", "sample.pdf"))
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	p := &config.Profile{
		Mode: config.ModeFixtures, Environment: "acceptance", CscAPI: "v1_rsa",
		ClientID: "refsvc-fixtures", ClientSecret: "fixtures", RedirectURI: "http://app/cb",
		UpstreamBaseURL: "http://mock:9000",
	}
	a := New(p)

	res, err := a.Begin(sample, "B-B", nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if res.Step["kind"] != "redirect" {
		t.Fatalf("expected a redirect step, got %v", res.Step["kind"])
	}
	state, ok := res.Step["state"].(string)
	if !ok || state == "" {
		t.Fatalf("redirect step has no usable state, resume paths would not be exercised: %v", res.Step)
	}

	// Begin with the expected-signer option (covers the opts path).
	if _, err := a.Begin(sample, "B-B", &flow.Options{ExpectedSignerMatchOn: "certificate_serial_number", ExpectedSignerValue: "X"}); err != nil {
		t.Fatalf("begin with opts: %v", err)
	}

	garbage := []byte("not-a-handle")

	// ResumeRedirect — success advances to the token effect; a bad handle errors.
	r2, err := a.ResumeRedirect(res.Handle, "svc", state)
	if err != nil {
		t.Fatalf("resume redirect: %v", err)
	}
	if _, err := a.ResumeRedirect(garbage, "x", "y"); err == nil {
		t.Fatal("resume redirect with garbage handle should error")
	}

	// ResumeHTTP — feed the token response (success); a bad handle errors.
	if _, err := a.ResumeHTTP(r2.Handle, 200, []byte(`{"access_token":"bearer","token_type":"Bearer"}`)); err != nil {
		t.Fatalf("resume http: %v", err)
	}
	if _, err := a.ResumeHTTP(garbage, 200, []byte("{}")); err == nil {
		t.Fatal("resume http with garbage handle should error")
	}

	// ResumeRedirectError — a decline on a fresh session (success); a bad handle errors.
	fresh, err := a.Begin(sample, "B-B", nil)
	if err != nil {
		t.Fatalf("fresh begin: %v", err)
	}
	freshState, ok := fresh.Step["state"].(string)
	if !ok || freshState == "" {
		t.Fatalf("fresh redirect step has no usable state: %v", fresh.Step)
	}
	if _, err := a.ResumeRedirectError(fresh.Handle, "access_denied", freshState); err != nil {
		t.Fatalf("resume redirect error: %v", err)
	}
	if _, err := a.ResumeRedirectError(garbage, "x", "y"); err == nil {
		t.Fatal("resume redirect error with garbage handle should error")
	}
}
