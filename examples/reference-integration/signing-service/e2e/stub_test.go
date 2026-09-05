package e2e

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/config"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/flow"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/upstream"
)

const (
	stubSignerSerial = "694FE11553653A72D0DB75D9F08A63B2"
	stubSignerCN     = "WILLEKE LISELOTTE DE BRUIJN"

	stubChecklistStart = "<!-- hash-signing-stub-checklist:start -->"
	stubChecklistEnd   = "<!-- hash-signing-stub-checklist:end -->"
)

// stubContractChecklist is the sole list of claims made about the public Cleverbase hash-signing
// stub. TestProofMatrixHashStubChecklistInSync pins the rendered proof-matrix rows to these IDs, so
// the documentation cannot claim coverage that this suite does not name.
var stubContractChecklist = []struct {
	id       string
	endpoint string
}{
	{"authorize-service", "/oauth2/authorize"},
	{"authorize-credential", "/oauth2/authorize"},
	{"token-service", "/oauth2/token"},
	{"credentials-list", "/csc/v1/credentials/list"},
	{"credentials-info", "/csc/v1/credentials/info"},
	{"token-credential-sad", "/oauth2/token"},
	{"sign-hash", "/csc/v1/signatures/signHash"},
	{"token-wrong-client", "/oauth2/token"},
	{"info-missing-credential", "/csc/v1/credentials/info"},
	{"sign-hash-wrong-algorithm", "/csc/v1/signatures/signHash"},
	{"sign-hash-invalid-sad", "/csc/v1/signatures/signHash"},
	{"sign-hash-empty-credential-limitation", "/csc/v1/signatures/signHash"},
	{"sign-hash-malformed-hash-limitation", "/csc/v1/signatures/signHash"},
	{"sign-hash-short-hash-limitation", "/csc/v1/signatures/signHash"},
	{"oauth-auth-not-used", "/oauth2/auth"},
	{"oauth-revoke-not-used", "/oauth2/revoke"},
	{"csc-info-not-used", "/csc/v1/info"},
	{"csc-auth-revoke-not-used", "/csc/v1/auth/revoke"},
	{"ecdsa-v2-not-exposed", "not exposed by hash-signing stub"},
}

// recordedEffect is a complete in-memory record of one SDK-emitted HTTP effect and the stub's
// answer. It is test-only and never logs tokens, authorization codes, SADs, or signatures.
type recordedEffect struct {
	method   string
	url      string
	headers  [][2]string
	body     []byte
	status   int
	response []byte
}

// recordingEffector observes the real HTTP client rather than duplicating the SDK's protocol
// requests in the test. The exact effect sequence remains the sole source for request assertions.
type recordingEffector struct {
	next  flow.Effector
	mu    sync.Mutex
	calls []recordedEffect
}

func (r *recordingEffector) Do(ctx context.Context, method, rawURL string, headers [][2]string, body []byte) (int, []byte, error) {
	status, response, err := r.next.Do(ctx, method, rawURL, headers, body)
	r.mu.Lock()
	r.calls = append(r.calls, recordedEffect{
		method: method, url: rawURL, headers: append([][2]string(nil), headers...),
		body: append([]byte(nil), body...), status: status, response: append([]byte(nil), response...),
	})
	r.mu.Unlock()
	return status, response, err
}

func (r *recordingEffector) snapshot() []recordedEffect {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recordedEffect(nil), r.calls...)
}

type recordedAuthorization struct {
	query  url.Values
	status int
}

// stubAuthorizer follows Cleverbase's documented immediate authorization redirect. It shares the
// same Authorizer seam and start/complete driver as mock and human-backed runs; only approval is
// different, which is inherent to the public headless stub contract.
type stubAuthorizer struct {
	mu    sync.Mutex
	calls []recordedAuthorization
}

func (a *stubAuthorizer) Authorize(ctx context.Context, authorizeURL, expectState string) (code, state string, err error) {
	u, err := url.Parse(authorizeURL)
	if err != nil {
		return "", "", errors.New("parse stub authorize URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authorizeURL, nil)
	if err != nil {
		return "", "", fmt.Errorf("build stub authorize request: %w", err)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("stub authorize GET: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		return "", "", fmt.Errorf("stub authorize status %d, want 302", resp.StatusCode)
	}
	code, state, err = codeStateFromLocation(resp.Header.Get("Location"))
	if err != nil {
		return "", "", err
	}
	if state != expectState {
		return "", "", errors.New("stub callback state did not match SDK state")
	}
	a.mu.Lock()
	a.calls = append(a.calls, recordedAuthorization{query: u.Query(), status: resp.StatusCode})
	a.mu.Unlock()
	return code, state, nil
}

func (a *stubAuthorizer) snapshot() []recordedAuthorization {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]recordedAuthorization(nil), a.calls...)
}

type stubEvidence struct {
	signerPresent bool
	outcome       string
	serialNumber  string
	rawSubject    string
}

type stubEvidenceWire struct {
	Outcome string                  `json:"outcome"`
	Signer  *stubEvidenceSignerWire `json:"signer"`
}

type stubEvidenceSignerWire struct {
	SerialNumber string `json:"serial_number"`
	RawSubject   string `json:"raw_subject"`
}

type stubCredentialInfoWire struct {
	Key       stubKeyWire  `json:"key"`
	Cert      stubCertWire `json:"cert"`
	AuthMode  string       `json:"authMode"`
	SCAL      string       `json:"SCAL"`
	Multisign int          `json:"multisign"`
}

type stubKeyWire struct {
	Algo []string `json:"algo"`
	Len  int      `json:"len"`
}

type stubCertWire struct {
	Certificates []string `json:"certificates"`
}

type stubFlowResult struct {
	status   string
	reason   string
	evidence stubEvidence
	access   stubAccess
}

// stubAccess is extracted only from the in-memory responses to the SDK's own successful effects.
// It lets the negative probes exercise the stub's documented error models without inventing a
// second OAuth/CSC happy-path client or logging bearer/SAD values.
type stubAccess struct {
	serviceToken string
	credentialID string
	sad          string
}

func TestLoadStubEnvRequiresExplicitConfiguration(t *testing.T) {
	// The public stub client is intentionally supplied by CI instead of becoming an implicit
	// network dependency of every local `go test ./...` invocation.
	for _, key := range []string{
		"REFSVC_CLIENT_ID",
		"REFSVC_CLIENT_SECRET",
		"REFSVC_REDIRECT_URI",
		"REFSVC_UPSTREAM_BASE_URL",
	} {
		t.Setenv(key, "")
	}
	if _, ok := loadStubEnv(); ok {
		t.Fatal("stub contract path must skip unless its explicit configuration is present")
	}

	t.Setenv("REFSVC_CLIENT_ID", "public-stub-client")
	t.Setenv("REFSVC_CLIENT_SECRET", "public-stub-credential")
	t.Setenv("REFSVC_REDIRECT_URI", "http://localhost:8080/oauth/cleverbase/callback")
	t.Setenv("REFSVC_UPSTREAM_BASE_URL", "https://trust-driver-stub-hash-signing.cleverbase.com")
	if _, ok := loadStubEnv(); !ok {
		t.Fatal("fully configured stub contract path should be enabled")
	}
}

func TestProofMatrixHashStubChecklistInSync(t *testing.T) {
	proofMatrix := filepath.Join(filepath.Dir(filepath.Dir(repoFixtures(t))), "docs", "proof-matrix.md")
	contents, err := os.ReadFile(proofMatrix)
	if err != nil {
		t.Fatalf("read proof matrix: %v", err)
	}
	start := strings.Index(string(contents), stubChecklistStart)
	end := strings.Index(string(contents), stubChecklistEnd)
	if start < 0 || end < 0 || end <= start {
		t.Fatalf("proof matrix must contain %s … %s", stubChecklistStart, stubChecklistEnd)
	}
	checklist := string(contents)[start+len(stubChecklistStart) : end]
	for _, item := range stubContractChecklist {
		row := "| `" + item.id + "` | `" + item.endpoint + "` |"
		if !strings.Contains(checklist, row) {
			t.Fatalf("proof matrix is missing stub checklist row %q", item.id)
		}
	}
	for _, row := range strings.Split(checklist, "\n") {
		if !strings.HasPrefix(row, "| `") {
			continue
		}
		id := strings.Split(strings.TrimPrefix(row, "| `"), "`")[0]
		found := false
		for _, item := range stubContractChecklist {
			found = found || item.id == id
		}
		if !found {
			t.Fatalf("proof matrix has undocumented stub checklist row %q", id)
		}
	}
}

func TestCleverbaseHashSigningStub(t *testing.T) {
	e, ok := loadStubEnv()
	if !ok {
		t.Skip("Cleverbase hash-signing stub requires REFSVC_CLIENT_ID, REFSVC_CLIENT_SECRET, REFSVC_REDIRECT_URI, and REFSVC_UPSTREAM_BASE_URL")
	}
	if e.cscAPI != "v1_rsa" {
		t.Fatalf("hash-signing stub exposes CSC v1 RSA only, got REFSVC_CSC_API=%q", e.cscAPI)
	}

	for _, level := range []string{config.ConformanceBB, config.ConformanceBT} {
		t.Run(level, func(t *testing.T) {
			result := runStubContract(t, e, level)
			if result.status != "failed" || result.reason != "signature_invalid" {
				t.Fatalf("stub %s terminal status=%s reason=%s, want failed/signature_invalid", level, result.status, result.reason)
			}
			if result.evidence.outcome != "signature_invalid" {
				t.Fatalf("stub %s evidence outcome=%q, want signature_invalid", level, result.evidence.outcome)
			}
			if result.evidence.signerPresent && (result.evidence.serialNumber != stubSignerSerial || result.evidence.rawSubject == "") {
				t.Fatalf("stub %s evidence identity=%+v, want canonical serial and raw subject", level, result.evidence)
			}
			if !result.evidence.signerPresent {
				t.Log("stub failure evidence does not expose signer identity; recorded as a contract limitation")
			}
			if level == config.ConformanceBB {
				assertStubModeledFailures(t, e, result.access)
			}
		})
	}
}

// runStubContract drives the exact public service flow through Cleverbase's headless signing
// stub. A stub response is deliberately not cryptographically valid, so the core must terminate at
// SignatureInvalid after accepting signHash; it must never embed or return that fake signature.
func runStubContract(t *testing.T, e liveEnv, level string) stubFlowResult {
	t.Helper()
	// B-T needs a configured TSA to begin. The core rejects the fake signature before a timestamp
	// request can exist, so this endpoint is intentionally never contacted; a real/stub TSA is not
	// implied by Cleverbase's signing stub.
	e.tsaURL = "https://tsa.invalid/rfc3161"
	effector := &recordingEffector{next: upstream.New("")}
	svc, store := buildLiveServiceWithEffector(t, e, level, effector)
	authorizer := &stubAuthorizer{}
	run := driveFlow(t, authorizer, svc, `{"conformanceLevel":"`+level+`","expectedSigner":{"matchOn":"certificate_serial_number","value":"`+stubSignerSerial+`"}}`)
	if run.correlationID == "" {
		t.Fatal("stub flow returned no correlation id")
	}

	view, err := store.ViewByID(run.correlationID)
	if err != nil {
		t.Fatalf("read stub session evidence: %v", err)
	}
	evidence := parseStubEvidence(t, view.Evidence)
	access := assertStubEffects(t, effector.snapshot(), e)
	assertStubAuthorizations(t, authorizer.snapshot(), e)
	return stubFlowResult{status: run.status, reason: run.reason, evidence: evidence, access: access}
}

func parseStubEvidence(t *testing.T, raw []byte) stubEvidence {
	t.Helper()
	var wire stubEvidenceWire
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("decode stub failure evidence: %v", err)
	}
	if wire.Signer == nil {
		return stubEvidence{outcome: wire.Outcome}
	}
	return stubEvidence{
		signerPresent: true,
		outcome:       wire.Outcome,
		serialNumber:  wire.Signer.SerialNumber,
		rawSubject:    wire.Signer.RawSubject,
	}
}

func assertStubAuthorizations(t *testing.T, calls []recordedAuthorization, e liveEnv) {
	t.Helper()
	if len(calls) != 2 {
		t.Fatalf("stub authorize calls=%d, want service + credential", len(calls))
	}
	for index, call := range calls {
		if call.status != http.StatusFound {
			t.Fatalf("authorize %d status=%d, want 302", index, call.status)
		}
		for key, want := range map[string]string{
			"response_type": "code",
			"client_id":     e.clientID,
			"redirect_uri":  e.redirectURI,
		} {
			if got := call.query.Get(key); got != want {
				t.Fatalf("authorize %d %s=%q, want configured value", index, key, got)
			}
		}
		if call.query.Get("state") == "" {
			t.Fatalf("authorize %d omitted CSRF state", index)
		}
	}
	if got := calls[0].query.Get("scope"); got != "service" {
		t.Fatalf("service authorize scope=%q, want service", got)
	}
	for _, unexpected := range []string{"credentialID", "numSignatures", "hash"} {
		if got := calls[0].query.Get(unexpected); got != "" {
			t.Fatalf("service authorize unexpectedly carried %s", unexpected)
		}
	}
	if got := calls[1].query.Get("scope"); got != "credential" {
		t.Fatalf("credential authorize scope=%q, want credential", got)
	}
	if calls[1].query.Get("credentialID") == "" {
		t.Fatal("credential authorize omitted credentialID")
	}
	if got := calls[1].query.Get("numSignatures"); got != "1" {
		t.Fatalf("credential authorize numSignatures=%q, want 1", got)
	}
	hash, err := base64.RawURLEncoding.DecodeString(calls[1].query.Get("hash"))
	if err != nil || len(hash) != 32 {
		t.Fatalf("credential authorize hash is not a SHA-256 base64url value (len=%d err=%v)", len(hash), err)
	}
}

func assertStubEffects(t *testing.T, calls []recordedEffect, e liveEnv) stubAccess {
	t.Helper()
	if len(calls) != 5 {
		for index, call := range calls {
			u, err := url.Parse(call.url)
			if err != nil {
				t.Logf("stub effect %d: malformed URL (%v), status=%d", index, err, call.status)
				continue
			}
			t.Logf("stub effect %d: %s %s status=%d", index, call.method, u.Path, call.status)
			if u.Path == "/oauth2/token" {
				form, parseErr := url.ParseQuery(string(call.body))
				if parseErr != nil {
					t.Logf("stub token effect %d: malformed form (%v)", index, parseErr)
					continue
				}
				t.Logf("stub token effect %d: client_id configured=%t length=%d redirect_uri configured=%t code present=%t", index,
					form.Get("client_id") == e.clientID, len(form.Get("client_id")), form.Get("redirect_uri") == e.redirectURI, form.Get("code") != "")
			}
		}
		t.Fatalf("stub HTTP effects=%d, want token/list/info/token/signHash", len(calls))
	}
	serviceToken := assertStubTokenEffect(t, calls[0], e, "Bearer")
	credentialID := assertStubCredentialList(t, calls[1])
	assertStubCredentialInfo(t, calls[2], credentialID)
	sad := assertStubTokenEffect(t, calls[3], e, "SAD")
	assertStubSignHash(t, calls[4], credentialID)
	return stubAccess{serviceToken: serviceToken, credentialID: credentialID, sad: sad}
}

func assertStubURL(t *testing.T, call recordedEffect, wantPath string) {
	t.Helper()
	u, err := url.Parse(call.url)
	if err != nil {
		t.Fatalf("parse emitted %s URL: %v", wantPath, err)
	}
	if call.method != http.MethodPost || u.Path != wantPath {
		t.Fatalf("effect=%s %s, want POST %s", call.method, u.Path, wantPath)
	}
}

func headerValue(headers [][2]string, name string) string {
	for _, header := range headers {
		if strings.EqualFold(header[0], name) {
			return header[1]
		}
	}
	return ""
}

func assertStubTokenEffect(t *testing.T, call recordedEffect, e liveEnv, wantTokenType string) string {
	t.Helper()
	assertStubURL(t, call, "/oauth2/token")
	if call.status != http.StatusOK {
		t.Fatalf("token status=%d, want 200", call.status)
	}
	if got := headerValue(call.headers, "Content-Type"); got != "application/x-www-form-urlencoded" {
		t.Fatalf("token Content-Type=%q", got)
	}
	basic, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(headerValue(call.headers, "Authorization"), "Basic "))
	if err != nil || string(basic) != e.clientID+":"+e.clientSecret {
		t.Fatal("token request did not use the configured HTTP Basic client authentication")
	}
	form, err := url.ParseQuery(string(call.body))
	if err != nil {
		t.Fatalf("parse token form: %v", err)
	}
	if form.Get("grant_type") != "authorization_code" || form.Get("code") == "" || form.Get("redirect_uri") != e.redirectURI {
		t.Fatal("token request did not carry grant_type, authorization code, and redirect URI")
	}
	if form.Get("client_id") != e.clientID {
		t.Fatal("token request omitted the configured client_id required by Cleverbase's token contract")
	}
	var response struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(call.response, &response); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if response.AccessToken == "" || response.TokenType != wantTokenType || response.ExpiresIn <= 0 {
		t.Fatalf("token response does not contain the expected %s token shape", wantTokenType)
	}
	return response.AccessToken
}

func assertStubCredentialList(t *testing.T, call recordedEffect) string {
	t.Helper()
	assertStubURL(t, call, "/csc/v1/credentials/list")
	if call.status != http.StatusOK || !strings.HasPrefix(headerValue(call.headers, "Authorization"), "Bearer ") {
		t.Fatal("credentials/list must use a successful bearer-authenticated request")
	}
	var request map[string]any
	if err := json.Unmarshal(call.body, &request); err != nil || len(request) != 0 {
		t.Fatalf("credentials/list request=%s, want {}", call.body)
	}
	var response struct {
		CredentialIDs []string `json:"credentialIDs"`
	}
	if err := json.Unmarshal(call.response, &response); err != nil || len(response.CredentialIDs) == 0 {
		t.Fatal("credentials/list response has no credentialID")
	}
	return response.CredentialIDs[0]
}

func assertStubCredentialInfo(t *testing.T, call recordedEffect, credentialID string) {
	t.Helper()
	assertStubURL(t, call, "/csc/v1/credentials/info")
	if call.status != http.StatusOK || !strings.HasPrefix(headerValue(call.headers, "Authorization"), "Bearer ") {
		t.Fatal("credentials/info must use a successful bearer-authenticated request")
	}
	var request struct {
		CredentialID string `json:"credentialID"`
		Certificates string `json:"certificates"`
		CertInfo     bool   `json:"certInfo"`
	}
	if err := json.Unmarshal(call.body, &request); err != nil {
		t.Fatalf("decode credentials/info request: %v", err)
	}
	if request.CredentialID != credentialID || request.Certificates != "chain" || !request.CertInfo {
		t.Fatal("credentials/info request did not request the selected certificate chain and info")
	}
	var response stubCredentialInfoWire
	if err := json.Unmarshal(call.response, &response); err != nil {
		t.Fatalf("decode credentials/info response: %v", err)
	}
	if response.SCAL != "2" || response.Key.Len != 2048 || !contains(response.Key.Algo, "1.2.840.113549.1.1.1") {
		t.Fatal("credentials/info does not advertise the expected SCAL2 RSA-2048 credential")
	}
	if response.AuthMode != "oauth2code" || response.Multisign != 1 || len(response.Cert.Certificates) == 0 {
		t.Fatalf("credentials/info shape authMode=%q multisign=%d chain length=%d, want oauth2code/1/non-empty", response.AuthMode, response.Multisign, len(response.Cert.Certificates))
	}
	leafDER, err := base64.StdEncoding.DecodeString(response.Cert.Certificates[0])
	if err != nil {
		t.Fatalf("decode leaf certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}
	if got := strings.ToUpper(leaf.SerialNumber.Text(16)); got != stubSignerSerial || leaf.Subject.CommonName != stubSignerCN {
		t.Fatalf("stub leaf identity serial=%q CN=%q, want documented TEST identity", got, leaf.Subject.CommonName)
	}
}

func assertStubSignHash(t *testing.T, call recordedEffect, credentialID string) {
	t.Helper()
	assertStubURL(t, call, "/csc/v1/signatures/signHash")
	if call.status != http.StatusOK || !strings.HasPrefix(headerValue(call.headers, "Authorization"), "Bearer ") {
		t.Fatal("signHash must use a successful bearer-authenticated request")
	}
	var request struct {
		CredentialID string   `json:"credentialID"`
		SAD          string   `json:"SAD"`
		Hash         []string `json:"hash"`
		HashAlgo     string   `json:"hashAlgo"`
		SignAlgo     string   `json:"signAlgo"`
	}
	if err := json.Unmarshal(call.body, &request); err != nil {
		t.Fatalf("decode signHash request: %v", err)
	}
	if request.CredentialID != credentialID || request.SAD == "" || request.HashAlgo != "2.16.840.1.101.3.4.2.1" || request.SignAlgo != "1.2.840.113549.1.1.1" || len(request.Hash) != 1 {
		t.Fatal("signHash request did not carry the documented RSA/SHA-256 CSC fields")
	}
	hash, err := base64.StdEncoding.DecodeString(request.Hash[0])
	if err != nil || len(hash) != 32 {
		t.Fatalf("signHash hash is not one SHA-256 base64 value (len=%d err=%v)", len(hash), err)
	}
	var response struct {
		Signatures []string `json:"signatures"`
	}
	if err := json.Unmarshal(call.response, &response); err != nil || len(response.Signatures) != 1 {
		t.Fatal("stub signHash response has no signature value")
	}
}

// assertStubModeledFailures probes the error cases the published hash-signing stub models. The SDK
// never intentionally emits malformed requests, so these probes necessarily sit at the contract
// boundary; they reuse the successful driver-issued bearer, credential ID, and SAD above rather than
// grow a second happy-path OAuth/CSC client. No credential value is logged.
func assertStubModeledFailures(t *testing.T, e liveEnv, access stubAccess) {
	t.Helper()
	if access.serviceToken == "" || access.credentialID == "" || access.sad == "" {
		t.Fatal("successful stub flow did not supply tokens and credential ID for error probes")
	}

	// The token endpoint must reject bad HTTP Basic credentials. A fresh immediate-redirect code keeps
	// this probe about client authentication rather than replaying an already-consumed authorization
	// code.
	authorizer := &stubAuthorizer{}
	state := "stub-wrong-client-credentials"
	code, _, err := authorizer.Authorize(context.Background(), stubAuthorizeURL(t, e, "service", state), state)
	if err != nil {
		t.Fatalf("obtain code for wrong-client-credentials probe: %v", err)
	}
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"client_id":    {e.clientID},
		"redirect_uri": {e.redirectURI},
	}.Encode()
	status, _, err := upstream.New("").Do(context.Background(), http.MethodPost, stubURL(t, e, "/oauth2/token"), [][2]string{
		{"Content-Type", "application/x-www-form-urlencoded"},
		{"Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte(e.clientID+":wrong-client-secret"))},
	}, []byte(form))
	if err != nil {
		t.Fatalf("wrong-client-credentials token probe: %v", err)
	}
	if status < http.StatusBadRequest || status >= http.StatusInternalServerError {
		t.Fatalf("wrong client credentials token status=%d, want 4xx", status)
	}

	// Each remaining case is an explicit 400 in the stub's OpenAPI. These are protocol-inherent bad
	// inputs, not SDK branches to add: the real flow above already proves the only valid request shape.
	expectBadRequest(t, "credentials/info missing credentialID", stubPostJSON(t, e, "/csc/v1/credentials/info", access.serviceToken, map[string]any{
		"certificates": "chain", "certInfo": true,
	}))

	validHash := base64.StdEncoding.EncodeToString(make([]byte, 32))
	baseSignHash := map[string]any{
		"credentialID": access.credentialID,
		"SAD":          access.sad,
		"hash":         []string{validHash},
		"hashAlgo":     "2.16.840.1.101.3.4.2.1",
		"signAlgo":     "1.2.840.113549.1.1.1",
	}
	with := func(key string, value any) map[string]any {
		request := make(map[string]any, len(baseSignHash))
		for requestKey, requestValue := range baseSignHash {
			request[requestKey] = requestValue
		}
		request[key] = value
		return request
	}
	expectBadRequest(t, "signHash rejected signAlgo", stubPostJSON(t, e, "/csc/v1/signatures/signHash", access.serviceToken, with("signAlgo", "1.2.840.113549.1.1.11")))
	expectBadRequest(t, "signHash invalid SAD", stubPostJSON(t, e, "/csc/v1/signatures/signHash", access.serviceToken, with("SAD", "invalid-or-expired-sad")))
	// The published schema requires credentialID, but the beta stub currently accepts an empty value.
	// Pin that observed limitation so the proof matrix distinguishes a reachable endpoint from a
	// validated server-side constraint; this is not a shape the SDK is allowed to emit.
	expectStubLimitation(t, "signHash missing credentialID", stubPostJSON(t, e, "/csc/v1/signatures/signHash", access.serviceToken, with("credentialID", "")))
	// The current beta stub also accepts malformed hashes. Keep these separate from the valid-flow
	// assertion above: it proves request shape acceptance, not cryptographic input validation.
	expectStubLimitation(t, "signHash malformed hash", stubPostJSON(t, e, "/csc/v1/signatures/signHash", access.serviceToken, with("hash", []string{"not-base64"})))
	expectStubLimitation(t, "signHash wrong hash length", stubPostJSON(t, e, "/csc/v1/signatures/signHash", access.serviceToken, with("hash", []string{base64.StdEncoding.EncodeToString(make([]byte, 31))})))
}

func expectBadRequest(t *testing.T, name string, status int) {
	t.Helper()
	if status != http.StatusBadRequest {
		t.Fatalf("%s status=%d, want 400", name, status)
	}
}

func expectStubLimitation(t *testing.T, name string, status int) {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("%s status=%d, want current beta-stub limitation 200", name, status)
	}
}

func stubPostJSON(t *testing.T, e liveEnv, path, bearer string, body any) int {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode %s probe: %v", path, err)
	}
	status, _, err := upstream.New("").Do(context.Background(), http.MethodPost, stubURL(t, e, path), [][2]string{
		{"Content-Type", "application/json"},
		{"Authorization", "Bearer " + bearer},
	}, payload)
	if err != nil {
		t.Fatalf("%s probe: %v", path, err)
	}
	return status
}

func stubAuthorizeURL(t *testing.T, e liveEnv, scope, state string) string {
	t.Helper()
	u, err := url.Parse(stubURL(t, e, "/oauth2/authorize"))
	if err != nil {
		t.Fatalf("parse stub authorize URL: %v", err)
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("scope", scope)
	q.Set("client_id", e.clientID)
	q.Set("redirect_uri", e.redirectURI)
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String()
}

func stubURL(t *testing.T, e liveEnv, path string) string {
	t.Helper()
	joined, err := url.JoinPath(e.upstreamBaseURL, path)
	if err != nil {
		t.Fatalf("join stub URL: %v", err)
	}
	return joined
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
