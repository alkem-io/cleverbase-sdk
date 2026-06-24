// Package e2e drives the reference signing service end-to-end against the credential-free mock
// upstream (no Cleverbase credentials) and validates the produced PDF's CMS with OpenSSL — the
// credential-free MVP gate (US1 / FR-021). Build requires the cleverbase-ffi staticlib/dylib on the
// linker path (the Makefile/CI sets CGO_LDFLAGS + DYLD_LIBRARY_PATH).
package e2e

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/mock-upstream/mock"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/config"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/flow"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/httpapi"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/sdk"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/session"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/upstream"
)

const apiKey = "e2e-key"

func repoFixtures(t *testing.T) string {
	t.Helper()
	dir, _ := os.Getwd()
	for range 12 {
		cand := filepath.Join(dir, "tests", "fixtures")
		if st, err := os.Stat(filepath.Join(cand, "upstream")); err == nil && st.IsDir() {
			return cand
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("tests/fixtures not found")
	return ""
}

func samplePDF(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "cmd", "refsvc", "sample.pdf"))
	if err != nil {
		t.Fatalf("read sample pdf: %v", err)
	}
	return b
}

// buildService wires the signing service (fixtures mode) against the given upstream URL.
func buildService(t *testing.T, conformance, upstreamURL string) *httptest.Server {
	t.Helper()
	p := &config.Profile{
		Mode: config.ModeFixtures, Environment: "acceptance", CscAPI: "v1_rsa",
		ClientID: "refsvc-fixtures", ClientSecret: "fixtures", RedirectURI: "http://app/return",
		UpstreamBaseURL: upstreamURL, TsaURL: upstreamURL + "/tsr",
		APIKey: apiKey, AuthEnabled: true, DefaultConformance: conformance, SessionTTL: time.Minute,
	}
	store := session.NewMemory()
	eng := &flow.Engine{
		SDK: sdk.New(p), Up: upstream.New(upstreamURL), Store: store,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), TTL: p.SessionTTL,
		RedirectRewrite: upstream.New(upstreamURL).Rewrite,
	}
	service := &httpapi.Service{Engine: eng, Store: store, Profile: p, Sample: samplePDF(t)}
	svcSrv := httptest.NewServer(service.Handler())
	t.Cleanup(svcSrv.Close)
	return svcSrv
}

// stack spins up the mock upstream + the signing service (fixtures mode) in-process.
func stack(t *testing.T, conformance string) *httptest.Server {
	t.Helper()
	m, err := mock.New(repoFixtures(t))
	if err != nil {
		t.Fatalf("mock: %v", err)
	}
	mockSrv := httptest.NewServer(m.Handler())
	t.Cleanup(mockSrv.Close)
	return buildService(t, conformance, mockSrv.URL)
}

func postJSON(t *testing.T, rawURL, body string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("post %s: status %d body %v", rawURL, resp.StatusCode, m)
	}
	return m
}

// followRedirect GETs the (mock) authorization URL without following, returning code+state.
func followRedirect(t *testing.T, authURL string) (code, state string) {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("authorize GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	loc := resp.Header.Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse redirect %q: %v", loc, err)
	}
	return u.Query().Get("code"), u.Query().Get("state")
}

// runFlow performs start → complete ×2 and returns the result PDF + evidence header (or the terminal
// status/reason if it ends early).
func runFlow(t *testing.T, svc *httptest.Server, startBody string) (pdf []byte, evidence string, status, reason string) {
	t.Helper()
	start := postJSON(t, svc.URL+"/v1/sign/start", startBody)
	corr, _ := start["correlationId"].(string)
	redirect, _ := start["redirectUrl"].(string)

	for i := 0; i < 2 && redirect != ""; i++ {
		code, state := followRedirect(t, redirect)
		res := postJSON(t, svc.URL+"/v1/sign/complete", `{"code":"`+code+`","state":"`+state+`"}`)
		status, _ = res["status"].(string)
		reason, _ = res["reason"].(string)
		redirect, _ = res["redirectUrl"].(string)
		if status == "completed" {
			break
		}
		if status != "authorizing" {
			return nil, "", status, reason // failed / declined
		}
	}
	if status != "completed" {
		return nil, "", status, reason
	}

	req, _ := http.NewRequest(http.MethodGet, svc.URL+"/v1/sign/result?correlationId="+corr, nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("result: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("result fetch after completion returned %d", resp.StatusCode)
	}
	pdf, _ = io.ReadAll(resp.Body)
	return pdf, resp.Header.Get("X-Signature-Evidence"), "completed", ""
}

var byteRangeRE = regexp.MustCompile(`/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]`)

// validateCMS extracts the PAdES ByteRange + /Contents and verifies the detached CMS with OpenSSL
// against the synthetic CA. Returns an error describing any failure.
func validateCMS(t *testing.T, pdf []byte) {
	t.Helper()
	m := byteRangeRE.FindSubmatch(pdf)
	if m == nil {
		t.Fatal("no /ByteRange in signed PDF")
	}
	n := func(b []byte) int { v, _ := strconv.Atoi(string(b)); return v }
	a, b, c, d := n(m[1]), n(m[2]), n(m[3]), n(m[4])
	if a+b > len(pdf) || c+d > len(pdf) || a+b > c {
		t.Fatalf("ByteRange out of bounds: [%d %d %d %d] len=%d", a, b, c, d, len(pdf))
	}
	signed := append(append([]byte{}, pdf[a:a+b]...), pdf[c:c+d]...)
	// /Contents is a separate dict field: find the keyword, then the <hex> after it. The hex is
	// zero-padded to a fixed size, so decode it all then trim to the DER object's true length —
	// the same extraction the SDK's own independent-validation test uses.
	cmsDER := extractContents(t, pdf)

	work := t.TempDir()
	caPEM := filepath.Join(work, "ca.pem")
	if out, err := exec.Command("openssl", "x509", "-inform", "DER",
		"-in", filepath.Join(repoFixtures(t), "pki", "ca.cert.der"), "-out", caPEM).CombinedOutput(); err != nil {
		t.Fatalf("materialize CA: %v %s", err, out)
	}
	sigDER := filepath.Join(work, "sig.der")
	dataBin := filepath.Join(work, "data.bin")
	if err := os.WriteFile(sigDER, cmsDER, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataBin, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("openssl", "cms", "-verify", "-binary", "-inform", "DER",
		"-in", sigDER, "-content", dataBin, "-CAfile", caPEM, "-purpose", "any", "-no_check_time").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl cms -verify failed: %v\n%s", err, out)
	}
}

// assertTimestampToken checks that a B-T signature embeds an RFC 3161 signature-timestamp token as
// an unsigned attribute (OID 1.2.840.113549.1.9.16.2.14).
func assertTimestampToken(t *testing.T, pdf []byte) {
	t.Helper()
	work := t.TempDir()
	sigDER := filepath.Join(work, "sig.der")
	if err := os.WriteFile(sigDER, extractContents(t, pdf), 0o600); err != nil {
		t.Fatal(err)
	}
	info, _ := exec.Command("openssl", "cms", "-cmsout", "-inform", "DER", "-in", sigDER, "-print").CombinedOutput()
	if !strings.Contains(string(info), "1.2.840.113549.1.9.16.2.14") {
		t.Fatalf("B-T signature missing timestamp token attribute:\n%s", info)
	}
}

// extractContents finds the /Contents <hex> blob and returns the embedded CMS DER, trimmed to the
// DER object's declared length (dropping the zero padding).
func extractContents(t *testing.T, pdf []byte) []byte {
	t.Helper()
	k := strings.Index(string(pdf), "/Contents")
	if k < 0 {
		t.Fatal("no /Contents in signed PDF")
	}
	lt := bytes.IndexByte(pdf[k:], '<')
	if lt < 0 {
		t.Fatal("no '<' after /Contents")
	}
	lt += k + 1
	gt := bytes.IndexByte(pdf[lt:], '>')
	if gt < 0 {
		t.Fatal("no '>' closing /Contents")
	}
	hexStr := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\n', '\r', '\t':
			return -1
		}
		return r
	}, string(pdf[lt:lt+gt]))
	raw := decodeHex(t, hexStr)
	return raw[:derTotalLen(raw)]
}

// derTotalLen returns the full length of the leading DER TLV (tag + length + content).
func derTotalLen(b []byte) int {
	if len(b) < 2 {
		return len(b)
	}
	l := b[1]
	if l < 0x80 {
		return 2 + int(l)
	}
	n := int(l & 0x7f)
	if len(b) < 2+n {
		return len(b)
	}
	length := 0
	for i := range n {
		length = length<<8 | int(b[2+i])
	}
	return 2 + n + length
}

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	if len(s)%2 == 1 {
		s += "0"
	}
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		v, err := strconv.ParseUint(s[2*i:2*i+2], 16, 8)
		if err != nil {
			t.Fatalf("bad hex in /Contents: %v", err)
		}
		b[i] = byte(v)
	}
	return b
}

func TestCredentialFreeBB(t *testing.T) {
	// validateCMS execs `openssl cms -verify`; skip (don't hard-fail) when it is absent, matching
	// TestCredentialFreeBT.
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl required to validate the CMS signature")
	}
	svc := stack(t, "B-B")
	doc := base64.StdEncoding.EncodeToString(samplePDF(t))
	pdf, evidence, status, _ := runFlow(t, svc, `{"document":"`+doc+`","conformanceLevel":"B-B"}`)
	if status != "completed" || len(pdf) == 0 {
		t.Fatalf("expected completed with a PDF, got status=%s len=%d", status, len(pdf))
	}
	if evidence == "" {
		t.Fatal("missing X-Signature-Evidence header")
	}
	if _, err := base64.StdEncoding.DecodeString(evidence); err != nil {
		t.Fatalf("evidence header not base64: %v", err)
	}
	validateCMS(t, pdf)
}

func TestCredentialFreeBT(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl required for B-T")
	}
	svc := stack(t, "B-T")
	doc := base64.StdEncoding.EncodeToString(samplePDF(t))
	pdf, _, status, _ := runFlow(t, svc, `{"document":"`+doc+`","conformanceLevel":"B-T"}`)
	if status != "completed" || len(pdf) == 0 {
		t.Fatalf("expected completed B-T PDF, got status=%s len=%d", status, len(pdf))
	}
	validateCMS(t, pdf)
	assertTimestampToken(t, pdf)
}

// TestUpstreamReceivesHashOnly proves the document never leaves the backend: every request the
// service makes to the upstream is recorded, and none may carry the PDF's distinctive structure —
// Cleverbase only ever receives a hash via signHash (FR-004 / SC, hash-only).
func TestUpstreamReceivesHashOnly(t *testing.T) {
	m, err := mock.New(repoFixtures(t))
	if err != nil {
		t.Fatalf("mock: %v", err)
	}
	var mu sync.Mutex
	var bodies []string
	rec := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(b))
		m.Handler().ServeHTTP(w, r)
	}))
	defer rec.Close()

	svc := buildService(t, "B-T", rec.URL) // B-T exercises the TSA request too
	doc := base64.StdEncoding.EncodeToString(samplePDF(t))
	_, _, status, _ := runFlow(t, svc, `{"document":"`+doc+`","conformanceLevel":"B-T"}`)
	if status != "completed" {
		t.Fatalf("expected completed, got %s", status)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) == 0 {
		t.Fatal("no upstream requests were recorded")
	}

	rawDoc := samplePDF(t)
	// Every common encoding a regression could smuggle the document in as.
	encodings := []string{
		base64.StdEncoding.EncodeToString(rawDoc),                  // padded standard base64
		base64.RawStdEncoding.EncodeToString(rawDoc),               // unpadded standard base64
		base64.URLEncoding.EncodeToString(rawDoc),                  // padded base64url
		base64.RawURLEncoding.EncodeToString(rawDoc),               // unpadded base64url
		url.QueryEscape(base64.StdEncoding.EncodeToString(rawDoc)), // form/query-escaped base64
		hex.EncodeToString(rawDoc),                                 // hex
	}
	sawSignHash := false
	for i, b := range bodies {
		// Negative: no upstream request may carry the document — verbatim or in any common encoding.
		if bytes.Contains([]byte(b), rawDoc) {
			t.Fatalf("upstream request %d carried the raw document (hash-only violated): %.120s", i, b)
		}
		for _, enc := range encodings {
			if strings.Contains(b, enc) {
				t.Fatalf("upstream request %d carried an encoded document (hash-only violated): %.120s", i, b)
			}
		}
		// Positive: the only document-derived payload is the signHash request, and its hash must be
		// exactly a 32-byte SHA-256 digest — not the document.
		if strings.Contains(b, `"hash"`) {
			sawSignHash = true
			var sh struct {
				Hash []string `json:"hash"`
			}
			if err := json.Unmarshal([]byte(b), &sh); err != nil || len(sh.Hash) != 1 {
				t.Fatalf("signHash request %d malformed: %.120s", i, b)
			}
			digest, err := base64.StdEncoding.DecodeString(sh.Hash[0])
			if err != nil || len(digest) != 32 {
				t.Fatalf("signHash request %d hash is not a 32-byte digest (len=%d, err=%v)", i, len(digest), err)
			}
		}
	}
	if !sawSignHash {
		t.Fatal("expected a signHash request carrying the document digest")
	}
}

func TestExpectedSignerMismatch(t *testing.T) {
	svc := stack(t, "B-B")
	doc := base64.StdEncoding.EncodeToString(samplePDF(t))
	body := `{"document":"` + doc + `","expectedSigner":{"matchOn":"certificate_serial_number","value":"DOES-NOT-MATCH"}}`
	_, _, status, reason := runFlow(t, svc, body)
	if status != "failed" || reason != "identity_mismatch" {
		t.Fatalf("expected failed/identity_mismatch, got %s/%s", status, reason)
	}
}
