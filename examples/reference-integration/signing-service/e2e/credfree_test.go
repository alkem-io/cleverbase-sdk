// Package e2e drives the reference signing service end-to-end against the credential-free mock
// upstream (no Cleverbase credentials) and validates the produced PDF's CMS with OpenSSL — the
// credential-free MVP gate (US1 / FR-021). Build requires the cleverbase-ffi staticlib/dylib on the
// linker path (the Makefile/CI sets CGO_LDFLAGS + DYLD_LIBRARY_PATH).
package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

// buildService wires the signing service (fixtures mode) against the given upstream URL with the
// given CSC API (v1_rsa → /csc/v1 RSA signer, v2_ecdsa → /csc/v2 ECDSA P-256 signer).
func buildService(t *testing.T, conformance, cscAPI, upstreamURL string) *httptest.Server {
	t.Helper()
	p := &config.Profile{
		Mode: config.ModeFixtures, Environment: "acceptance", CscAPI: cscAPI,
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

// stack spins up the mock upstream + the signing service (fixtures mode) in-process for the given
// CSC API.
func stack(t *testing.T, conformance, cscAPI string) *httptest.Server {
	t.Helper()
	m, err := mock.New(repoFixtures(t))
	if err != nil {
		t.Fatalf("mock: %v", err)
	}
	mockSrv := httptest.NewServer(m.Handler())
	t.Cleanup(mockSrv.Close)
	return buildService(t, conformance, cscAPI, mockSrv.URL)
}

// cscAPIs is the algorithm table both credential-free flows run over: v1_rsa (RSA) and v2_ecdsa
// (ECDSA P-256). validateCMS / assertTimestampToken are algorithm-agnostic OpenSSL and reused
// unchanged for both (FR-004 / FR-005).
var cscAPIs = []struct{ name, api string }{
	{"v1_rsa", "v1_rsa"},
	{"v2_ecdsa", "v2_ecdsa"},
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

// stateFromURL extracts the OIDC `state` (CSRF nonce) the flow embedded in an authorize URL, so the
// Authorizer can be told the state the service expects echoed back. Empty string if absent/unparseable.
func stateFromURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Query().Get("state")
}

// runFlow performs start → complete ×2 and returns the result PDF + evidence header (or the terminal
// status/reason if it ends early). It drives each Cleverbase redirect through the pluggable Authorizer
// (mockAutoApprove for credential-free runs, Interactive/Headless for live), calling Authorize exactly
// once per redirect; the loop itself is authorizer-agnostic (contracts/authorizer.md, FR-013).
func runFlow(t *testing.T, auth Authorizer, svc *httptest.Server, startBody string) (pdf []byte, evidence string, status, reason string) {
	t.Helper()
	start := postJSON(t, svc.URL+"/v1/sign/start", startBody)
	corr, _ := start["correlationId"].(string)
	redirect, _ := start["redirectUrl"].(string)
	expectState := stateFromURL(redirect)

	for i := 0; i < 2 && redirect != ""; i++ {
		code, state, err := auth.Authorize(context.Background(), redirect, expectState)
		if err != nil {
			t.Fatalf("authorize redirect %d: %v", i, err)
		}
		res := postJSON(t, svc.URL+"/v1/sign/complete", `{"code":"`+code+`","state":"`+state+`"}`)
		status, _ = res["status"].(string)
		reason, _ = res["reason"].(string)
		redirect, _ = res["redirectUrl"].(string)
		expectState = stateFromURL(redirect)
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
// against the synthetic CA, failing the test on any verification error. Algorithm-agnostic (RSA +
// ECDSA), reused unchanged across both arms.
func validateCMS(t *testing.T, pdf []byte) {
	t.Helper()
	if err := verifyCMS(t, pdf, extractContents(t, pdf)); err != nil {
		t.Fatalf("openssl cms -verify failed: %v", err)
	}
}

// verifyCMS runs `openssl cms -verify` over the PDF's ByteRange content against the given CMS DER
// and returns the error (nil on accept), trusting the synthetic credential-free CA. Splitting the CMS
// bytes out lets a caller verify a tampered CMS and assert rejection (F1 / no-false-accept).
func verifyCMS(t *testing.T, pdf, cmsDER []byte) error {
	t.Helper()
	work := t.TempDir()
	caPEM := filepath.Join(work, "ca.pem")
	if out, err := exec.Command("openssl", "x509", "-inform", "DER",
		"-in", filepath.Join(repoFixtures(t), "pki", "ca.cert.der"), "-out", caPEM).CombinedOutput(); err != nil {
		t.Fatalf("materialize CA: %v %s", err, out)
	}
	return verifyCMSWithCA(t, pdf, cmsDER, caPEM)
}

// verifyCMSWithCA runs `openssl cms -verify` over the PDF's ByteRange content against the given CMS
// DER, trusting the PEM trust anchor at caPEMPath. Algorithm-agnostic (RSA + ECDSA) and trust-anchor
// agnostic: the credential-free arm passes the synthetic CA; the live arm passes the real Cleverbase
// issuer chain (REFSVC_LIVE_CA_BUNDLE); the N3 negative test passes a deliberately-wrong CA. Returns
// the error (nil on accept) so a caller can assert a loud failure on an untrusted issuer.
func verifyCMSWithCA(t *testing.T, pdf, cmsDER []byte, caPEMPath string) error {
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

	work := t.TempDir()
	sigDER := filepath.Join(work, "sig.der")
	dataBin := filepath.Join(work, "data.bin")
	if err := os.WriteFile(sigDER, cmsDER, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataBin, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("openssl", "cms", "-verify", "-binary", "-inform", "DER",
		"-in", sigDER, "-content", dataBin, "-CAfile", caPEMPath, "-purpose", "any", "-no_check_time").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\n%s", err, out)
	}
	return nil
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
	// Table over {v1_rsa, v2_ecdsa}: the same credential-free B-B flow + the same algorithm-agnostic
	// OpenSSL validator, for both algorithms (FR-004 / FR-005).
	for _, tc := range cscAPIs {
		t.Run(tc.name, func(t *testing.T) {
			svc := stack(t, "B-B", tc.api)
			doc := base64.StdEncoding.EncodeToString(samplePDF(t))
			pdf, evidence, status, _ := runFlow(t, mockAutoApprove{}, svc, `{"document":"`+doc+`","conformanceLevel":"B-B"}`)
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
		})
	}
}

func TestCredentialFreeBT(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl required for B-T")
	}
	for _, tc := range cscAPIs {
		t.Run(tc.name, func(t *testing.T) {
			svc := stack(t, "B-T", tc.api)
			doc := base64.StdEncoding.EncodeToString(samplePDF(t))
			pdf, _, status, _ := runFlow(t, mockAutoApprove{}, svc, `{"document":"`+doc+`","conformanceLevel":"B-T"}`)
			if status != "completed" || len(pdf) == 0 {
				t.Fatalf("expected completed B-T PDF, got status=%s len=%d", status, len(pdf))
			}
			validateCMS(t, pdf)
			assertTimestampToken(t, pdf)
		})
	}
}

// TestCredentialFreeECDSATamperRejected (F1 / FR-012 / SC-006): a produced ECDSA CMS with one
// signature byte flipped MUST be REJECTED by the always-on validator — proving no false-accept. The
// flip targets the /Contents CMS DER; the surrounding PDF/ByteRange is untouched so the failure is
// the signature check, not a structural parse error.
func TestCredentialFreeECDSATamperRejected(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl required to validate the CMS signature")
	}
	svc := stack(t, "B-B", "v2_ecdsa")
	doc := base64.StdEncoding.EncodeToString(samplePDF(t))
	pdf, _, status, _ := runFlow(t, mockAutoApprove{}, svc, `{"document":"`+doc+`","conformanceLevel":"B-B"}`)
	if status != "completed" || len(pdf) == 0 {
		t.Fatalf("expected completed ECDSA PDF, got status=%s len=%d", status, len(pdf))
	}
	cmsDER := extractContents(t, pdf)
	// Baseline: the untampered CMS verifies, so a later rejection is attributable to the tamper.
	if err := verifyCMS(t, pdf, cmsDER); err != nil {
		t.Fatalf("baseline ECDSA CMS should verify before tampering: %v", err)
	}
	tampered := tamperSignature(t, cmsDER)
	if err := verifyCMS(t, pdf, tampered); err == nil {
		t.Fatal("validateCMS MUST reject a tampered ECDSA signature (no false-accept)")
	}
}

// tamperSignature locates the CMS SignerInfo.signature OCTET STRING and flips its last content byte,
// leaving the surrounding DER structurally intact (parse still succeeds; only the signature value
// changes).
func tamperSignature(t *testing.T, cmsDER []byte) []byte {
	t.Helper()
	sig := signerInfoSignature(t, cmsDER)
	pos := bytes.LastIndex(cmsDER, sig)
	if pos < 0 {
		t.Fatal("signature bytes not found in CMS DER")
	}
	out := append([]byte{}, cmsDER...)
	out[pos+len(sig)-1] ^= 0x01
	return out
}

// signerInfoSignature parses the CMS and returns the first SignerInfo's raw signature value, using
// `openssl asn1parse` to avoid pulling a DER library into the test — the signature is the OCTET
// STRING that immediately follows the signatureAlgorithm; we find it by parsing the CMS and reading
// the last OCTET STRING primitive, which in a single-signer detached CMS is the signature value.
func signerInfoSignature(t *testing.T, cmsDER []byte) []byte {
	t.Helper()
	work := t.TempDir()
	in := filepath.Join(work, "cms.der")
	if err := os.WriteFile(in, cmsDER, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("openssl", "asn1parse", "-inform", "DER", "-in", in).CombinedOutput()
	if err != nil {
		t.Fatalf("asn1parse: %v\n%s", err, out)
	}
	// Each line: " <offset>:d=.. hl=.. l=.. prim: <TYPE> ...". The SignerInfo.signature is the last
	// OCTET STRING primitive in a single-signer detached CMS (after the cert + signed attrs).
	var lastOff, lastHL, lastLen int
	found := false
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "OCTET STRING") || !strings.Contains(line, "prim:") {
			continue
		}
		off, hl, l, ok := parseASN1Line(line)
		if !ok {
			continue
		}
		lastOff, lastHL, lastLen = off, hl, l
		found = true
	}
	if !found {
		t.Fatalf("no OCTET STRING primitive in CMS:\n%s", out)
	}
	start := lastOff + lastHL
	if start+lastLen > len(cmsDER) {
		t.Fatalf("signature span out of range: %d+%d > %d", start, lastLen, len(cmsDER))
	}
	return cmsDER[start : start+lastLen]
}

// asn1OffsetRE captures the offset, header length (hl), and content length (l) from an
// `openssl asn1parse` line: "  <off>:d=.. hl=<hl> l=  <l> prim: OCTET STRING ...".
var asn1OffsetRE = regexp.MustCompile(`^\s*(\d+):d=\s*\d+\s+hl=\s*(\d+)\s+l=\s*(\d+)`)

func parseASN1Line(line string) (off, hl, l int, ok bool) {
	m := asn1OffsetRE.FindStringSubmatch(line)
	if m == nil {
		return 0, 0, 0, false
	}
	off, _ = strconv.Atoi(m[1])
	hl, _ = strconv.Atoi(m[2])
	l, _ = strconv.Atoi(m[3])
	return off, hl, l, true
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
	// scanned holds, per upstream request, the full attacker-reachable surface — request line (URL,
	// incl. path + query), headers, and body — so the hash-only assertion covers more than just the
	// body. A regression that smuggled the PDF/secret into the authorize URL/path/query/headers would
	// otherwise sail through (the recorder used to save only r.Body, despite claiming to cover EVERY
	// upstream request).
	var scanned []string
	rec := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var sb strings.Builder
		sb.WriteString(r.Method)
		sb.WriteByte(' ')
		sb.WriteString(r.URL.String())
		sb.WriteByte('\n')
		_ = r.Header.Write(&sb)
		sb.WriteByte('\n')
		_, _ = sb.Write(b)
		mu.Lock()
		bodies = append(bodies, string(b))
		scanned = append(scanned, sb.String())
		mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(b))
		m.Handler().ServeHTTP(w, r)
	}))
	defer rec.Close()

	svc := buildService(t, "B-T", "v1_rsa", rec.URL) // B-T exercises the TSA request too
	doc := base64.StdEncoding.EncodeToString(samplePDF(t))
	_, _, status, _ := runFlow(t, mockAutoApprove{}, svc, `{"document":"`+doc+`","conformanceLevel":"B-T"}`)
	if status != "completed" {
		t.Fatalf("expected completed, got %s", status)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(scanned) == 0 {
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
	// Negative: no part of any upstream request — URL (path+query), headers, or body — may carry the
	// document, verbatim or in any common encoding.
	for i, s := range scanned {
		if strings.Contains(s, string(rawDoc)) {
			t.Fatalf("upstream request %d carried the raw document (hash-only violated): %.120s", i, s)
		}
		for _, enc := range encodings {
			if strings.Contains(s, enc) {
				t.Fatalf("upstream request %d carried an encoded document (hash-only violated): %.120s", i, s)
			}
		}
	}
	sawSignHash := false
	for i, b := range bodies {
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
	svc := stack(t, "B-B", "v1_rsa")
	doc := base64.StdEncoding.EncodeToString(samplePDF(t))
	body := `{"document":"` + doc + `","expectedSigner":{"matchOn":"certificate_serial_number","value":"DOES-NOT-MATCH"}}`
	_, _, status, reason := runFlow(t, mockAutoApprove{}, svc, body)
	if status != "failed" || reason != "identity_mismatch" {
		t.Fatalf("expected failed/identity_mismatch, got %s/%s", status, reason)
	}
}
