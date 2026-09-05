package mock

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// findFixtures walks up from the test's working dir to the repo's tests/fixtures.
func findFixtures(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for range 12 {
		cand := filepath.Join(dir, "tests", "fixtures")
		if st, err := os.Stat(filepath.Join(cand, "upstream")); err == nil && st.IsDir() {
			return cand
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not locate tests/fixtures")
	return ""
}

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	s, err := New(findFixtures(t))
	if err != nil {
		t.Fatalf("mock.New: %v", err)
	}
	return httptest.NewServer(s.Handler())
}

func TestAuthorizeRedirectsWithScopedCode(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	for scope, wantCode := range map[string]string{"service": "svc", "credential": "cred"} {
		u := ts.URL + "/oauth2/authorize?scope=" + scope + "&redirect_uri=" + url.QueryEscape("http://app/cb") + "&state=xyz"
		resp, err := client.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		loc := resp.Header.Get("Location")
		status := resp.StatusCode
		_ = resp.Body.Close()
		if status != http.StatusFound {
			t.Fatalf("scope %s: want 302, got %d", scope, status)
		}
		if !strings.Contains(loc, "code="+wantCode) || !strings.Contains(loc, "state=xyz") {
			t.Fatalf("scope %s: unexpected Location %q", scope, loc)
		}
	}
}

func TestTokenServiceVsCredential(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	get := func(code string) string {
		resp, err := http.PostForm(ts.URL+"/oauth2/token", url.Values{
			"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"test-client"},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var m map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return m["access_token"]
	}
	if tok := get("svc"); tok != "bearer" {
		t.Fatalf("service token = %q, want bearer", tok)
	}
	if tok := get("cred"); tok != "SAD" {
		t.Fatalf("credential token = %q, want SAD", tok)
	}

	// Cleverbase's documented token contract requires the public client identifier in the form even
	// when the client authenticates separately. The mock must reject the old underspecified shape so
	// the credential-free E2E cannot mask a regression that the public signing stub catches.
	resp, err := http.PostForm(ts.URL+"/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "code": {"svc"}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("token without client_id status = %d, want 400", resp.StatusCode)
	}

	// URL query parameters are not form fields in Cleverbase's token contract. ParseForm merges
	// both sources, so this regression test ensures the mock reads PostForm and cannot accept an
	// underspecified SDK request merely because an unrelated query string carries client_id.
	resp, err = http.PostForm(ts.URL+"/oauth2/token?client_id=test-client", url.Values{
		"grant_type": {"authorization_code"}, "code": {"svc"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("token with query-only client_id status = %d, want 400", resp.StatusCode)
	}
}

// signHash POSTs a SHA-256 digest to the given CSC route and returns the decoded signature bytes.
func signHash(t *testing.T, baseURL, route string, digest []byte) []byte {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"hash": []string{base64.StdEncoding.EncodeToString(digest)}})
	resp, err := http.Post(baseURL+route+"/signatures/signHash", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Signatures []string `json:"signatures"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || len(out.Signatures) != 1 {
		t.Fatalf("signHash response: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(out.Signatures[0])
	if err != nil {
		t.Fatalf("sig base64: %v", err)
	}
	return sig
}

// parseCert loads a signer cert (DER) from the PKI fixtures.
func parseCert(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	certDER, err := os.ReadFile(filepath.Join(findFixtures(t), "pki", name))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// TestSignHashV1ProducesVerifiableRSASignature asserts the /csc/v1 route signs with RSA (PKCS#1
// v1.5 over SHA-256) verifiable against signer-rsa — the route's expected algorithm (T014).
func TestSignHashV1ProducesVerifiableRSASignature(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	digest := sha256.Sum256([]byte("to-be-signed attributes"))
	sig := signHash(t, ts.URL, "/csc/v1", digest[:])

	pub, ok := parseCert(t, "signer-rsa.cert.der").PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("signer-rsa cert is not RSA")
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("v1 RSA signature does not verify: %v", err)
	}
}

// TestSignHashV2ProducesVerifiableECDSASignature asserts the /csc/v2 route signs with ECDSA P-256
// and returns the raw 64-byte r‖s wire form, verifiable against signer-ec after reconstructing
// (r, s) — exercising the real CSC-v2 path the SDK core normalizes (T004).
func TestSignHashV2ProducesVerifiableECDSASignature(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	digest := sha256.Sum256([]byte("to-be-signed attributes"))
	sig := signHash(t, ts.URL, "/csc/v2", digest[:])

	// The v2 wire form is raw fixed-width r‖s (64 bytes for P-256), NOT a DER ECDSA-Sig-Value.
	if len(sig) != 2*p256ScalarLen {
		t.Fatalf("v2 signature must be raw 64-byte r‖s, got %d bytes", len(sig))
	}
	pub, ok := parseCert(t, "signer-ec.cert.der").PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("signer-ec cert is not ECDSA")
	}
	r := new(big.Int).SetBytes(sig[:p256ScalarLen])
	s := new(big.Int).SetBytes(sig[p256ScalarLen:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		t.Fatal("v2 ECDSA signature does not verify against signer-ec")
	}
}

// credentialsInfoKey / Cert / Info mirror the credentials/info response shape we assert on (named
// types so the test carries no nested anonymous structs).
type credentialsInfoKey struct {
	Algo []string `json:"algo"`
}

type credentialsInfoCert struct {
	Certificates []string `json:"certificates"`
	SerialNumber string   `json:"serialNumber"`
}

type credentialsInfo struct {
	Key  credentialsInfoKey  `json:"key"`
	Cert credentialsInfoCert `json:"cert"`
}

// rsaPub / ecdsaPub report whether a parsed certificate's public key is of that type — used to
// assert the advertised cert matches the route's algorithm.
func rsaPub(c *x509.Certificate) bool   { _, ok := c.PublicKey.(*rsa.PublicKey); return ok }
func ecdsaPub(c *x509.Certificate) bool { _, ok := c.PublicKey.(*ecdsa.PublicKey); return ok }

// TestInfoCarriesRouteSignerCertAndAlgo asserts each route's credentials/info advertises the cert +
// key.algo OID of THAT route's signer — RSA on v1, ECDSA P-256 on v2 (one template, per-route
// substitution; T011/T014).
func TestInfoCarriesRouteSignerCertAndAlgo(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	cases := []struct {
		route, wantOID, wantSerial string
		pubMatches                 func(*x509.Certificate) bool // the advertised cert's key type
		pubName                    string
	}{
		{"/csc/v1", "1.2.840.113549.1.1.1", "PNONL-123", rsaPub, "RSA"},
		{"/csc/v2", "1.2.840.10045.2.1", "PNONL-456", ecdsaPub, "ECDSA"},
	}
	for _, c := range cases {
		resp, err := http.Get(ts.URL + c.route + "/credentials/info")
		if err != nil {
			t.Fatal(err)
		}
		var m credentialsInfo
		err = json.NewDecoder(resp.Body).Decode(&m)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("%s info decode: %v", c.route, err)
		}
		if len(m.Key.Algo) != 1 || m.Key.Algo[0] != c.wantOID {
			t.Fatalf("%s key.algo = %v, want [%s]", c.route, m.Key.Algo, c.wantOID)
		}
		if m.Cert.SerialNumber != c.wantSerial {
			t.Fatalf("%s serialNumber = %q, want %q", c.route, m.Cert.SerialNumber, c.wantSerial)
		}
		if len(m.Cert.Certificates) != 1 || strings.Contains(m.Cert.Certificates[0], "{{") {
			t.Fatalf("%s cert placeholder not substituted: %v", c.route, m.Cert.Certificates)
		}
		certDER, err := base64.StdEncoding.DecodeString(m.Cert.Certificates[0])
		if err != nil {
			t.Fatalf("%s substituted cert is not base64: %v", c.route, err)
		}
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatalf("%s substituted cert does not parse: %v", c.route, err)
		}
		// The advertised cert's public-key type must match the route's algorithm (no drift between
		// the cert and the OID/signature).
		if !c.pubMatches(cert) {
			t.Fatalf("%s cert is not %s", c.route, c.pubName)
		}
	}
}
