package mock

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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
		resp, err := http.PostForm(ts.URL+"/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}})
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
}

func TestSignHashProducesVerifiableSignature(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	digest := sha256.Sum256([]byte("to-be-signed attributes"))
	body, _ := json.Marshal(map[string]any{"hash": []string{base64.StdEncoding.EncodeToString(digest[:])}})
	resp, err := http.Post(ts.URL+"/csc/v1/signatures/signHash", "application/json", strings.NewReader(string(body)))
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

	// Verify against the signer cert's public key — the same trust anchor the SDK embeds.
	certDER, _ := os.ReadFile(filepath.Join(findFixtures(t), "pki", "signer-rsa.cert.der"))
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("signer cert is not RSA")
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
}

func TestInfoCarriesSubstitutedCert(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/csc/v1/credentials/info")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("info decode: %v", err)
	}
	cert := m["cert"].(map[string]any)
	certs := cert["certificates"].([]any)
	if len(certs) != 1 || strings.Contains(certs[0].(string), "{{") {
		t.Fatalf("cert placeholder not substituted: %v", certs)
	}
	if _, err := base64.StdEncoding.DecodeString(certs[0].(string)); err != nil {
		t.Fatalf("substituted cert is not base64: %v", err)
	}
}
