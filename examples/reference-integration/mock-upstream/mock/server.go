// Package mock implements a credential-free stand-in for Cleverbase's CSC/OIDC surface + an RFC 3161
// TSA. It serves the SDK's recorded upstream fixtures (tests/fixtures/upstream/*.json) and signs
// signHash requests + timestamps with the synthetic test PKI, so a produced signature validates with
// OpenSSL exactly as in the SDK's own independent-validation test. No protocol logic is re-invented:
// the response shapes come from the shared fixtures (Constitution VIII / FR-015).
package mock

import (
	"crypto"
	"crypto/rsa"
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
)

// codeCredential is the OAuth code the mock returns for the credential-scope authorization (and the
// token endpoint switches on it to serve the credential SAD instead of the service token).
const codeCredential = "cred"

// maxRequestBody caps POST request bodies (signHash, token form) so an unbounded body cannot
// exhaust memory. These payloads are tiny (a base64 hash + metadata, or an OAuth form), so 1 MiB is
// generous; the DER TSA request has its own tighter 64 KiB cap in handleTSA.
const maxRequestBody = 1 << 20 // 1 MiB

// bodyErrorStatus maps a request-body read/decode error to an HTTP status: an over-limit body
// (http.MaxBytesReader) is 413 Request Entity Too Large; any other decode failure is 400.
func bodyErrorStatus(err error) int {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

// Server holds the loaded PKI + fixtures and routes the mock endpoints.
type Server struct {
	pkiDir   string
	rsaKey   *rsa.PrivateKey
	infoJSON []byte
	listJSON []byte
	svcToken []byte
	credSAD  []byte
	mux      *http.ServeMux
}

func readFixturesAndPKI(fixturesDir string) (*Server, error) {
	upstream := filepath.Join(fixturesDir, "upstream")
	pki := filepath.Join(fixturesDir, "pki")

	//nolint:gosec // G304: fixture path under the operator-set REFMOCK_FIXTURES_DIR, never request input.
	keyDER, err := os.ReadFile(filepath.Join(pki, "signer-rsa.key.pk8"))
	if err != nil {
		return nil, fmt.Errorf("read signer key: %w", err)
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, fmt.Errorf("parse signer key: %w", err)
	}
	rsaKey, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("signer key is not RSA")
	}
	//nolint:gosec // G304: fixture path under the operator-set REFMOCK_FIXTURES_DIR, never request input.
	certDER, err := os.ReadFile(filepath.Join(pki, "signer-rsa.cert.der"))
	if err != nil {
		return nil, fmt.Errorf("read signer cert: %w", err)
	}
	certB64 := base64.StdEncoding.EncodeToString(certDER)

	//nolint:gosec // G304: fixture filenames are internal constants under REFMOCK_FIXTURES_DIR, never request input.
	read := func(name string) ([]byte, error) { return os.ReadFile(filepath.Join(upstream, name)) }
	info, err := read("credentials_info.json")
	if err != nil {
		return nil, err
	}
	info = []byte(strings.ReplaceAll(string(info), "{{signer_rsa_cert_b64}}", certB64))
	list, err := read("credentials_list.json")
	if err != nil {
		return nil, err
	}
	svc, err := read("service_token.json")
	if err != nil {
		return nil, err
	}
	cred, err := read("credential_token.json")
	if err != nil {
		return nil, err
	}

	return &Server{pkiDir: pki, rsaKey: rsaKey, infoJSON: info, listJSON: list, svcToken: svc, credSAD: cred}, nil
}

// New builds the mock from a fixtures directory (containing upstream/ and pki/).
func New(fixturesDir string) (*Server, error) {
	s, err := readFixturesAndPKI(fixturesDir)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/authorize", s.handleAuthorize)
	mux.HandleFunc("/oauth2/token", s.handleToken)
	// CSC v1 (RSA) and v2 share the same RSA fixtures here.
	for _, base := range []string{"/csc/v1", "/csc/v2"} {
		mux.HandleFunc(base+"/credentials/list", s.handleList)
		mux.HandleFunc(base+"/credentials/info", s.handleInfo)
		mux.HandleFunc(base+"/signatures/signHash", s.handleSignHash)
	}
	mux.HandleFunc("/tsr", s.handleTSA)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, map[string]string{"status": "ok"}) })
	s.mux = mux
	return s, nil
}

// Handler returns the routed mock.
func (s *Server) Handler() http.Handler { return s.mux }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeRaw(w http.ResponseWriter, b []byte) {
	w.Header().Set("content-type", "application/json")
	_, _ = w.Write(b)
}

// handleAuthorize 302-redirects back to the request's redirect_uri with a scope-tagged code+state,
// auto-completing the human authorization step for credential-free runs.
func (*Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	code := "svc"
	if q.Get("scope") == "credential" {
		code = codeCredential
	}
	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}
	// Build the location with net/url so code+state are merged into the redirect_uri's existing
	// query instead of string-appended: a raw "?code=...&state=..." concatenation produces a
	// malformed URL (e.g. a double "?") when the redirect_uri already carries a query or fragment.
	loc, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	rq := loc.Query()
	rq.Set("code", code)
	rq.Set("state", state)
	loc.RawQuery = rq.Encode()
	//nolint:gosec // G710: this is a credential-free OAuth MOCK; mirroring the caller's redirect_uri back is exactly its job (no real sessions/tokens are at risk).
	http.Redirect(w, r, loc.String(), http.StatusFound)
}

// handleToken returns the service Bearer token or the credential SAD based on the code.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	// Cap the form body before ParseForm reads it so an unbounded request cannot exhaust memory;
	// an OAuth token form is tiny, so the shared 1 MiB cap is generous.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	_ = r.ParseForm()
	if r.Form.Get("code") == codeCredential {
		writeRaw(w, s.credSAD)
		return
	}
	writeRaw(w, s.svcToken)
}

func (s *Server) handleList(w http.ResponseWriter, _ *http.Request) { writeRaw(w, s.listJSON) }
func (s *Server) handleInfo(w http.ResponseWriter, _ *http.Request) { writeRaw(w, s.infoJSON) }

type signHashRequest struct {
	Hash []string `json:"hash"`
}

// handleSignHash RSA-signs the submitted to-be-signed digest with the synthetic signer key
// (PKCS#1 v1.5 over a SHA-256 DigestInfo), mirroring the SDK's independent-validation test.
func (s *Server) handleSignHash(w http.ResponseWriter, r *http.Request) {
	// Cap the body before decoding so an unbounded request cannot exhaust memory; a signHash
	// request only carries a base64 hash plus small metadata, so 1 MiB is generous.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req signHashRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Hash) == 0 {
		http.Error(w, "bad signHash request", bodyErrorStatus(err))
		return
	}
	tbs, err := base64.StdEncoding.DecodeString(req.Hash[0])
	if err != nil {
		http.Error(w, "bad hash base64", http.StatusBadRequest)
		return
	}
	sig, err := rsa.SignPKCS1v15(nil, s.rsaKey, crypto.SHA256, tbs)
	if err != nil {
		http.Error(w, "sign failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"signatures": []string{base64.StdEncoding.EncodeToString(sig)}})
}
