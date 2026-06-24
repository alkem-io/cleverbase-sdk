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
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

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
		return nil, fmt.Errorf("signer key is not RSA")
	}
	certDER, err := os.ReadFile(filepath.Join(pki, "signer-rsa.cert.der"))
	if err != nil {
		return nil, fmt.Errorf("read signer cert: %w", err)
	}
	certB64 := base64.StdEncoding.EncodeToString(certDER)

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
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	code := "svc"
	if q.Get("scope") == "credential" {
		code = "cred"
	}
	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}
	loc := redirectURI + "?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state)
	http.Redirect(w, r, loc, http.StatusFound)
}

// handleToken returns the service Bearer token or the credential SAD based on the code.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if r.Form.Get("code") == "cred" {
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
	var req signHashRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Hash) == 0 {
		http.Error(w, "bad signHash request", http.StatusBadRequest)
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
