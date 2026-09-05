// Package mock implements a credential-free stand-in for Cleverbase's CSC/OIDC surface + an RFC 3161
// TSA. It serves the SDK's recorded upstream fixtures (tests/fixtures/upstream/*.json) and signs
// signHash requests + timestamps with the synthetic test PKI, so a produced signature validates with
// OpenSSL exactly as in the SDK's own independent-validation test. No protocol logic is re-invented:
// the response shapes come from the shared fixtures (Constitution VIII / FR-015).
//
// CSC v1 (/csc/v1) is the RSA signer; CSC v2 (/csc/v2) is the ECDSA P-256 signer. Both routes share
// one `credentials/info` template, substituted per route from the SAME signer that produces the
// signHash bytes (cert + key.algo OID never drift) — one parametrized path, no RSA/ECDSA twin code
// (FR-004).
package mock

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// OAuth codes the mock returns for the two authorization scopes and recognizes at /oauth2/token.
const (
	codeService    = "svc"
	codeCredential = "cred"
)

// maxRequestBody caps POST request bodies (signHash, token form) so an unbounded body cannot
// exhaust memory. These payloads are tiny (a base64 hash + metadata, or an OAuth form), so 1 MiB is
// generous; the DER TSA request has its own tighter 64 KiB cap in handleTSA.
const maxRequestBody = 1 << 20 // 1 MiB

// p256ScalarLen is the fixed width (bytes) of each of r and s in a P-256 raw r‖s signature.
const p256ScalarLen = 32

// Per-route signer algorithm labels — one authoritative string each (Constitution III), used as the
// key-load error label.
const (
	algoRSA   = "RSA"
	algoECDSA = "EcdsaP256"
)

// bodyErrorStatus maps a request-body read/decode error to an HTTP status: an over-limit body
// (http.MaxBytesReader) is 413 Request Entity Too Large; any other decode failure is 400.
func bodyErrorStatus(err error) int {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

// signer is a per-CSC-route signing identity: a loaded private key + its certificate, the key.algo
// OID it advertises in credentials/info, the subject DN / serial of that cert, and the routine that
// signs the 32-byte to-be-signed digest. RSA → PKCS#1 v1.5(SHA-256); ECDSA P-256 → raw 64-byte r‖s
// (the real CSC-v2 wire form; the SDK core's ecdsa_signature_to_der normalizes it).
type signer struct {
	certDER   []byte // signer-<algo>.cert.der
	algoOID   string // credentials/info key.algo OID
	subjectDN string // credentials/info cert.subjectDN
	serial    string // credentials/info cert.serialNumber
	sign      func(tbs []byte) ([]byte, error)
}

// rsaSigner loads signer-rsa and signs PKCS#1 v1.5 over a SHA-256 digest.
func rsaSigner(pkiDir string) (*signer, error) {
	key, err := loadKey[*rsa.PrivateKey](pkiDir, "signer-rsa.key.pk8", algoRSA)
	if err != nil {
		return nil, err
	}
	certDER, err := readPKI(pkiDir, "signer-rsa.cert.der")
	if err != nil {
		return nil, err
	}
	return &signer{
		certDER:   certDER,
		algoOID:   "1.2.840.113549.1.1.1", // rsaEncryption
		subjectDN: "CN=Jane Doe,serialNumber=PNONL-123",
		serial:    "PNONL-123",
		sign: func(tbs []byte) ([]byte, error) {
			return rsa.SignPKCS1v15(nil, key, crypto.SHA256, tbs)
		},
	}, nil
}

// ecSigner loads signer-ec and signs ECDSA P-256, returning the raw 64-byte r‖s (each scalar
// big-endian, left-padded to 32 bytes) — the CSC-v2 wire form, NOT a DER ECDSA-Sig-Value.
func ecSigner(pkiDir string) (*signer, error) {
	key, err := loadKey[*ecdsa.PrivateKey](pkiDir, "signer-ec.key.pk8", algoECDSA)
	if err != nil {
		return nil, err
	}
	certDER, err := readPKI(pkiDir, "signer-ec.cert.der")
	if err != nil {
		return nil, err
	}
	return &signer{
		certDER:   certDER,
		algoOID:   "1.2.840.10045.2.1", // id-ecPublicKey
		subjectDN: "CN=John Roe,serialNumber=PNONL-456",
		serial:    "PNONL-456",
		sign: func(tbs []byte) ([]byte, error) {
			r, s, err := ecdsa.Sign(rand.Reader, key, tbs)
			if err != nil {
				return nil, err
			}
			return rawRS(r, s), nil
		},
	}, nil
}

// rawRS encodes (r, s) as the fixed-width 64-byte r‖s P-256 signature: each scalar big-endian,
// left-padded to 32 bytes. FillBytes left-pads into a fixed slice (and panics if a scalar somehow
// exceeded 32 bytes, which cannot happen for P-256) — exactly the CSC-v2 wire encoding.
func rawRS(r, s *big.Int) []byte {
	out := make([]byte, 2*p256ScalarLen)
	r.FillBytes(out[:p256ScalarLen])
	s.FillBytes(out[p256ScalarLen:])
	return out
}

// readPKI reads a file from the PKI fixtures directory.
func readPKI(pkiDir, name string) ([]byte, error) {
	//nolint:gosec // G304: fixture filename is an internal constant under REFMOCK_FIXTURES_DIR, never request input.
	return os.ReadFile(filepath.Join(pkiDir, name))
}

// loadKey reads a PKCS#8 private key and type-asserts it to the expected concrete key type.
func loadKey[T any](pkiDir, name, label string) (T, error) {
	var zero T
	der, err := readPKI(pkiDir, name)
	if err != nil {
		return zero, fmt.Errorf("read %s key: %w", label, err)
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return zero, fmt.Errorf("parse %s key: %w", label, err)
	}
	key, ok := keyAny.(T)
	if !ok {
		return zero, fmt.Errorf("signer key is not %s", label)
	}
	return key, nil
}

// Server holds the loaded per-route signers + fixtures and routes the mock endpoints.
type Server struct {
	pkiDir   string
	listJSON []byte
	svcToken []byte
	credSAD  []byte
	mux      *http.ServeMux
}

func readFixturesAndPKI(fixturesDir string) (*Server, []byte, error) {
	upstream := filepath.Join(fixturesDir, "upstream")
	pki := filepath.Join(fixturesDir, "pki")

	//nolint:gosec // G304: fixture filenames are internal constants under REFMOCK_FIXTURES_DIR, never request input.
	read := func(name string) ([]byte, error) { return os.ReadFile(filepath.Join(upstream, name)) }
	infoTemplate, err := read("credentials_info.json")
	if err != nil {
		return nil, nil, err
	}
	list, err := read("credentials_list.json")
	if err != nil {
		return nil, nil, err
	}
	svc, err := read("service_token.json")
	if err != nil {
		return nil, nil, err
	}
	cred, err := read("credential_token.json")
	if err != nil {
		return nil, nil, err
	}

	return &Server{pkiDir: pki, listJSON: list, svcToken: svc, credSAD: cred}, infoTemplate, nil
}

// infoFor fills the one credentials/info template from a signer (cert + key.algo OID + subject), so
// the cert and OID the credentials/info advertises always match the bytes signHash returns.
func infoFor(template []byte, s *signer) []byte {
	r := strings.NewReplacer(
		"{{key_algo_oid}}", s.algoOID,
		"{{signer_cert_b64}}", base64.StdEncoding.EncodeToString(s.certDER),
		"{{signer_subject_dn}}", s.subjectDN,
		"{{signer_serial}}", s.serial,
	)
	return []byte(r.Replace(string(template)))
}

// New builds the mock from a fixtures directory (containing upstream/ and pki/).
func New(fixturesDir string) (*Server, error) {
	s, infoTemplate, err := readFixturesAndPKI(fixturesDir)
	if err != nil {
		return nil, err
	}
	rsaSig, err := rsaSigner(s.pkiDir)
	if err != nil {
		return nil, err
	}
	ecSig, err := ecSigner(s.pkiDir)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/authorize", s.handleAuthorize)
	mux.HandleFunc("/oauth2/token", s.handleToken)
	// CSC v1 → RSA signer (signer-rsa); CSC v2 → ECDSA P-256 signer (signer-ec). Each route binds
	// its own signer + the credentials/info filled from that same signer (no drift).
	routes := map[string]*signer{"/csc/v1": rsaSig, "/csc/v2": ecSig}
	for base, sig := range routes {
		info := infoFor(infoTemplate, sig)
		mux.HandleFunc(base+"/credentials/list", s.handleList)
		mux.HandleFunc(base+"/credentials/info", serveInfo(info))
		mux.HandleFunc(base+"/signatures/signHash", signHashHandler(sig))
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
	code := codeService
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
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid token form", bodyErrorStatus(err))
		return
	}
	// Cleverbase's token contract requires client_id in the form as well as client authentication.
	// Keep the mock strict here so its credential-free flows cannot mask the documented-stub
	// integration defect this endpoint caught.
	if r.Form.Get("client_id") == "" {
		http.Error(w, "missing client_id", http.StatusBadRequest)
		return
	}
	if r.Form.Get("code") == codeCredential {
		writeRaw(w, s.credSAD)
		return
	}
	writeRaw(w, s.svcToken)
}

func (s *Server) handleList(w http.ResponseWriter, _ *http.Request) { writeRaw(w, s.listJSON) }

// serveInfo returns a handler that serves the route's pre-substituted credentials/info.
func serveInfo(info []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { writeRaw(w, info) }
}

type signHashRequest struct {
	Hash []string `json:"hash"`
}

// signHashHandler signs the submitted to-be-signed digest with the route's signer (RSA PKCS#1 v1.5
// over a SHA-256 DigestInfo on /csc/v1; raw ECDSA P-256 r‖s on /csc/v2), mirroring the SDK's
// independent-validation test. One handler, dispatched on the route's signer — no hardcoded key.
func signHashHandler(sig *signer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
		out, err := sig.sign(tbs)
		if err != nil {
			http.Error(w, "sign failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"signatures": []string{base64.StdEncoding.EncodeToString(out)}})
	}
}
