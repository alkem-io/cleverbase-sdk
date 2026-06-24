package mock

import (
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

// openssl flags reused across the DER→PEM materialization steps.
const (
	flagInform = "-inform"
	flagIn     = "-in"
	flagOut    = "-out"
	formatDER  = "DER"
)

// tsaConfig is an openssl `ts` configuration referencing PEMs materialized into the work dir.
const tsaConfig = `[tsa]
default_tsa = tsa_config1
[tsa_config1]
serial = serial
crypto_device = builtin
signer_cert = tsa.cert.pem
certs = ca.cert.pem
signer_key = tsa.key.pem
default_policy = 1.3.6.1.4.1.99999.1.1
signer_digest = sha256
digests = sha256, sha384, sha512
accuracy = secs:1
clock_precision_digits = 0
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
`

// handleTSA issues an RFC 3161 timestamp for B-T by driving `openssl ts -reply` with the synthetic
// TSA PKI (materialized per-request from the committed DER/PKCS#8 into a temp dir, as the SDK test
// does). Requires `openssl` on PATH.
func (s *Server) handleTSA(w http.ResponseWriter, r *http.Request) {
	reqDER, err := io.ReadAll(r.Body)
	if err != nil || len(reqDER) == 0 {
		http.Error(w, "empty timestamp request", http.StatusBadRequest)
		return
	}
	work, err := os.MkdirTemp("", "mocktsa")
	if err != nil {
		http.Error(w, "tsa temp", http.StatusInternalServerError)
		return
	}
	defer func() { _ = os.RemoveAll(work) }()

	ctx := r.Context()
	der2pem := func(args ...string) error { return exec.CommandContext(ctx, "openssl", args...).Run() }
	steps := [][]string{
		{"x509", flagInform, formatDER, flagIn, filepath.Join(s.pkiDir, "tsa.cert.der"), flagOut, filepath.Join(work, "tsa.cert.pem")},
		{"x509", flagInform, formatDER, flagIn, filepath.Join(s.pkiDir, "ca.cert.der"), flagOut, filepath.Join(work, "ca.cert.pem")},
		{"pkey", flagInform, formatDER, flagIn, filepath.Join(s.pkiDir, "tsa.key.pk8"), flagOut, filepath.Join(work, "tsa.key.pem")},
	}
	for _, st := range steps {
		if err := der2pem(st...); err != nil {
			http.Error(w, "tsa materialize: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if err := os.WriteFile(filepath.Join(work, "serial"), []byte("0A"), 0o600); err != nil {
		http.Error(w, "tsa serial", http.StatusInternalServerError)
		return
	}
	if err := os.WriteFile(filepath.Join(work, "tsa.cnf"), []byte(tsaConfig), 0o600); err != nil {
		http.Error(w, "tsa cnf", http.StatusInternalServerError)
		return
	}
	if err := os.WriteFile(filepath.Join(work, "req.tsq"), reqDER, 0o600); err != nil {
		http.Error(w, "tsa query", http.StatusInternalServerError)
		return
	}
	cmd := exec.CommandContext(ctx, "openssl", "ts", "-reply", "-config", "tsa.cnf", "-queryfile", "req.tsq", flagOut, "resp.tsr")
	cmd.Dir = work
	if out, err := cmd.CombinedOutput(); err != nil {
		http.Error(w, "openssl ts -reply: "+string(out), http.StatusInternalServerError)
		return
	}
	resp, err := os.ReadFile(filepath.Join(work, "resp.tsr"))
	if err != nil {
		http.Error(w, "tsa read reply", http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/timestamp-reply")
	_, _ = w.Write(resp)
}
