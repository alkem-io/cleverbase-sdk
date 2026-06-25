#!/usr/bin/env bash
#
# Reproducible recipe for the synthetic test PKI used by the SDK's independent-validation tests and
# the reference-integration mock upstream.
#
# This is a RECIPE, not part of the test run: it is never invoked by `cargo test` / `go test`, and it
# does NOT overwrite the already-committed fixtures unless you explicitly run it in this directory.
# Regenerating churns every `include_bytes!` (Rust) / `os.ReadFile` (Go) consumer, so only run it
# when the PKI material genuinely needs to be rotated.
#
# It produces, with the EXACT existing filenames the consumers depend on:
#   ca.{key.pem,cert.pem,cert.der}                          self-signed test root
#   signer-rsa.{key.pem,key.pk8,csr,cert.pem,cert.der}      RSA-2048 leaf, CSR signed by the CA
#   signer-ec.{key.pem,key.pk8,csr,cert.pem,cert.der}       prime256v1 (P-256) leaf, signed by the CA
#   tsa.{key.pem,key.pk8,cert.pem,cert.der}                 RFC 3161 TSA (RSA, EKU=timeStamping)
#
# Side-files (per contracts/algorithm-fixtures.md §3 / A1):
#   tsa.cnf            committed openssl `ts` INPUT config — consumed, never regenerated here.
#   ca.cert.srl        transient openssl serial byproduct of `x509 -CA` — not part of the output set.
#   tsa_serial.txt     transient openssl `ts` serial byproduct — not part of the output set.
#
# Both signer certs MUST chain to the CA: `openssl verify -CAfile ca.cert.der signer-*.cert.der` OK.
#
# Usage:  cd tests/fixtures/pki && ./gen.sh
set -euo pipefail
cd "$(dirname "$0")"

DAYS_CA=3650   # ~10y root
DAYS_LEAF=825  # ~27mo leaves (matches the committed validity window length)

# --- helpers ---------------------------------------------------------------------------------------

# der_and_pk8 <stem>: derive the DER cert + the PKCS#8 (.pk8) private key the consumers load, from a
# generated <stem>.cert.pem + <stem>.key.pem.
der_and_pk8() {
  local stem="$1"
  openssl x509 -in "${stem}.cert.pem" -outform DER -out "${stem}.cert.der"
  openssl pkcs8 -topk8 -nocrypt -in "${stem}.key.pem" -outform DER -out "${stem}.key.pk8"
}

# --- CA (self-signed root) -------------------------------------------------------------------------

openssl genrsa -out ca.key.pem 2048
openssl req -x509 -new -key ca.key.pem -sha256 -days "${DAYS_CA}" \
  -subj "/CN=Cleverbase SDK Test CA/O=Alkemio Test" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -out ca.cert.pem
openssl x509 -in ca.cert.pem -outform DER -out ca.cert.der

# leaf_cert <stem> <subject> <keygen-cmd...>: generate a key (via the given keygen command into
# <stem>.key.pem), a CSR, then a CA-signed leaf cert, and the DER/PKCS#8 derivations.
leaf_cert() {
  local stem="$1" subject="$2"
  shift 2
  "$@" # keygen: writes ${stem}.key.pem
  openssl req -new -key "${stem}.key.pem" -subj "${subject}" -out "${stem}.csr"
  openssl x509 -req -in "${stem}.csr" -CA ca.cert.pem -CAkey ca.key.pem -CAcreateserial \
    -sha256 -days "${DAYS_LEAF}" \
    -extfile <(printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,nonRepudiation\n') \
    -out "${stem}.cert.pem"
  der_and_pk8 "${stem}"
}

# --- RSA signer (signer-rsa) -----------------------------------------------------------------------
leaf_cert signer-rsa "/CN=Jane Doe/serialNumber=PNONL-123" \
  openssl genrsa -out signer-rsa.key.pem 2048

# --- ECDSA P-256 signer (signer-ec) ----------------------------------------------------------------
leaf_cert signer-ec "/CN=John Roe/serialNumber=PNONL-456" \
  openssl ecparam -name prime256v1 -genkey -noout -out signer-ec.key.pem

# --- RFC 3161 TSA (tsa) ----------------------------------------------------------------------------
# RSA key + a CA-signed cert carrying a critical Extended Key Usage of timeStamping (id-kp-timeStamping).
openssl genrsa -out tsa.key.pem 2048
openssl req -new -key tsa.key.pem -subj "/CN=Cleverbase SDK Test TSA" -out tsa.csr
openssl x509 -req -in tsa.csr -CA ca.cert.pem -CAkey ca.key.pem -CAcreateserial \
  -sha256 -days "${DAYS_LEAF}" \
  -extfile <(printf 'basicConstraints=CA:FALSE\nextendedKeyUsage=critical,timeStamping\n') \
  -out tsa.cert.pem
der_and_pk8 tsa
rm -f tsa.csr # the TSA CSR is not part of the committed set

# --- verify the chains -----------------------------------------------------------------------------
openssl verify -CAfile ca.cert.der signer-rsa.cert.der
openssl verify -CAfile ca.cert.der signer-ec.cert.der
openssl verify -CAfile ca.cert.der tsa.cert.der

echo "OK: regenerated ca / signer-rsa / signer-ec / tsa; both signer certs chain to the CA."
echo "Note: tsa.cnf is a committed INPUT (kept); ca.cert.srl + tsa_serial.txt are transient byproducts."
