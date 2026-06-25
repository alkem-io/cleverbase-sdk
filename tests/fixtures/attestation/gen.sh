#!/usr/bin/env bash
#
# Reproducible recipe for the SYNTHETIC test PKI + trust material used by the EUDI attestation
# verification tests (SD-JWT VC verifier, mdoc verifier, trust-list engine — feature 004, task T003,
# research D9 "Tier B backbone"). It mints a small, fully OFFLINE test PKI and a minimal test
# trust-list anchor that T009/T013 verify against.
#
# This is a RECIPE, not part of the test run: it is never invoked by `cargo test`, and running it
# regenerates (and overwrites) the committed fixtures in this directory. Regenerating churns every
# `include_bytes!` consumer, so only run it when the test material genuinely needs to be rotated.
#
# CONSTRAINTS
#   * ONLY synthetic test material — no real keys, no real secrets, no network (SC-003 offline).
#   * Mirrors tests/fixtures/pki/gen.sh exactly for how material is committed under the repo
#     `.gitignore` (which ignores *.pem / *.key globally): the durable, tracked fixtures are the DER
#     certs (*.cert.der) and PKCS#8 keys (*.key.pk8); the *.pem / *.csr files this script writes are
#     transient working files that the .gitignore drops (the tests load the DER/PKCS#8 forms).
#
# IT PRODUCES (stable filenames the consumers depend on):
#
#   Trust roots
#     ca-iaca.{key.pem,key.pk8,cert.pem,cert.der}   self-signed test CA / ISO 18013-5 IACA root (EC P-256)
#
#   Signers issued by the root (the trusted happy path)
#     sdjwt-issuer.{key.pem,key.pk8,csr,cert.pem,cert.der}
#                                                   SD-JWT VC issuer EC P-256 leaf (JOSE ES256), CA-signed
#     mdoc-ds.{key.pem,key.pk8,csr,cert.pem,cert.der}
#                                                   mdoc Document Signer EC P-256 leaf (COSE ES256),
#                                                   IACA-signed, EKU = id-mso-mdl-DS (1.0.18013.5.1.2)
#
#   Holder key (no cert — holder binding / KB-JWT / DeviceAuth in later tests)
#     holder.{key.pem,key.pk8,pub.pem,jwk.json}     EC P-256 holder key + its public JWK
#
#   Negative / untrusted material (does NOT chain to the root — for the wrong-issuer reject path)
#     wrong-issuer.{key.pem,key.pk8,cert.pem,cert.der}
#                                                   self-signed EC P-256 issuer NOT chained to ca-iaca
#
#   Minimal test trust-list anchor (so the trust engine T009/T013 has something to anchor against)
#     trust-list.json                               JSON manifest: per-role/format trusted anchors
#                                                   (base64 DER) + a NextUpdate, mirrors what the
#                                                   native engine's configured test anchor consumes
#
#   NOTICE                                          attribution for the vendored Tier A vectors + this PKI
#
# EVERY signer cert MUST chain to ca-iaca; the wrong-issuer cert MUST NOT:
#   openssl verify -CAfile ca-iaca.cert.der sdjwt-issuer.cert.der  -> OK
#   openssl verify -CAfile ca-iaca.cert.der mdoc-ds.cert.der       -> OK
#   openssl verify -CAfile ca-iaca.cert.der wrong-issuer.cert.der  -> FAILS (self-signed, not chained)
#
# Usage:  cd tests/fixtures/attestation && ./gen.sh
set -euo pipefail
cd "$(dirname "$0")"

DAYS_CA=3650    # ~10y IACA root
DAYS_LEAF=455   # ~15mo signer certs (ISO 18013-5 Annex B caps an mdoc DS at 457 days)

# ISO/IEC 18013-5 mdoc Document Signer extended-key-usage OID (id-mso-mdl-DS).
EKU_MDL_DS="1.0.18013.5.1.2"

# --- helpers ---------------------------------------------------------------------------------------

# der_and_pk8 <stem>: derive the committed DER cert + PKCS#8 (.pk8) key the tests load, from a
# generated <stem>.cert.pem + <stem>.key.pem.
der_and_pk8() {
  local stem="$1"
  openssl x509 -in "${stem}.cert.pem" -outform DER -out "${stem}.cert.der"
  openssl pkcs8 -topk8 -nocrypt -in "${stem}.key.pem" -outform DER -out "${stem}.key.pk8"
}

# genec <out.key.pem>: generate an EC P-256 (prime256v1) private key.
genec() { openssl ecparam -name prime256v1 -genkey -noout -out "$1"; }

# --- CA / IACA root (self-signed, EC P-256) --------------------------------------------------------
# An ISO 18013-5 Annex-B-shaped IACA root: CA:TRUE, keyCertSign + cRLSign, with a CRL distribution
# point. Doubles as the SD-JWT VC issuing root (one test root keeps the fixture set small).
genec ca-iaca.key.pem
openssl req -x509 -new -key ca-iaca.key.pem -sha256 -days "${DAYS_CA}" \
  -subj "/CN=Cleverbase SDK Test IACA Root/O=Alkemio Test/C=NL" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "crlDistributionPoints=URI:https://test.invalid/iaca.crl" \
  -out ca-iaca.cert.pem
openssl x509 -in ca-iaca.cert.pem -outform DER -out ca-iaca.cert.der

# leaf_cert <stem> <subject> <ext-lines>: EC P-256 key + CSR + CA-signed leaf + DER/PKCS#8 forms.
leaf_cert() {
  local stem="$1" subject="$2" exts="$3"
  genec "${stem}.key.pem"
  openssl req -new -key "${stem}.key.pem" -subj "${subject}" -out "${stem}.csr"
  openssl x509 -req -in "${stem}.csr" -CA ca-iaca.cert.pem -CAkey ca-iaca.key.pem -CAcreateserial \
    -sha256 -days "${DAYS_LEAF}" \
    -extfile <(printf '%b' "${exts}") \
    -out "${stem}.cert.pem"
  der_and_pk8 "${stem}"
}

# --- SD-JWT VC issuer (ES256 over JOSE) ------------------------------------------------------------
leaf_cert sdjwt-issuer "/CN=Cleverbase SDK Test SD-JWT VC Issuer/O=Alkemio Test/C=NL" \
  'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n'

# --- mdoc Document Signer (ES256 over COSE; ISO 18013-5 §B.1.7) ------------------------------------
leaf_cert mdoc-ds "/CN=Cleverbase SDK Test mdoc Document Signer/O=Alkemio Test/C=NL" \
  "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,${EKU_MDL_DS}\n"

# --- Holder key (no certificate; used for holder binding / KB-JWT / DeviceAuth) --------------------
genec holder.key.pem
openssl pkcs8 -topk8 -nocrypt -in holder.key.pem -outform DER -out holder.key.pk8
openssl ec -in holder.key.pem -pubout -out holder.pub.pem 2>/dev/null

# Emit the holder PUBLIC key as a P-256 JWK (kty/crv/x/y, base64url, no padding) — the form the
# SD-JWT VC `cnf` / OpenID4VCI proof / mdoc DeviceKey consumers bind against. Public material only.
# Pure-openssl: the uncompressed P-256 point is 65 bytes (0x04 || X[32] || Y[32]); slice X and Y out
# of the hex dump and base64url-encode each — no language runtime needed.
holder_jwk() {
  local hex x_hex y_hex x_b64u y_b64u
  # `EC -text` prints the public point as hex octets under "pub:"; flatten to one hex string.
  hex="$(openssl ec -in holder.key.pem -noout -text 2>/dev/null \
    | awk '/pub:/{f=1;next} /ASN1 OID|NIST CURVE|Private-Key/{f=0} f' \
    | tr -dc '0-9a-f')"
  # Drop the leading 04 (uncompressed-point marker); X = next 32 bytes, Y = final 32 bytes.
  x_hex="${hex:2:64}"
  y_hex="${hex:66:64}"
  # hex -> raw -> base64url (strip padding, +/ -> -_).
  x_b64u="$(printf '%s' "${x_hex}" | xxd -r -p | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
  y_b64u="$(printf '%s' "${y_hex}" | xxd -r -p | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
  cat > holder.jwk.json <<JWK
{
  "kty": "EC",
  "crv": "P-256",
  "x": "${x_b64u}",
  "y": "${y_b64u}"
}
JWK
  echo "holder JWK: {\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"${x_b64u}\",\"y\":\"${y_b64u}\"}"
}
holder_jwk

# --- Wrong / untrusted issuer (self-signed; NOT chained to the root) -------------------------------
# Same shape as the real SD-JWT VC issuer leaf but self-signed under its own key, so it is a valid
# certificate that simply does NOT chain to ca-iaca — the wrong-issuer / untrusted negative path.
genec wrong-issuer.key.pem
openssl req -x509 -new -key wrong-issuer.key.pem -sha256 -days "${DAYS_LEAF}" \
  -subj "/CN=Untrusted Test Issuer (NOT chained)/O=Rogue Test/C=XX" \
  -addext "basicConstraints=CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -out wrong-issuer.cert.pem
der_and_pk8 wrong-issuer

# --- Minimal test trust-list anchor (JSON manifest for T009/T013) ----------------------------------
# The native EU trust-list engine (T013) fetches/authenticates signed TS 119 612 XML in production;
# for the OFFLINE suite the configured test anchor (StaticTestAnchors) is seeded from this manifest:
# per (role, format) it lists the trusted anchor certificate(s) as base64 DER, plus a NextUpdate so
# the stale-list (past NextUpdate -> fail-closed) case has a value to exercise. The wrong-issuer is
# deliberately absent so the negative path resolves to Untrusted.
B64_IACA="$(openssl base64 -A -in ca-iaca.cert.der)"
NEXT_UPDATE="$(date -u -v+3650d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null \
  || date -u -d '+3650 days' '+%Y-%m-%dT%H:%M:%SZ')"
cat > trust-list.json <<JSON
{
  "schema": "cleverbase-sdk/test-trust-list/v1",
  "comment": "SYNTHETIC offline test trust anchor for feature 004 (T009/T013). NOT a real EU LOTL/TL.",
  "nextUpdate": "${NEXT_UPDATE}",
  "anchors": [
    {
      "role": "Pid",
      "format": "SdJwtVc",
      "serviceName": "Cleverbase SDK Test PID Provider (SD-JWT VC)",
      "anchorCertDerB64": "${B64_IACA}"
    },
    {
      "role": "Qeaa",
      "format": "SdJwtVc",
      "serviceName": "Cleverbase SDK Test QEAA Issuer (SD-JWT VC)",
      "anchorCertDerB64": "${B64_IACA}"
    },
    {
      "role": "Pid",
      "format": "Mdoc",
      "serviceName": "Cleverbase SDK Test IACA (mdoc)",
      "anchorCertDerB64": "${B64_IACA}"
    }
  ]
}
JSON

# --- Minimal test qualified-status Trusted List (JSON, for the opt-in gate T018/T019) --------------
# The opt-in eIDAS qualified-status determination (TS 119 615 v1.4.1 cl. 4.12) needs a national
# Trusted List whose EAA/Q services carry a per-service status HISTORY so the gate can read the
# granted/withdrawn status AT the relevant time (the credential's issuance time, not "now"). This is
# the JSON counterpart of a signed TS 119 612 national TL; the SDK's qualified module parses it. It
# is SYNTHETIC and OFFLINE: the list is "signed" by the IACA root (signerCertDerB64), and it lists:
#   * sdjwt-issuer  as an EAA/Q service, GRANTED from 2020-01-01 (qualified at the test instants);
#   * mdoc-ds       as an EAA/Q service, GRANTED then WITHDRAWN on 2025-09-01 (status-at-time matters);
#   * ca-iaca       as a plain EAA (NON-qualified) service — a trusted-but-not-qualified issuer.
# A signing cert absent from every service yields the honest Indeterminate (no false "qualified").
B64_SDJWT="$(openssl base64 -A -in sdjwt-issuer.cert.der)"
B64_MDOC_DS="$(openssl base64 -A -in mdoc-ds.cert.der)"
SVCTYPE_EAA_Q="http://uri.etsi.org/TrstSvc/Svctype/EAA/Q"
SVCTYPE_EAA="http://uri.etsi.org/TrstSvc/Svctype/EAA"
SVCSTATUS_GRANTED="http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
SVCSTATUS_WITHDRAWN="http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn"
cat > qualified-trust-list.json <<JSON
{
  "schema": "cleverbase-sdk/test-qualified-trust-list/v1",
  "comment": "SYNTHETIC offline test qualified-status (TS 119 615 v1.4.1 cl. 4.12 / TS 119 612) national Trusted List for feature 004 (T018/T019). NOT a real EU national TL.",
  "nextUpdate": "${NEXT_UPDATE}",
  "signerCertDerB64": "${B64_IACA}",
  "services": [
    {
      "serviceName": "Cleverbase SDK Test QEAA Issuer (EAA/Q, granted)",
      "serviceTypeIdentifier": "${SVCTYPE_EAA_Q}",
      "signingCertDerB64": "${B64_SDJWT}",
      "statusHistory": [
        { "status": "${SVCSTATUS_GRANTED}", "startingTime": "2020-01-01T00:00:00Z" }
      ]
    },
    {
      "serviceName": "Cleverbase SDK Test QEAA Issuer (EAA/Q, granted then withdrawn)",
      "serviceTypeIdentifier": "${SVCTYPE_EAA_Q}",
      "signingCertDerB64": "${B64_MDOC_DS}",
      "statusHistory": [
        { "status": "${SVCSTATUS_GRANTED}", "startingTime": "2020-01-01T00:00:00Z" },
        { "status": "${SVCSTATUS_WITHDRAWN}", "startingTime": "2025-09-01T00:00:00Z" }
      ]
    },
    {
      "serviceName": "Cleverbase SDK Test Non-Qualified EAA Issuer (EAA, no /Q)",
      "serviceTypeIdentifier": "${SVCTYPE_EAA}",
      "signingCertDerB64": "${B64_IACA}",
      "statusHistory": [
        { "status": "${SVCSTATUS_GRANTED}", "startingTime": "2020-01-01T00:00:00Z" }
      ]
    }
  ]
}
JSON

# --- NOTICE ----------------------------------------------------------------------------------------
cat > NOTICE <<'NOTICE'
Cleverbase SDK — EUDI attestation test fixtures (feature 004)
=============================================================

ALL key material in this directory is SYNTHETIC and generated solely for tests by `gen.sh`.
It contains NO real keys, NO real secrets, and is NOT for any production use.

Tier B — self-generated test backbone (this directory, minted by gen.sh)
------------------------------------------------------------------------
  ca-iaca.*        self-signed test CA / ISO 18013-5 IACA root (EC P-256)
  sdjwt-issuer.*   SD-JWT VC issuer leaf (JOSE ES256), issued by ca-iaca
  mdoc-ds.*        mdoc Document Signer leaf (COSE ES256, EKU id-mso-mdl-DS), issued by ca-iaca
  holder.*         EC P-256 holder key (+ public JWK) for holder binding / KB-JWT / DeviceAuth
  wrong-issuer.*   self-signed issuer that does NOT chain to ca-iaca (wrong-issuer negative path)
  trust-list.json  minimal per-role/format test trust anchor for the trust-list engine (T009/T013)
  qualified-trust-list.json
                   minimal national Trusted List with EAA/Q services + per-service status history
                   for the opt-in qualified-status gate (TS 119 615 cl.4.12 — T018/T019)

Tier A — vendored upstream conformance vectors (vectors/, see vectors/README.md)
--------------------------------------------------------------------------------
  vectors/sd-jwt-vc/arf-pid-specification.yml
  vectors/sd-jwt-vc/ietf-examples-settings.yml
      Source: IETF oauth-wg/oauth-sd-jwt-vc, examples/03-pid + examples/settings.yml.
      The arf-pid SD-JWT VC conformance example INPUTS (the rendered SD-JWT is reproduced
      deterministically from these with random_seed:0). IETF Trust Legal Provisions (BCP 78/79);
      code components under the Simplified BSD License (TLP §4). Upstream commits only the YAML
      inputs (rendered outputs are .gitignore'd upstream), so these inputs are the vendored form.

  vectors/mdoc/multipaz-TestVectors.kt
      Source: OpenWallet Foundation `multipaz` (org.multipaz.mdoc.TestVectors), originally
      The Android Open Source Project. Licensed under the Apache License, Version 2.0.
      The ISO/IEC 18013-5 Annex-D worked-example mdoc vectors (DeviceResponse, MSO, etc.).
NOTICE

# --- verify the chains -----------------------------------------------------------------------------
echo "--- chain verification ---"
openssl verify -CAfile ca-iaca.cert.der sdjwt-issuer.cert.der
openssl verify -CAfile ca-iaca.cert.der mdoc-ds.cert.der
# The wrong-issuer MUST NOT verify against the root (negative path). `openssl verify` exits non-zero;
# assert that and print the outcome rather than aborting the script under `set -e`.
if openssl verify -CAfile ca-iaca.cert.der wrong-issuer.cert.der >/dev/null 2>&1; then
  echo "ERROR: wrong-issuer.cert.der unexpectedly verified against ca-iaca — fixture is broken." >&2
  exit 1
fi
echo "wrong-issuer.cert.der: correctly REJECTED against ca-iaca.cert.der (expected)"

# --- drop transient working files ------------------------------------------------------------------
# The tests load only the DER certs + PKCS#8 keys (+ the JSON/JWK/YAML/Kotlin material); the CSRs and
# the openssl serial byproduct add churn without test value, so remove them from the output set. The
# *.pem / *.key working files stay on disk but are dropped by the repo .gitignore.
rm -f -- *.csr ca-iaca.cert.srl

echo
echo "OK: minted ca-iaca / sdjwt-issuer / mdoc-ds / holder / wrong-issuer + trust-list.json + qualified-trust-list.json."
echo "Committed forms: *.cert.der + *.key.pk8 (+ trust-list.json, qualified-trust-list.json, holder.jwk.json, NOTICE)."
echo "Transient (gitignored / removed) working files: *.pem, *.key, *.csr, *.srl — not tracked."
