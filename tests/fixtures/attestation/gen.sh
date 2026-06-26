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

# --- Chain-validation negative anchors (RFC 5280 §6.1.3 / §6.1.4 / §4.2.1.9) -----------------------
# Two extra anchor PKIs that exercise the issued-by (CA-issues-leaf) path's RFC 5280 gates the genuine
# `ca-iaca` set cannot, because `ca-iaca` is correctly a valid, in-window CA:
#
#   expired-ca / expired-ca-leaf  — an EXPIRED issuing CA (CA:TRUE, keyCertSign) with a fixed PAST
#       validity window, whose leaf's OWN window still covers the test instants. So only the ANCHOR
#       is out of its validity window: per RFC 5280 §6.1.3 (a)(2) EVERY certificate in the path
#       (the CA included) must be valid at the time of interest, so the leaf must be REJECTED even
#       though its own window is fine. Guards the "anchor validity not enforced" fix (ChainError::AnchorExpired).
#
#   non-ca / non-ca-leaf          — a NON-CA issuer (basicConstraints CA:FALSE, keyUsage WITHOUT
#       keyCertSign) that nevertheless signs a leaf carrying its subject as issuer. Per RFC 5280
#       §6.1.4 (k)/(n) and §4.2.1.9, only a cert asserting cA=TRUE (and, if keyUsage is present,
#       keyCertSign) may act as an issuing CA, so the leaf must be REJECTED (the classic "any cert is
#       a CA" gap). Guards the CA-constraint fix (ChainError::NotACa).
#
# Fixed (deterministic, reproducible) validity windows via -not_before / -not_after so the EXPIRED
# anchor is reproducible regardless of when gen.sh runs (no "-days from now" drift).
EXPIRED_NB="20180101000000Z" # notBefore 2018-01-01
EXPIRED_NA="20190101000000Z" # notAfter  2019-01-01 — long past every test instant
LEAF_NB="20260101000000Z"    # notBefore 2026-01-01 — covers the fixtures' NOW (2026-09-01)
LEAF_NA="20270101000000Z"    # notAfter  2027-01-01

# Expired issuing CA (CA:TRUE, keyCertSign) with a PAST validity window.
genec expired-ca.key.pem
openssl req -x509 -new -key expired-ca.key.pem -sha256 \
  -not_before "${EXPIRED_NB}" -not_after "${EXPIRED_NA}" \
  -subj "/CN=Cleverbase SDK Test EXPIRED CA/O=Alkemio Test/C=NL" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out expired-ca.cert.pem
der_and_pk8 expired-ca

# Leaf issued by the expired CA, with its OWN window covering the test instants (only the CA expired).
genec expired-ca-leaf.key.pem
openssl req -new -key expired-ca-leaf.key.pem \
  -subj "/CN=Cleverbase SDK Test Leaf Of Expired CA/O=Alkemio Test/C=NL" -out expired-ca-leaf.csr
openssl x509 -req -in expired-ca-leaf.csr -CA expired-ca.cert.pem -CAkey expired-ca.key.pem \
  -CAcreateserial -sha256 -not_before "${LEAF_NB}" -not_after "${LEAF_NA}" \
  -extfile <(printf '%b' 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n') \
  -out expired-ca-leaf.cert.pem
der_and_pk8 expired-ca-leaf

# Non-CA "issuer" (CA:FALSE, keyUsage withOUT keyCertSign), in-window, that nonetheless signs a leaf.
genec non-ca.key.pem
openssl req -x509 -new -key non-ca.key.pem -sha256 \
  -not_before "${LEAF_NB}" -not_after "${LEAF_NA}" \
  -subj "/CN=Cleverbase SDK Test Non-CA Issuer/O=Alkemio Test/C=NL" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -out non-ca.cert.pem
der_and_pk8 non-ca

# Leaf "issued by" the non-CA cert (its subject is the leaf's issuer); in-window.
genec non-ca-leaf.key.pem
openssl req -new -key non-ca-leaf.key.pem \
  -subj "/CN=Cleverbase SDK Test Leaf Of Non-CA/O=Alkemio Test/C=NL" -out non-ca-leaf.csr
openssl x509 -req -in non-ca-leaf.csr -CA non-ca.cert.pem -CAkey non-ca.key.pem \
  -CAcreateserial -sha256 -not_before "${LEAF_NB}" -not_after "${LEAF_NA}" \
  -extfile <(printf '%b' 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n') \
  -out non-ca-leaf.cert.pem
der_and_pk8 non-ca-leaf

# --- Multi-tier (sub-CA) path-validation fixtures (RFC 5280 §6.1 path length > 1) -------------------
# eIDAS QTSP / EUDI issuer PKIs commonly present x5c/x5chain = [leaf, intermediate, …] where the leaf
# is issued by an intermediate sub-CA that itself chains to the trust-list-pinned root. RFC 5280 §6.1
# permits a certification path of length > 1, so the trust engine MUST build/validate the full path
# leaf → intermediate → … → a CONFIGURED ANCHOR over the SUPPLIED chain rather than only checking a
# one-hop chain, while rejecting attacker-supplied intermediates that never reach a trusted anchor.
#
# These live under a SEPARATE root (`mt-root`) ON PURPOSE: the always-on `ca-iaca` root is minted
# `pathlen:0` (it issues only end-entity leaves — the direct IACA shape every existing test depends
# on, byte-for-byte), so it cannot anchor a sub-CA. A dedicated `mt-root` with `pathlen:1` (one
# intermediate permitted, §4.2.1.9 / §6.1.4 (m)) anchors the multi-tier set additively, leaving the
# `ca-iaca` PKI and every fixture that chains to it completely unchanged.
#
#   mt-root                 self-signed root, basicConstraints critical CA:TRUE,pathlen:1 + keyCertSign.
#   mt-intermediate / mt-leaf
#       The conformant 2-tier happy path: `mt-intermediate` is a real sub-CA (critical CA:TRUE,
#       pathlen:0 + keyCertSign) ISSUED BY mt-root; `mt-leaf` is an end-entity ISSUED BY
#       mt-intermediate. The supplied chain [mt-leaf, mt-intermediate] MUST be TRUSTED against the
#       configured mt-root anchor (leaf → sub-CA → root).
#   mt-noca-intermediate / mt-noca-leaf
#       Broken hop — the intermediate is NOT a CA. `mt-noca-intermediate` is CA:FALSE (critical) yet
#       ISSUED BY mt-root; it "issues" `mt-noca-leaf`. The chain reaches the anchor by name+signature
#       but the §6.1.4 CA-constraint gate must REJECT it — guards `ChainError::NotACa` on a path.
#   mt-expired-intermediate / mt-expired-leaf
#       Broken hop — the intermediate is EXPIRED. A valid CA:TRUE sub-CA ISSUED BY mt-root but with a
#       PAST window (2018..2019); its leaf's OWN window is current. Per §6.1.3 (a)(2) every cert in
#       the path must be valid at the time of interest → REJECTED (`ChainError::AnchorExpired`).
#   attacker-ca / attacker-leaf
#       An attacker chain that does NOT reach any configured anchor. `attacker-ca` is a SELF-SIGNED CA
#       under a rogue name (it chains to neither mt-root nor ca-iaca); `attacker-leaf` is issued by
#       it. The supplied chain [attacker-leaf, attacker-ca] is internally well-formed (each hop
#       name-matches + verifies, attacker-ca is a CA) but TERMINATES at a NON-anchor, so it MUST be
#       REJECTED as untrusted — an attacker cannot manufacture trust by supplying their own
#       intermediates.
DAYS_INT=1825 # ~5y sub-CA (well inside the root window)

# Multi-tier root: pathlen:1 permits exactly ONE intermediate sub-CA beneath it.
genec mt-root.key.pem
openssl req -x509 -new -key mt-root.key.pem -sha256 -days "${DAYS_CA}" \
  -subj "/CN=Cleverbase SDK Test Multi-Tier Root/O=Alkemio Test/C=NL" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out mt-root.cert.pem
der_and_pk8 mt-root

# issue_under <stem> <subject> <ca-stem> <ext-lines> [<not_before> <not_after>]: CSR + CA-signed cert
# + DER/PKCS#8, signed by an ARBITRARY parent CA (so an intermediate can sign a leaf). With the two
# optional time args it pins a fixed validity window; otherwise it uses -days (DAYS_LEAF).
issue_under() {
  local stem="$1" subject="$2" castem="$3" exts="$4" nb="${5:-}" na="${6:-}"
  genec "${stem}.key.pem"
  openssl req -new -key "${stem}.key.pem" -subj "${subject}" -out "${stem}.csr"
  if [ -n "${nb}" ]; then
    openssl x509 -req -in "${stem}.csr" -CA "${castem}.cert.pem" -CAkey "${castem}.key.pem" \
      -CAcreateserial -sha256 -not_before "${nb}" -not_after "${na}" \
      -extfile <(printf '%b' "${exts}") -out "${stem}.cert.pem"
  else
    openssl x509 -req -in "${stem}.csr" -CA "${castem}.cert.pem" -CAkey "${castem}.key.pem" \
      -CAcreateserial -sha256 -days "${DAYS_LEAF}" \
      -extfile <(printf '%b' "${exts}") -out "${stem}.cert.pem"
  fi
  der_and_pk8 "${stem}"
}

CA_EXTS='basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n'
EE_EXTS='basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n'

# Happy 2-tier path: mt-root → mt-intermediate (sub-CA) → mt-leaf (end-entity).
issue_under mt-intermediate "/CN=Cleverbase SDK Test Multi-Tier Intermediate Sub-CA/O=Alkemio Test/C=NL" \
  mt-root "${CA_EXTS}"
issue_under mt-leaf "/CN=Cleverbase SDK Test Multi-Tier Leaf/O=Alkemio Test/C=NL" \
  mt-intermediate "${EE_EXTS}"

# Broken hop — non-CA intermediate (CA:FALSE) issued by mt-root, that "issues" a leaf.
issue_under mt-noca-intermediate "/CN=Cleverbase SDK Test Multi-Tier Non-CA Intermediate/O=Alkemio Test/C=NL" \
  mt-root 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
issue_under mt-noca-leaf "/CN=Cleverbase SDK Test Multi-Tier Leaf Of Non-CA Intermediate/O=Alkemio Test/C=NL" \
  mt-noca-intermediate "${EE_EXTS}"

# Broken hop — EXPIRED intermediate sub-CA (valid CA, past window) issued by mt-root; in-window leaf.
issue_under mt-expired-intermediate "/CN=Cleverbase SDK Test Multi-Tier Expired Intermediate/O=Alkemio Test/C=NL" \
  mt-root "${CA_EXTS}" "${EXPIRED_NB}" "${EXPIRED_NA}"
issue_under mt-expired-leaf "/CN=Cleverbase SDK Test Multi-Tier Leaf Of Expired Intermediate/O=Alkemio Test/C=NL" \
  mt-expired-intermediate "${EE_EXTS}" "${LEAF_NB}" "${LEAF_NA}"

# Attacker chain: a SELF-SIGNED rogue CA (chains to no configured anchor) that issues its own leaf.
genec attacker-ca.key.pem
openssl req -x509 -new -key attacker-ca.key.pem -sha256 -days "${DAYS_INT}" \
  -subj "/CN=Attacker Rogue Intermediate CA (NOT chained)/O=Rogue Test/C=XX" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out attacker-ca.cert.pem
der_and_pk8 attacker-ca
issue_under attacker-leaf "/CN=Attacker Leaf (issued by rogue CA)/O=Rogue Test/C=XX" \
  attacker-ca "${EE_EXTS}"

# Path-length DoS-cap fixture: a SELF-SIGNED CA with NO pathLenConstraint (CA:TRUE + keyCertSign, no
# pathlen), so it can act as the issuer of an arbitrarily long synthetic chain. Reusing this single
# self-signed CA as the issuer at every hop (subject == issuer; it signed itself) lets a test build a
# supplied chain longer than the validator's MAX_PATH_LEN that the §6.1.4 pathLenConstraint gate does
# NOT short-circuit — so the length-cap (ChainError::PathTooLong) is the gate that fires. (The bounded
# `attacker-ca` above carries pathlen:0 and would trip NotACa at depth 1, never reaching the cap.)
genec nolen-ca.key.pem
openssl req -x509 -new -key nolen-ca.key.pem -sha256 -days "${DAYS_INT}" \
  -subj "/CN=Cleverbase SDK Test Unbounded Self-Signed CA (no pathlen)/O=Rogue Test/C=XX" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out nolen-ca.cert.pem
der_and_pk8 nolen-ca
issue_under nolen-leaf "/CN=Cleverbase SDK Test Leaf Of Unbounded CA/O=Rogue Test/C=XX" \
  nolen-ca "${EE_EXTS}"

# --- Wrong leaf key-purpose fixtures (leaf EKU / key-purpose enforcement) ---------------------------
# The trust engine enforces the role/format-appropriate LEAF key purpose (ISO/IEC 18013-5:2021 Annex B
# Table B.3: an mdoc Document Signer leaf MUST carry extendedKeyUsage = id-mso-mdl-DS 1.0.18013.5.1.2;
# RFC 5280 §4.2.1.12 leaves EKU criticality at the issuer's option). A genuinely-chained-but-WRONG-
# PURPOSE leaf (a TLS serverAuth cert issued under the same trusted root) MUST be rejected even though
# it chains perfectly — closing the "right chain, wrong purpose" false-accept. These leaves are issued
# by `mt-root` (so they chain to a configured anchor by name+signature) and form a same-root trio that
# isolates the EKU gate: only the key purpose differs between the trusted and rejected leaves.
#   mt-mdoc-ds            EC P-256 DS leaf with the CORRECT mdlDS EKU → trusted as an mdoc DS.
#   mt-mdoc-ds-serverauth EC P-256 leaf with EKU = serverAuth (1.3.6.1.5.5.7.3.1), NOT id-mso-mdl-DS →
#       presented as an mdoc DS leaf it MUST be rejected (WrongLeafPurpose).
#   mt-mdoc-ds-no-eku     EC P-256 leaf with NO extendedKeyUsage at all. ISO 18013-5 Annex B makes the
#       DS EKU mandatory, so a DS leaf lacking it MUST be rejected (WrongLeafPurpose).
# (The genuine ca-iaca-rooted `mdoc-ds` fixture remains the production-shape positive case; mt-root is
# used here because its CA key is available to mint the negative variants, where ca-iaca's is not.)
EKU_SERVER_AUTH="1.3.6.1.5.5.7.3.1" # id-kp-serverAuth (TLS server) — a FOREIGN purpose for an mdoc DS.
issue_under mt-mdoc-ds "/CN=Cleverbase SDK Test Multi-Tier mdoc DS (mdlDS EKU)/O=Alkemio Test/C=NL" \
  mt-root "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,${EKU_MDL_DS}\n"
issue_under mt-mdoc-ds-serverauth "/CN=Cleverbase SDK Test Multi-Tier Wrong-EKU DS (serverAuth)/O=Alkemio Test/C=NL" \
  mt-root "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,${EKU_SERVER_AUTH}\n"
issue_under mt-mdoc-ds-no-eku "/CN=Cleverbase SDK Test Multi-Tier No-EKU DS/O=Alkemio Test/C=NL" \
  mt-root 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n'

# --- Cross-certificate / alternate-intermediate fixtures (backtracking path-walk) ------------------
# A conformant credential may carry x5c/x5chain intermediates of which SEVERAL name-match (and validly
# issue) the leaf — e.g. a cross-certified sub-CA: two certificates with the SAME subject DN and the
# SAME public key, one self-signed (a dead-end that reaches no anchor) and one issued by the configured
# root. A greedy non-backtracking walk that commits to the FIRST name-matching issuer FALSE-REJECTS the
# credential when the dead-end is tried first; a backtracking walk explores the alternate and accepts.
#
# `xc-key` is ONE EC key reused as the cross-cert sub-CA public key. The leaf is issued by it (so the
# leaf's signature verifies under EITHER cross-cert, since they share the key):
#   xc-intermediate  subject "…Cross-Cert Sub-CA", key=xc-key, CA:TRUE, ISSUED BY mt-root → reaches root.
#   xc-deadend       subject "…Cross-Cert Sub-CA" (SAME DN), key=xc-key, CA:TRUE, but ISSUED BY the rogue
#                    `attacker-ca` (a DIFFERENT issuer DN, NOT supplied and NOT a configured anchor) →
#                    a genuine dead-end: nothing in the supplied set or anchors matches its issuer DN.
#   xc-leaf          end-entity issued by the xc-key sub-CA (its issuer DN is the shared sub-CA subject).
# Supplied as [xc-leaf, xc-deadend, xc-intermediate], only the BACKTRACKING walk reaches mt-root: a
# greedy walk that commits to xc-deadend (a valid issuer of xc-leaf) dead-ends and FALSE-REJECTS.
XC_SUBJECT="/CN=Cleverbase SDK Test Cross-Cert Sub-CA/O=Alkemio Test/C=NL"
genec xc-key.key.pem
# xc-intermediate: the shared-key sub-CA, issued by mt-root (reaches the configured root).
openssl req -new -key xc-key.key.pem -subj "${XC_SUBJECT}" -out xc-intermediate.csr
openssl x509 -req -in xc-intermediate.csr -CA mt-root.cert.pem -CAkey mt-root.key.pem -CAcreateserial \
  -sha256 -days "${DAYS_INT}" \
  -extfile <(printf '%b' "${CA_EXTS}") -out xc-intermediate.cert.pem
der_and_pk8 xc-intermediate
# xc-deadend: the SAME subject + SAME key, but ISSUED BY the rogue attacker-ca (a different issuer DN
# that is neither supplied nor a configured anchor) → a genuine dead-end branch.
openssl req -new -key xc-key.key.pem -subj "${XC_SUBJECT}" -out xc-deadend.csr
openssl x509 -req -in xc-deadend.csr -CA attacker-ca.cert.pem -CAkey attacker-ca.key.pem -CAcreateserial \
  -sha256 -days "${DAYS_INT}" \
  -extfile <(printf '%b' "${CA_EXTS}") -out xc-deadend.cert.pem
der_and_pk8 xc-deadend
# xc-leaf: an end-entity whose issuer is the shared sub-CA subject; its signature verifies under xc-key.
# Issue it under xc-intermediate (which holds xc-key) so the issuer DN is the shared sub-CA subject.
genec xc-leaf.key.pem
openssl req -new -key xc-leaf.key.pem \
  -subj "/CN=Cleverbase SDK Test Cross-Cert Leaf/O=Alkemio Test/C=NL" -out xc-leaf.csr
openssl x509 -req -in xc-leaf.csr -CA xc-intermediate.cert.pem -CAkey xc-key.key.pem -CAcreateserial \
  -sha256 -days "${DAYS_LEAF}" \
  -extfile <(printf '%b' "${EE_EXTS}") -out xc-leaf.cert.pem
der_and_pk8 xc-leaf

# --- Self-issued (key-rollover) intermediate fixtures (RFC 5280 §6.1.4 (l) / §4.2.1.9) -------------
# A self-issued certificate (subject DN == issuer DN, e.g. a CA's key-rollover cert) is NOT counted
# toward pathLenConstraint ("the maximum number of NON-SELF-ISSUED intermediate certificates that may
# follow this certificate", §4.2.1.9). A path that includes a self-issued rollover cert mid-chain MUST
# therefore be accepted even when counting it would exceed the issuing root's pathlen.
#
#   si-root      self-signed root, basicConstraints critical CA:TRUE,pathlen:1 (≤1 NON-self-issued
#                intermediate may follow) + keyCertSign.
#   si-rollover  a KEY-ROLLOVER cert: subject DN == issuer DN == si-root's DN (SELF-ISSUED), carrying a
#                NEW key, but SIGNED BY si-root's old key (so it chains to si-root). CA:TRUE. Being
#                self-issued it does NOT consume pathLen budget.
#   si-subca     a real (NON-self-issued) sub-CA issued by si-rollover (using the new key). CA:TRUE.
#   si-leaf      end-entity issued by si-subca.
# Path si-leaf → si-subca → si-rollover → si-root: the ONLY non-self-issued intermediate following
# si-root is si-subca (si-rollover is self-issued, excluded), so pathlen:1 is satisfied. Counting the
# rollover would make it 2 > 1 → a (wrong) PathTooLong/NotACa reject. This fixture guards that.
SI_ROOT_SUBJECT="/CN=Cleverbase SDK Test Self-Issued Rollover Root/O=Alkemio Test/C=NL"
genec si-root.key.pem
openssl req -x509 -new -key si-root.key.pem -sha256 -days "${DAYS_CA}" \
  -subj "${SI_ROOT_SUBJECT}" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out si-root.cert.pem
der_and_pk8 si-root
# si-rollover: a NEW key, subject == si-root's DN, signed by si-root (issuer == si-root's DN) → the
# issuer and subject DNs are identical ⇒ SELF-ISSUED. CA:TRUE so it may issue the next sub-CA.
genec si-rollover.key.pem
openssl req -new -key si-rollover.key.pem -subj "${SI_ROOT_SUBJECT}" -out si-rollover.csr
openssl x509 -req -in si-rollover.csr -CA si-root.cert.pem -CAkey si-root.key.pem -CAcreateserial \
  -sha256 -days "${DAYS_INT}" \
  -extfile <(printf '%b' "${CA_EXTS}") -out si-rollover.cert.pem
der_and_pk8 si-rollover
# si-subca: a real non-self-issued sub-CA issued BY si-rollover (signed with the new rollover key).
genec si-subca.key.pem
openssl req -new -key si-subca.key.pem \
  -subj "/CN=Cleverbase SDK Test Self-Issued Path Sub-CA/O=Alkemio Test/C=NL" -out si-subca.csr
openssl x509 -req -in si-subca.csr -CA si-rollover.cert.pem -CAkey si-rollover.key.pem -CAcreateserial \
  -sha256 -days "${DAYS_INT}" \
  -extfile <(printf '%b' "${CA_EXTS}") -out si-subca.cert.pem
der_and_pk8 si-subca
issue_under si-leaf "/CN=Cleverbase SDK Test Self-Issued Path Leaf/O=Alkemio Test/C=NL" \
  si-subca "${EE_EXTS}"

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
# is SYNTHETIC and OFFLINE: the list is SIGNED by the IACA root (signerCertDerB64 = ca-iaca), which is
# ALSO the scheme-operator trust anchor the gate authenticates the list against. Before reading any
# status the gate chain-validates the signer against the scheme anchor (here ca-iaca signs/IS the
# signer, a direct DER-equal pin) and rejects a stale list (now >= nextUpdate); a forged/unsigned/
# unchained/stale list yields the honest Indeterminate, never Qualified (SC-007). It lists:
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
  expired-ca.*     EXPIRED issuing CA (CA:TRUE, keyCertSign; past validity window) for the chain
  expired-ca-leaf.*  leaf issued by expired-ca whose OWN window is current (anchor-validity reject path)
  non-ca.*         NON-CA issuer (CA:FALSE, no keyCertSign) for the "any cert is a CA" reject path
  non-ca-leaf.*    leaf issued by non-ca (CA-constraint reject path)
  mt-root.*        independent multi-tier root (CA:TRUE,pathlen:1) anchoring the sub-CA path fixtures
  mt-intermediate.*  sub-CA issued by mt-root (critical CA:TRUE + keyCertSign) — multi-tier path
  mt-leaf.*        end-entity issued by mt-intermediate (2-tier happy path: leaf→sub-CA→root)
  mt-noca-intermediate.*  CA:FALSE "intermediate" issued by mt-root (multi-tier NotACa reject path)
  mt-noca-leaf.*   leaf issued by the non-CA intermediate
  mt-expired-intermediate.*  EXPIRED sub-CA issued by mt-root (multi-tier AnchorExpired reject path)
  mt-expired-leaf.*  leaf (in-window) issued by the expired intermediate
  attacker-ca.*    self-signed rogue CA that chains to no configured anchor (attacker-intermediate)
  attacker-leaf.*  leaf issued by attacker-ca (supplied chain terminates at a non-anchor → untrusted)
  nolen-ca.*       self-signed CA with NO pathLenConstraint (path-length DoS-cap / PathTooLong fixture)
  nolen-leaf.*     leaf issued by nolen-ca
  mt-mdoc-ds.*     mt-root-issued mdoc DS leaf WITH the correct mdlDS EKU (1.0.18013.5.1.2) — purpose OK
  mt-mdoc-ds-serverauth.*  mt-root-issued leaf with a FOREIGN serverAuth EKU (wrong mdoc DS purpose)
  mt-mdoc-ds-no-eku.*  mt-root-issued leaf with NO EKU (mandatory mdoc DS EKU missing → wrong purpose)
  xc-key.*         the EC key SHARED by the two cross-certificates below (one committed pk8)
  xc-intermediate.* cross-cert sub-CA (subject S, key xc-key) issued by mt-root → reaches the anchor
  xc-deadend.*     cross-cert sub-CA (SAME subject S + key) issued by the rogue attacker-ca → dead-end
  xc-leaf.*        end-entity issued by the shared sub-CA (both cross-certs validly issue it → backtrack)
  si-root.*        self-signed root (pathlen:1) for the self-issued key-rollover path fixtures
  si-rollover.*    SELF-ISSUED key-rollover cert (subject DN == issuer DN, pathlen:1) signed by si-root
  si-subca.*       the one NON-self-issued sub-CA (issued by si-rollover) — the only pathLen-counted hop
  si-leaf.*        end-entity issued by si-subca (path validates only when the rollover is NOT counted)
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

# The negative anchors are valid OpenSSL signatures (the SDK's RFC 5280 §6.1.3/§6.1.4 gates, not the
# signature math, are what reject them), so confirm the signatures themselves are sound: expired-ca-leaf
# is signed by expired-ca, and non-ca-leaf by non-ca. `openssl verify` rejects expired-ca (expired) and
# non-ca (CA:FALSE) as issuers — exactly the conditions the SDK gates — so verify only the leaf/issuer
# signature linkage with `-no_check_time -partial_chain` to assert the chain is otherwise structurally sound.
openssl verify -no_check_time -partial_chain -CAfile expired-ca.cert.der expired-ca-leaf.cert.der
echo "non-ca / non-ca-leaf: signature linkage minted (rejected by the SDK's CA-constraint gate, by design)"

# Multi-tier (sub-CA) path: the conformant 2-tier chain MUST verify with the intermediate supplied as
# an untrusted path-building cert (-untrusted) against the mt-root — leaf → intermediate → root.
openssl verify -CAfile mt-root.cert.der -untrusted mt-intermediate.cert.der mt-leaf.cert.der
# The attacker chain MUST NOT verify against mt-root even with its own intermediate supplied (it
# terminates at a self-signed rogue CA that is not the configured anchor).
if openssl verify -CAfile mt-root.cert.der -untrusted attacker-ca.cert.der attacker-leaf.cert.der >/dev/null 2>&1; then
  echo "ERROR: attacker chain unexpectedly verified against mt-root — fixture is broken." >&2
  exit 1
fi
echo "attacker-leaf [+ attacker-ca]: correctly REJECTED against mt-root.cert.der (expected)"
echo "mt-{noca,expired}-intermediate: multi-tier broken-hop linkage minted (rejected by the SDK gates, by design)"

# Leaf key-purpose trio: all three chain to mt-root by name+signature (only the EKU differs — the SDK's
# leaf-purpose gate distinguishes them, not the signature math, so verify the chains are sound).
openssl verify -CAfile mt-root.cert.der mt-mdoc-ds.cert.der
openssl verify -CAfile mt-root.cert.der mt-mdoc-ds-serverauth.cert.der
openssl verify -CAfile mt-root.cert.der mt-mdoc-ds-no-eku.cert.der
echo "mt-mdoc-ds{,-serverauth,-no-eku}: chains sound; EKU purpose distinguished by the SDK (by design)"
# Cross-cert backtracking: the leaf verifies via xc-intermediate (reaches mt-root); xc-deadend (same
# subject+key, issued by the rogue attacker-ca) does NOT reach the anchor.
openssl verify -CAfile mt-root.cert.der -untrusted xc-intermediate.cert.der xc-leaf.cert.der
if openssl verify -CAfile mt-root.cert.der -untrusted xc-deadend.cert.der xc-leaf.cert.der >/dev/null 2>&1; then
  echo "ERROR: xc-leaf unexpectedly verified via xc-deadend — backtracking fixture is broken." >&2
  exit 1
fi
echo "xc-leaf: verifies via xc-intermediate→mt-root; the xc-deadend cross-cert is a true dead-end (expected)"
# Self-issued rollover path: si-leaf → si-subca → si-rollover (self-issued) → si-root validates only
# because the self-issued rollover is NOT counted toward si-root's pathlen:1 (RFC 5280 §6.1.4 (l)).
openssl verify -CAfile si-root.cert.der -untrusted <(cat si-rollover.cert.der si-subca.cert.der) si-leaf.cert.der
echo "si-leaf: self-issued rollover excluded from pathLen, path validates (RFC 5280 §6.1.4 (l)) (expected)"

# --- drop transient working files ------------------------------------------------------------------
# The tests load only the DER certs + PKCS#8 keys (+ the JSON/JWK/YAML/Kotlin material); the CSRs and
# the openssl serial byproduct add churn without test value, so remove them from the output set. The
# *.pem / *.key working files stay on disk but are dropped by the repo .gitignore.
rm -f -- *.csr ca-iaca.cert.srl

echo
echo "OK: minted ca-iaca / sdjwt-issuer / mdoc-ds / holder / wrong-issuer + trust-list.json + qualified-trust-list.json."
echo "Committed forms: *.cert.der + *.key.pk8 (+ trust-list.json, qualified-trust-list.json, holder.jwk.json, NOTICE)."
echo "Transient (gitignored / removed) working files: *.pem, *.key, *.csr, *.srl — not tracked."
