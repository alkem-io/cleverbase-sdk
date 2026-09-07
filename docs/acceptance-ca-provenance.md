# Cleverbase acceptance certificate provenance

This record captures certificate material published by Cleverbase for its acceptance
environment. It does **not** promote an observed certificate to a trust anchor: no CA certificate
is committed to this repository, and the SDK's integrity verifier does not perform chain or
revocation validation. Cleverbase must confirm the acceptance CA fingerprint before an operator
uses the reconstructed bundle as `TRUST_GATEWAY_E2E_CA_BUNDLE`.

Observed on 2026-09-07 from Cleverbase's
[Qualifications and certificates](https://cleverbase.com/en/legal/qualifications/) page.

## Published test certificates

| Purpose | HTTPS source | ZIP SHA-256 | Leaf SHA-256 fingerprint | Serial | Validity (UTC) |
|---|---|---|---|---|---|
| Authentication | [authentication-x509-test.zip](https://cleverbase.com/content/legal/certificates/authentication-x509-test.zip) | `4cca162217d6f410c995ae47d0bb9c1b8e3e35cfa23464f2f53368e4fc0d5181` | `57:76:4E:28:01:F3:BC:D8:44:72:42:17:02:D8:05:3A:FA:01:D2:2A:B1:47:BA:F2:59:1E:64:97:1B:92:F6:DC` | `9DBC636AC58CF5646D6A9351D1830B84` | 2024-03-26 13:39:14 to 2027-03-26 13:53:44 |
| Content commitment | [content-commitment-x509-test.zip](https://cleverbase.com/content/legal/certificates/content-commitment-x509-test.zip) | `90138836601a81b4afcf9235f0eb86245bb5ca22e00c0d5b7b0c095754c16fc3` | `0A:92:E4:B0:86:93:B9:FE:79:18:1C:19:BC:A6:8B:62:43:00:B1:A6:7D:A4:D5:D5:E2:DE:06:3C:6E:7F:D5:DB` | `9E0B0052E2CFFBD40EC8EF14DBBE2354` | 2024-03-26 13:40:13 to 2027-03-26 13:56:08 |

Both leaves have subject
`SN=for testing purposes, GN=Cleverbase, C=NL, CN=Cleverbase for testing purposes, serialNumber=HB-a0b2ab9e-60e7-4c3a-832e-04859d851aa4`
and issuer `ACC Cleverbase ID PKIoverheid Burger CA - G3`. Their Authority Information Access
extension points to `http://pki.acc.cleverbase.com/CleverbaseBurgerG3.cer`.

The certificate retrieved from that AIA URL was self-signed, had `CA:TRUE`, and had:

- subject and issuer:
  `C=NL, O=Cleverbase ID B.V., organizationIdentifier=NTRNL-67419925, CN=ACC Cleverbase ID PKIoverheid Burger CA - G3`;
- serial: `F0495BE0B240BE91`;
- validity: 2018-03-02 09:05:35 to 2038-03-02 09:05:35 UTC;
- DER SHA-256 and certificate fingerprint:
  `26:FC:21:FE:73:E6:F7:E3:D4:27:13:6B:A6:B9:9B:FB:FF:D6:A0:89:1B:99:A3:05:93:A0:9A:A6:68:3D:4F:93`.

Both published leaves verify cryptographically against that certificate. This proves their chain
relationship only; it does not independently establish the CA as trusted or qualified.

## Reconstruct and inspect an external bundle

Run this in a temporary directory. The AIA transport is HTTP, so the pinned digest is mandatory;
do not update it by trust-on-first-use.

```bash
work_dir="$(mktemp -d)"
cd "$work_dir"

curl --fail --show-error --location --proto '=https' --proto-redir '=https' \
  --output authentication-x509-test.zip \
  https://cleverbase.com/content/legal/certificates/authentication-x509-test.zip
curl --fail --show-error --location --proto '=https' --proto-redir '=https' \
  --output content-commitment-x509-test.zip \
  https://cleverbase.com/content/legal/certificates/content-commitment-x509-test.zip

printf '%s  %s\n' \
  4cca162217d6f410c995ae47d0bb9c1b8e3e35cfa23464f2f53368e4fc0d5181 \
  authentication-x509-test.zip \
  90138836601a81b4afcf9235f0eb86245bb5ca22e00c0d5b7b0c095754c16fc3 \
  content-commitment-x509-test.zip | shasum -a 256 --check

unzip authentication-x509-test.zip
unzip content-commitment-x509-test.zip

curl --fail --show-error --location \
  --output CleverbaseBurgerG3.cer \
  http://pki.acc.cleverbase.com/CleverbaseBurgerG3.cer
printf '%s  %s\n' \
  26fc21fe73e6f7e3d427136ba6b99bfbffd6a0891b99a30593a09aa6683d4f93 \
  CleverbaseBurgerG3.cer | shasum -a 256 --check

openssl x509 -inform DER -in CleverbaseBurgerG3.cer -out cleverbase-acceptance-ca.pem
openssl verify -CAfile cleverbase-acceptance-ca.pem authentication-x509-test.crt
openssl verify -CAfile cleverbase-acceptance-ca.pem content-commitment-x509-test.crt

install -d -m 0700 "$HOME/.config/trust-gateway"
install -m 0600 cleverbase-acceptance-ca.pem \
  "$HOME/.config/trust-gateway/cleverbase-acceptance-ca.pem"
```

Before a real acceptance run, compare the signing certificate chain embedded in the resulting PDF
with this record and ask Cleverbase to confirm the observed CA fingerprint. A different chain must
be investigated and recorded; it must not be silently added to the bundle.

## Cleverbase hash-signing stub is a different hierarchy

The checked-in hash-signing stub leaf is documented in
[`crates/cleverbase-core/tests/fixtures/README.md`](../crates/cleverbase-core/tests/fixtures/README.md).
It has issuer `TEST Cleverbase ID PKIoverheid Burger CA - G3`, while the certificate currently
served by its AIA URL identifies itself as `TST Cleverbase ID PKIoverheid Burger CA - G3`; the leaf
does not verify against that fetched certificate. The stub material is a contract-test fixture and
must not be used as an acceptance trust anchor.
