# Contract: algorithm-parametrized fixtures + mock multi-signer

How the test/reference layer makes **signature algorithm a parameter** without RSA/ECDSA copy-paste
(FR-004). Three coordinated pieces, one source of truth per algorithm.

## 1. Mock multi-signer (`mock-upstream/mock/server.go`)

Replace the single `rsaKey *rsa.PrivateKey` with per-CSC-route signers:

```go
type signer struct {
    keyAlgo  string            // "RSA" | "EcdsaP256"
    certDER  []byte            // signer-<algo>.cert.der
    algoOID  string            // credentials/info key.algo OID
    sign     func(tbs []byte) ([]byte, error) // RSA PKCS1v15(SHA256) | P-256 -> raw r‖s
}
// /csc/v1 -> RSA signer (signer-rsa), /csc/v2 -> EC signer (signer-ec)
```

**Contract**:
- `handleSignHash` dispatches on the route's `signer.sign`, never a hardcoded key.
- ECDSA `sign` returns the **raw 64-byte `r‖s`** (the real CSC-v2 wire form) — the core's
  `ecdsa_signature_to_der` normalizes it; this exercises that path end-to-end.
- The cert + `algo` OID the matching `credentials/info` advertises and the bytes `signHash` returns come
  from the **same** `signer` (no drift).
- The TSA stays a separate RSA authority — untouched.

## 2. credentials_info template — per-route substitution (`tests/fixtures/upstream/`)

One `credentials/info` **template** is filled per route with the selected signer's cert + `algo` OID so the
core detects the right `KeyAlgo`:

| Route | `key.algo` OID | cert |
|-------|----------------|------|
| RSA (v1) | `1.2.840.113549.1.1.1` | `signer-rsa.cert.der` |
| ECDSA (v2) | `1.2.840.10045.2.1` (id-ecPublicKey) | `signer-ec.cert.der` |

**Contract**: the mock fills the **one** `credentials/info` template per route from the selected `signer`'s
cert + `algo` OID (per-route substitution) — a **single template**, no two hand-maintained copies (the
consistent phrasing used in data-model.md and research.md).

## 3. Reproducible PKI (`tests/fixtures/pki/gen.sh` — new)

**Contract**: regenerates, deterministically, with the **exact existing filenames** (Go `os.ReadFile` +
Rust `include_bytes!` depend on them):
- `ca.{key.pem,cert.pem,cert.der}` — self-signed test root.
- `signer-rsa.{key.pem,key.pk8,csr,cert.pem,cert.der}` — RSA-2048, CSR signed by CA.
- `signer-ec.{key.pem,key.pk8,csr,cert.pem,cert.der}` — `prime256v1`, CSR signed by CA.
- `tsa.{key.pem,key.pk8,cert.pem,cert.der}` — RFC 3161 TSA (RSA), signed by CA.
- both signer certs MUST `openssl verify -CAfile ca.cert.der` OK.

**Side-files (A1)**: `tsa.cnf` is a committed openssl `ts` **input config** the recipe consumes (kept, not
generated). `ca.cert.srl` / `tsa_serial.txt` are **transient openssl serial byproducts** (re-created during
signing); they are NOT part of the reproducible output set and the recipe need not reproduce them
byte-for-byte. So "exact existing filenames" applies to the `ca/signer-*/tsa` key+cert material above, not
the serial/config side-files.

## Affected tests (must fail first, then pass)

- `mock/server_test.go`: assert the **route's** expected algorithm (v1→RSA, v2→ECDSA), replacing the
  hardcoded RSA assertion; verify an EC `signHash` response with `ecdsa.VerifyASN1`/raw-r‖s as appropriate.
- `e2e/credfree_test.go`: `TestCredentialFree{BB,BT}` become a table over `{v1_rsa, v2_ecdsa}`; `validateCMS`
  + `assertTimestampToken` reused **unchanged** (algorithm-agnostic OpenSSL).
- `crates/cleverbase-core/tests/independent_validation.rs`: `produce_signed_pdf`/`drive_bt_to_timestamp`/
  `upstream_fixture` parametrized over `KeyAlgo`; new ECDSA B-B + B-T arms; OpenSSL verify/timestamp reused.

## Invariants

- No RSA/ECDSA twin code anywhere (FR-004): one `signer` type, one `credentials_info` template, one
  parametrized producer per harness.
- RSA behaviour + existing RSA validation unchanged (FR-005, SC-002).
</content>
