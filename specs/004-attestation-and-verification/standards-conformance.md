# Standards conformance + version-pinning audit (T032, FR-010)

This is the conformance-traceability home FR-010 requires (Constitution Principle II/VII): for every
governing standard it records the **targeted version** and the **demonstrating module/test** in the
`cleverbase-attestation` crate. It also pins the third-party crate versions the format/trust layers
build on, and (as the Polish-phase record) carries the T031 DRY review and the T034 quickstart
results.

The crate is intentionally a **standalone, sans-IO core** (it does not depend on `cleverbase-core`):
verification is standards-based and Cleverbase-independent. See `docs/limitations.md` and
`examples/reference-integration/README.md` for the honest Cleverbase-reality note (FR-011/SC-006).

## 1. Standards traceability matrix (FR-010)

Each row maps a governing standard → its targeted version → the task that implements it → the
module/tests that demonstrate conformance. "Module" paths are under `crates/cleverbase-attestation/`.
Test names are the in-crate `#[cfg(test)]` cases (run with `cargo test -p cleverbase-attestation`).

| Standard | Targeted version | Task | Demonstrating module | Representative tests |
|----------|------------------|------|----------------------|----------------------|
| **eIDAS** — Regulation (EU) 910/2014 **as amended by (EU) 2024/1183** (the qualified/(Q)EAA + per-role trust framing: PID Art. 5a(18), PuB-EAA Art. 45f(3)) | Consolidated 2024/1183 | T013, T019 | `src/trust/`, `src/qualified/` | `qualified::tests::qualified_issuer_granted_at_the_relevant_time_is_qualified`, `qualified::tests::trusted_but_non_qualified_issuer_is_not_qualified` |
| **SD-JWT VC** — `draft-ietf-oauth-sd-jwt-vc` + **SD-JWT** RFC 9901 | draft-16 / RFC 9901 | T011 | `src/sdjwtvc/` | `sdjwtvc::tests::valid_credential_from_trusted_issuer_is_accepted_with_disclosed_attributes`, `selective_disclosure_reveals_only_the_presented_subset`, `tampered_issuer_signature_is_rejected_as_tamper` |
| **ISO/IEC 18013-5** — mdoc (`DeviceResponse`, MSO `valueDigests`/`validityInfo`, `DeviceAuth`) | 18013-5:2021 | T012 | `src/mdoc/` | `mdoc::tests::valid_mdoc_verifies_and_returns_disclosed_attributes`, `value_digest_mismatch_is_rejected_as_disclosure_integrity`, `expired_validity_info_is_rejected_as_expired` |
| **OpenID4VP** — request build (DCQL + fresh nonce + audience) + `vp_token` binding verify + **in-core DCQL satisfaction** (§6 + §"VP Token Validation" 2.2/3) | 1.0 (DCQL) | T015 | `src/openid4vp/`, `src/dcql.rs` | `openid4vp::tests::build_request_draws_a_fresh_nonce_each_call`, `sd_jwt_bound_to_the_issued_request_is_valid`, `sd_jwt_replayed_with_a_stale_nonce_is_replay`, `sd_jwt_of_the_wrong_vct_is_query_not_satisfied`, `verify_vp_token_required_set_satisfied_by_one_option`, `dcql::tests::*` |
| **OpenID4VCI** — pre-authorized-code `obtain` (sans-IO state machine + signer-hook PoP) | **1.0 final** (see §1.3) | T025 | `src/issuance/obtain.rs`, `src/issuance/signer.rs` | `issuance::obtain::tests::*` (skip-when-`None`, reference round-trip, `proofs` array, Nonce-Endpoint, `credentials` array, `tx_code`, deferred-202), `issuance::signer::tests::*` |
| **ETSI TS 119 612** — Trusted Lists (LOTL / national TL, TLv6) | v2.4.1 / TLv6 | T013 | `src/trust/xml.rs`, `src/trust/engine.rs`, `src/trust/chain.rs` | `trust::engine::tests::*` (present/absent/expired-entry/unreachable→fail-closed/stale→fail-closed), `trust::xml::tests::*`, `trust::chain::tests::*` |
| **ETSI TS 119 602** — Lists of Trusted Entities (LoTE) data model the TL reader follows | v1.x | T013 | `src/trust/xml.rs`, `src/trust/manifest.rs` | `trust::xml::tests::*`, `trust::manifest::tests::*` |
| **ETSI TS 119 615** — qualified-status determination, **cl. 4.12** | v1.4.1 (`qualified::TS_119_615_VERSION = "1.4.1"`) | T019 | `src/qualified/` | `qualified::tests::the_implementation_is_pinned_to_ts_119_615_v1_4_1`, `issuer_absent_from_the_trust_list_is_indeterminate`, `withdrawn_eaa_q_is_qualified_before_and_not_qualified_after_the_withdrawal` |

Notes:

- The **qualified gate (TS 119 615 cl. 4.12)** is **opt-in, experimental, version-pinned** (cl. 4.12
  is pre-operational): off by default via `VerifyContext::qualified_gate`; enabling/disabling it never
  changes the always-on verdict (SC-007). The pinned constant is asserted by
  `the_implementation_is_pinned_to_ts_119_615_v1_4_1` so a silent version drift fails the suite.
- **ES256** (ECDSA / P-256 / SHA-256) is the EUDI mandatory baseline (HAIP 1.0 §7); both the
  SD-JWT VC issuer/KB-JWT JOSE signatures and the mdoc COSE signatures are verified over it.
- **EU DSS** is a **test-only** parity oracle for the trust-list engine, never a runtime/build dep.

### 1.1 Leaf key-purpose policy (X.509 path validation — `src/trust/chain.rs`)

`verify_chain` enforces the role/format-appropriate **leaf key purpose** on the credential's signing
certificate (the `LeafPurpose` parameter), so a genuinely-chained-but-WRONG-PURPOSE leaf is rejected
(closing the "right chain, wrong purpose" false-accept — e.g. a TLS `serverAuth` cert issued under the
same trusted root, or an mdoc-DS cert presented as the SD-JWT VC issuer leaf). The purpose is threaded
from the credential's `Format` **and `IssuerRole`** by `resolve_chain` (the SD-JWT VC issuer's per-role
QcStatement requirement is keyed by the role); the trust-list-signer authentication paths
(`trust::xml`, `qualified`) pass `TrustListSigner`, which imposes no credential-leaf purpose (a TL
signer is governed by a separate ETSI profile).

| Leaf role/format | Enforced leaf-purpose rule | Standard (verified online) |
|------------------|----------------------------|----------------------------|
| **mdoc Document Signer** (`Format::Mdoc`) | The full **Table B.3 DS-leaf profile**: (a) `extendedKeyUsage` MUST be present and contain `id-mso-mdl-DS` = **`1.0.18013.5.1.2`** (row `m`; criticality **not** required per RFC 5280 §4.2.1.12 / ISO row `m`, not `mc`); (b) `keyUsage` MUST assert **`digitalSignature`** (row `mc`); (c) `basicConstraints` MUST be **`cA=FALSE`** (row `mc`). Absent/foreign EKU (e.g. only `serverAuth`), a `keyUsage` lacking `digitalSignature`, or `cA=TRUE` is rejected (`WrongLeafPurpose`) — so a DS leaf can no longer double as an issuing CA. | **ISO/IEC 18013-5:2021 Annex B, Table B.3** (mDL document signer certificate; keyUsage & basicConstraints rows `mc`). OID cross-checked at the OID registry; reference-verifier cross-check (auth0-lab/mdl, spruceid/isomdl). Criticality per **RFC 5280 §4.2.1.12**. |
| **SD-JWT VC issuer** (`Format::SdJwtVc`, keyed by `IssuerRole`) | **No EKU is mandated by any governing spec.** Two layered checks: **(1) base floor (every role)** — the leaf **MUST NOT be a CA** (`basicConstraints cA=TRUE` ⇒ rejected) and `keyUsage` **MUST be present** and assert a signing bit (`digitalSignature` or `nonRepudiation`/content-commitment). ETSI EN 319 412-2 §4.3.2 (`NAT-4.3.2-1`) / EN 319 412-3 §4.3.1 (`LEG-4.3.1-2`) make keyUsage **SHALL-present** and a content/seal-signing cert Type A/B/F (all carry a signing bit), so an **absent** keyUsage is now rejected (tightened from the prior "absent allowed"). **(2) per-role eIDAS QcStatement** (`qcStatements` ext `1.3.6.1.5.5.7.1.3`, non-critical): **PID** → `QcType` with `id-etsi-qct-pid` **`0.4.0.194126.1.1`** (TS 119 412-6 PID-4.5-01); **QEAA** → `QcCompliance` **`0.4.0.1862.1.1`** + `QcType` `id-etsi-qct-esign`/`-eseal` **`0.4.0.1862.1.6.{1,2}`** (EN 319 412-5 §4.2 + TS 119 412-6 QEA-7.1); **PuB-EAA** → `QcPSB` **`0.4.0.1862.1.10`** (PSB-8.3-01); **NonQualifiedEAA** → no Qc requirement. This is the in-band guard closing the chain-to-root false-trust where a plain eSeal/EAA cert sharing a QTSP root would be trusted as PID/QEAA (audit **T1.3**). | IETF **`draft-ietf-oauth-sd-jwt-vc`** §2.5 + **RFC 9901** (silent on EKU/keyUsage); **OpenID4VC HAIP 1.0** §6.1.1 (chain-to-anchor only); **ETSI EN 319 412-2** §4.3.2 / **EN 319 412-3** §4.3.1 (keyUsage SHALL-present, Types A/B/F; §4.3.10 forbids critical EKU); **EN 319 412-5** §4.2 + **TS 119 412-6** V1.1.1 Annex A (QcStatement OIDs, verified online). |
| **Trust-list signer** (`TrustListSigner`) | No credential-leaf key-purpose constraint (the signer is authenticated solely by chaining to a configured scheme-operator anchor). | n/a — TL signer governed by a separate ETSI profile, not the credential-leaf profiles above. |

Fail-closed throughout: a malformed or duplicate `extendedKeyUsage` / `keyUsage` / `basicConstraints` /
`qcStatements` extension is rejected (a leaf whose purpose cannot be decoded is not trusted to act in
that role), using `x509-cert`'s typed `ExtendedKeyUsage` / `KeyUsage` / `BasicConstraints` decoders and
a `der`-typed `QCStatement` (`SEQUENCE { statementId OID, statementInfo ANY }`) decode — no hand-rolled
ASN.1.

Source URLs: ISO 18013-5 DS profile (Table B.3) — https://www.iso.org/standard/69084.html (DS EKU
`1.0.18013.5.1.2`, https://oid-base.com/get/1.0.18013.5.1.2); RFC 5280 §4.2.1.9 (pathLenConstraint
"non-self-issued"), §4.2.1.12 (EKU criticality), §6.1 (self-issued = subject DN == issuer DN), §6.1.4
(l) (self-issued not counted toward path length) — https://www.rfc-editor.org/rfc/rfc5280; SD-JWT VC
§2.5 — https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-16.html; HAIP 1.0 §6.1.1 —
https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html; ETSI TS 119 412-6
/ EN 319 412-2 — https://www.etsi.org/deliver/etsi_ts/119400_119499/11941206/.

### 1.2 Certification-path validation hardening (RFC 5280 §6.1 — `src/trust/chain.rs`)

`verify_chain` walks the supplied `x5c`/`x5chain` to a configured anchor as a **bounded, backtracking
depth-first search**: when several supplied intermediates name-match (and validly issue) the current
certificate — a cross-certificate or an alternate sub-CA — each is tried in turn and a dead-end branch
is unwound so an alternate is explored. A conformant credential that reaches a configured anchor via
**some** valid path is therefore accepted (no false-reject from a greedy first-match commit). Two path
counters are threaded distinctly per **RFC 5280**: `pathLenConstraint` counts only **non-self-issued**
intermediates (§4.2.1.9 / §6.1.4 (l): a self-issued — subject DN == issuer DN — key-rollover cert "is
not counted when evaluating path length"), while the `MAX_PATH_LEN` denial-of-service cap (the leaf plus
up to **8** promoted intermediates; the terminating anchor is the §6.1.1 trust-anchor input and is not a
hop) counts every hop (so a self-issued-cert flood cannot evade it). Source:
https://www.rfc-editor.org/rfc/rfc5280 §4.2.1.9, §6.1, §6.1.4.

Beyond name-chaining/signature/validity/CA-constraint, `verify_chain` now enforces (all verified online
against RFC 5280, sources below):

- **Unrecognized critical extensions are rejected** (§6.1.4 (o) / §6.1.5 (f); §4.2 / §6 "a
  certificate-using system MUST reject the certificate if it encounters a critical extension it does not
  recognize"). After the typed checks, every **processed** certificate (the leaf + each intermediate;
  **not** the trust anchor, a §6.1.1 input) is scanned and rejected (`UnsupportedCriticalExtension`) if it
  carries a critical extension whose OID the validator does not process. The recognized critical set is
  `basicConstraints`, `keyUsage`, `extendedKeyUsage`, `nameConstraints`, `subjectAltName`. (Closes audit
  **T1.1** — previously a critical `nameConstraints`/unknown OID was silently accepted.)
- **Name constraints are processed** (§4.2.1.10, §6.1.3 (b)(c), §6.1.4 (g)). Once a path reaches an
  anchor, the certificates are walked top-down building `permitted_subtrees` (intersected per CA) and
  `excluded_subtrees` (unioned); each non-self-issued certificate's subject DN and `subjectAltName` must
  lie within all permitted and outside all excluded subtrees (self-issued non-final certs are skipped per
  §6.1.3 (b)(c)). `directoryName` (binary-prefix RDN match per §7.1) and `dNSName` (add-labels-on-the-left
  per §4.2.1.10) subtrees are enforced; a constraint on any other `GeneralName` form, or a non-default
  `minimum`/`maximum` `BaseDistance`, is treated as unsupported and **fails closed**
  (`NameConstraintViolation`). Typed `x509-cert::ext::pkix::NameConstraints` decoding (no hand-rolled
  ASN.1). (Closes audit **T1.2** — a CA scoping a sub-CA's namespace is no longer ignored.)
- **Inner/outer signatureAlgorithm consistency** (§4.1.1.2 / §4.1.2.3): each processed certificate's outer
  `signatureAlgorithm` MUST equal its inner `tbsCertificate.signature` AlgorithmIdentifier (the unsigned
  outer field must not be substituted); a mismatch is `SignatureAlgorithmMismatch`. (Closes audit
  **T1.7**.)

### 1.2.1 DS-certificate validity at the MSO signing time (ISO/IEC 18013-5 §9.3.1 — the trust seam)

`verify_chain` (and `TrustAnchorSource::resolve` / `resolve_chain`) take an optional
**`leaf_validity_time`**: the instant the **leaf's own** validity window is checked at, while the rest of
the chain authentication (intermediates → anchor validity, name constraints, …) stays at `now_unix`. The
mdoc verifier passes `Some(mso.validityInfo.signed)` so the **Document Signer** certificate's window is
checked against the MSO signing time per **ISO/IEC 18013-5 §9.3.1**, not "now" — DS certs rotate
(~monthly) while mDLs live for years, so checking the DS window at `now` would **false-reject** a
conformant mDL once its DS cert expired (audit **T3.1**, the one HIGH false-reject). SD-JWT VC issuer and
trust-list-signer paths pass `None` (the leaf is checked at `now`, as before). Cross-checked online
against auth0-lab/mdl `Verifier.ts`, which checks the DS window against `validityInfo.signed` and the
MSO's own `validFrom`/`validUntil` against the verification clock separately.

Sources: RFC 5280 §4.1.1.2/§4.1.2.3, §4.2.1.9 (basicConstraints "MUST … mark this extension as critical"
is the **issuance** requirement of §4.2.1.9, distinct from the §6.1.4 (k) validation-side CA check),
§4.2.1.10, §6.1.3, §6.1.4, §6.1.5, §7.1 — https://www.rfc-editor.org/rfc/rfc5280; ISO/IEC 18013-5 §9.3.1
— https://www.iso.org/standard/69084.html (DS-vs-`signed` rule cross-checked at
https://github.com/auth0-lab/mdl `src/mdoc/Verifier.ts`).

### 1.3 OpenID4VCI **1.0 final** wire alignment + scope cuts (`src/issuance/obtain.rs`)

The gated `obtain` path (default `IssuerBackend::None`; Cleverbase ships no issuer API today) is
implemented against **OpenID4VCI 1.0 final** — verified online against the normative text, not training
data: the published spec
(<https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>) and the
`openid/OpenID4VCI` source `1.0/openid-4-verifiable-credential-issuance-1_0.md`. 1.0 made three breaking
changes over the early `~draft-13` shapes this code originally tracked; all three are now implemented
(closing conformance-audit Theme 8 T8.1–T8.3):

| 1.0 requirement (§ref + anchor) | Old draft-13 shape | Implemented 1.0 shape |
|---------------------------------|--------------------|-----------------------|
| **Credential Request** — §8.2 `#credential-request`: "`proofs` ... contains exactly one parameter named as the proof type ... the value set for this parameter is a **non-empty array**" | singular `proof: { proof_type:"jwt", jwt:<string> }` | `proofs: { jwt: [<jwt>] }`; the `proof_type` field is gone (`credential_request`) |
| **Nonce Endpoint** — §7 `#nonce-endpoint` / §7.2 `#nonce-response`: a dedicated endpoint returns a fresh `c_nonce`; the Token Response no longer carries one | `c_nonce` read from the Token Response | unauthenticated `POST {nonce_endpoint}` (empty body) → `{ "c_nonce": … }`, performed **before** building the PoP; `nonce_endpoint` added to `IssuerBackend` (`nonce_request`/`parse_nonce_response`, `NoncePending` phase) |
| **Credential Response** — §8.3 `#credential-response`: "`credentials` ... an array ... The elements of the array MUST be objects ... `credential`: REQUIRED" | top-level `credential` string | `credentials[0].credential` (string SD-JWT VC, or base64url mdoc CBOR) (`parse_credential_response`) |

The PoP-JWT itself was already conformant with **§F.1 `#jwt-proof-type`** (`typ:openid4vci-proof+jwt`,
`alg:ES256`, public-only `jwk` header, `aud`=Credential Issuer Identifier, `iat`, `iss` omitted for the
anonymous pre-authorized-code flow); only the `nonce` **source** changed (now the Nonce Endpoint). Per
§F.1 the `nonce` claim "MUST be present when the issuer has a Nonce Endpoint", which this path always
drives.

Also implemented (T8.4, partial):

- **`tx_code`** (§6.1 `#token-request`): when the offer carries a `tx_code` object, the End-User-supplied
  Transaction Code is sent in the Token Request ("This value MUST be present if a `tx_code` object was
  present in the Credential Offer"). Modeled as `CredentialOffer.tx_code: Option<Secret>` (a redacting
  `Secret`, never in `Debug`/log output — FR-010); percent-encoded into the form body when present.
- **Deferred (HTTP 202) detection** (§8.3): a deferred Credential Response (status 202 and/or a
  `transaction_id`) is surfaced as a distinct `ObtainError::Deferred` terminal failure rather than
  mis-parsed as a malformed body — non-silent, never a false accept. Polling the **Deferred Credential
  Endpoint** itself (§9 `#deferred-credential-issuance`) is a scope cut (below).

**Stated OpenID4VCI scope cuts** (record, don't silently omit — closing the audit's "docs claim plain
1.0" gap):

- **`credential_identifier` / `authorization_details` request path** (§8.2; §6.1.1 Token Response
  `credential_identifiers`). This path always sends `credential_configuration_id` and **never**
  `credential_identifier`, satisfying §8.2's mutual-exclusion MUST ("When this parameter is used, the
  `credential_identifier` MUST NOT be present") by construction. The full `authorization_details`
  negotiation (multi-configuration offers) is **out of scope** for the gated forward-looking path; the
  pre-authorized-code + `credential_configuration_id` flow is what the EUDI reference issuer uses.
- **Deferred Credential Endpoint** (§9 `#deferred-credential-issuance`): the deferred-issuance polling
  loop (`transaction_id` → `POST {deferred_endpoint}` → `interval` backoff) is **out of scope**; a
  deferred (202) response is detected and surfaced as the explicit `ObtainError::Deferred` failure
  rather than supported.
- **`token_type` / DPoP** (§6.1 `#token-response`; [@RFC9449]): the access token is used as a plain
  `Bearer` (the EUDI baseline / reference issuer). DPoP-bound tokens and the DPoP nonce are **out of
  scope**.
- **Encrypted Credential Requests/Responses** (§10 `#encrypted-messages`,
  `credential_response_encryption`) and **`notification_id`/Notification Endpoint** (§11) are **out of
  scope** (the integrator-supplied transport is plain JSON over the host's TLS).

These cuts keep the *implemented* flow interop-correct with a real 1.0 issuer (and the in-test double,
which speaks the 1.0 shapes); the deferred / `authorization_details` legs are reasoned omissions, not
silent gaps.

### 1.4 In-core DCQL satisfaction + credential-role derivation (OpenID4VP 1.0 §6 — `src/dcql.rs`)

The OpenID4VP DCQL query is parsed and evaluated **in-core** (verified online against the 1.0 spec
<https://openid.net/specs/openid-4-verifiable-presentations-1_0.html> and the `openid/OpenID4VP` source
`1.0/openid-4-verifiable-presentations-1_0.md`) — not carried opaquely and not delegated to the wallet
(§"Security Checks on the Returned Credentials and Presentations": *"the Verifier MUST NOT rely on the
Wallet to enforce these constraints"*). This closes the conformance-audit **T4.1/T4.2** false-trust (a
trusted, freshly-bound credential of the **wrong `vct`/`docType`**, or missing a requested claim, used
to pass as VALID) and the **T4.3** role-anchoring robustness gap.

| DCQL requirement (§ref) | Implemented behavior |
|-------------------------|----------------------|
| **§6.1 `format` + `meta`** | After the always-on bar accepts a presentation, the verifier checks format match + meta match (SD-JWT VC `vct` ∈ `meta.vct_values`; mdoc every `docType` == `meta.doctype_value`). A mismatch ⇒ `ReasonCode::QueryNotSatisfied`. |
| **§6.3 `claims` + §"Claims Path Pointer"** | Every requested claim path resolves in the verified **disclosed** attributes (JSON-nested key/index/`null`-all-elements for SD-JWT VC; `[namespace, elementIdentifier]` for mdoc); `claim_sets` (§"Selecting Claims") satisfied iff at least one option fully resolves. |
| **§6.3 `values`** | If a Claims Query lists `values`, the disclosed value MUST be one of them (verifier-side; for mdoc the CBOR value is matched as its JSON form per RFC 8949 §6.1). |
| **§"VP Token Validation" step 3 + §"Selecting Credentials"** | `openid4vp::verify_vp_token` folds the per-credential results: every **required** Credential Set Query needs a fully-satisfied `option` (or, with no `credential_sets`, every Credential Query satisfied); a `multiple:false` query carries at most one Presentation (§"Response Parameters"). |
| **Role derivation (EUDI ARF — T4.3)** | The credential's claimed type derives/validates the per-role trust-anchoring role (`dcql::reconcile_role`): a EUDI **PID** type (`vct urn:eudi:pid:1` / `eu.europa.ec.eudi.pid.1`; mdoc `docType eu.europa.ec.eudi.pid.1` — EUDI ARF PID Rulebook, <https://eudi.dev/1.7.1/annexes/annex-3/annex-3.01-pid-rulebook/>) MUST anchor under `IssuerRole::Pid`; a contradicting caller role ⇒ `ReasonCode::RoleMismatch`, rejected **before** the `TrustAnchorSource::resolve`. A type with no standardized mapping keeps the caller role. |

New `ReasonCode`s (closed enum, SemVer-minor additive): `QueryNotSatisfied`, `RoleMismatch`. The C-ABI
`wire` schema version is **unchanged (5)**: the credential type is matched in-core (not surfaced on
`VerificationResult`), and adding `ReasonCode` variants is the documented additive-by-minor contract (no
CBOR envelope-shape change).

**DCQL scope cuts (documented, not silent):**

- **`trusted_authorities`** (§6.1.1) is not evaluated by the DCQL layer — issuer trust is the always-on
  bar's per-role/format chain-to-anchor (the spec itself: *"Verifiers must verify that the issuer … is
  trusted on their own"*; `trusted_authorities` is a wallet-side data-minimization hint).
- **`require_cryptographic_holder_binding:false`** is not honored — the SDK **always** requires holder
  binding (the documented secure default — see §B / `verifier.md`).
- Claim paths resolve against the **verified disclosed** set (the privacy-minimal claims actually
  presented); a path targeting an always-visible non-disclosed scalar is treated as not-present (DCQL
  Claims Queries target selectively-disclosable subject claims).
- An empty/legacy/unparseable DCQL imposes **no** claim/type constraint (the prior opaque behavior is
  preserved); a malformed/unsupported-format Credential Query is dropped leniently so one bad entry never
  disables the gate for the rest. The query is verifier-controlled, so leniency here is not a holder-side
  bypass.
- **Encrypted responses** (`direct_post.jwt`) and the **DC-API** handover remain out of scope (carried
  forward from the audit's documented cuts).

## 2. Crate version pins (the format/trust + crypto layers)

The format/trust layers added for this feature are pinned to EXACT versions (`=x.y.z`) in the root
`Cargo.toml` `[workspace.dependencies]` so the conformance target is reproducible (Principle VII):

| Crate | Pin | Role |
|-------|-----|------|
| `coset` | `=0.4.2` | COSE codec for ISO 18013-5 mdoc (`IssuerAuth` / `DeviceAuth` `COSE_Sign1`). Codec only — crypto stays in the RustCrypto stack. |
| `sd-jwt-payload` | `=0.5.1` (`default-features = false`) | SD-JWT VC format layer (disclosures + KB-JWT structure); signature verification is in-house RustCrypto (no second crypto stack). |
| `quick-xml` | `=0.40.1` | TS 119 612 trust-list XML reader. |

The crypto / X.509 / CMS stack is **reused** from the signing core's pinned set (one authoritative
crypto stack — Principle III/IV; no hand-rolled crypto — Principle IV), at the workspace pins:
`ciborium 0.2`, `sha2 0.10`, `der 0.7`, `const-oid 0.9`, `spki 0.7`, `x509-cert 0.2`, `cms 0.2`,
`rsa 0.9`, `p256 0.13`, `ecdsa 0.16`, `signature 2`, `base64ct 1`.

## 3. DRY review (T031, Constitution Principle VIII)

Two reuse claims were verified against the source; no genuine copy-paste duplication was found, so no
extraction was performed (and none was warranted — see the justification for the parallel state
machines below).

### 3.1 Signer-hook is the spec-001 pattern, not a re-implementation

The holder signer-hook (`src/issuance/signer.rs`) reuses the **pattern** of the spec-001 remote-signing
flow (SDK builds the exact, deterministic signing input; the host signs out-of-process; the SDK
splices the signature back), explicitly documented in the module header. It is **not** a copy of any
signing logic, and there is no shared private-key handling to extract because **neither crate ever
holds a key**:

- `cleverbase-core` signs via the CSC **`signHash` HTTP effect** — the remote Cleverbase signer signs
  over the network (a `Step::PerformHttp`); there is no `Signer` trait.
- `cleverbase-attestation` signs the holder proof via a local **`Signer` callback trait**
  (`Signer::sign(handle, &SigningInput)`) — the integrator's wallet/HSM signs the holder key
  out-of-process.

The mechanisms differ **by domain** (a remote QES signing service vs. the integrator's local holder
HSM); only the sans-IO boundary and the build-input/splice-result shape are shared, which is the
intended reuse.

### 3.2 One trust-list primitive backs both the always-on bar and the qualified gate

`src/trust/chain.rs::verify_chain` is the **single** X.509 chain-validation primitive. It backs:

- the **always-on bar** — `src/trust/engine.rs` (`resolve`, line ~277) and `src/trust/xml.rs`
  (LOTL/national-TL signer authentication, line ~215); and
- the **qualified gate** — `src/qualified/mod.rs` anchors the national TL's signer certificate through
  the same `verify_chain` (its module header states this is "the same X.509 primitive the always-on
  bar uses — DRY").

The qualified module defines **no** parallel chain validator and also reuses
`src/trust/manifest.rs::parse_rfc3339_utc_pub` for the RFC 3339 status-time parsing — one authoritative
trust/time primitive set.

### 3.3 The parallel `begin`/`resume` + effect state machines are justified (not duplication)

`src/issuance/obtain.rs` defines its own `HttpEffect` / `HttpMethod` / `ObtainStep`, mirroring
`cleverbase-core::effects::{HttpEffect, HttpMethod, Step}`. This is a **justified parallel**, not
extractable copy-paste:

- `cleverbase-attestation` **does not depend on** `cleverbase-core` (sibling crates under
  `cleverbase-ffi`); the attestation core is deliberately standalone (one self-contained sans-IO
  attestation core). Sharing the type would force a cross-crate dependency (pulling the unrelated
  PAdES/CMS/timestamp stack into the attestation core) or a new shared crate — an architectural change
  far outside this task's scope (no opportunistic refactor — Principle VIII).
- The domains genuinely diverge: the `Step` enums share **no** terminal variants
  (`Step::{Redirect, Done{signed, evidence}}` vs. `ObtainStep::{Sign(SigningInput), Skipped,
  Obtained(HeldAttestation)}`), and the `HttpEffect.body` semantics differ
  (`Option<Vec<u8>>` skip-if-none vs. always-present `Vec<u8>`).

Recorded as a deliberate parallel; tracked here rather than refactored.

## 4. Quickstart results (T034)

`quickstart.md` scenarios 1–5 (the offline ones) were run end-to-end and confirmed green. The
quickstart names the suites as separate integration-test targets (`--test verify`,
`--test openid4vp_binding`, `--test qualified_gate`, `--test issuance`); in the delivered crate these
suites are **in-crate `#[cfg(test)]` modules** (the only integration-test targets are `live_issuance`
and the opt-in `export_artifacts`), so they are exercised via test-name filters, which is the
equivalent runnable form. Results:

| Scenario | Validates | Runnable command (as delivered) | Result |
|----------|-----------|---------------------------------|--------|
| 1 — verify both formats | US1, FR-001/002/003/005, SC-001/002 | `cargo test -p cleverbase-attestation sdjwtvc:: mdoc::` | green |
| 2 — replay / audience binding | FR-015, SC-008 | `cargo test -p cleverbase-attestation openid4vp::` | green |
| 3 — opt-in qualified gate | FR-014, SC-007 | `cargo test -p cleverbase-attestation qualified::` | green (fixture present; self-skips when absent) |
| 4 — independent cross-check | FR-013, Principle VI | `scripts/crosscheck-attestation.sh --expect valid <artifact>` | self-skips cleanly (no EU reference verifier on PATH); exit 0 |
| 5 — coverage + no-external-deps | FR-013, SC-003 | `cargo test -p cleverbase-attestation` + per-crate coverage | green; 230 tests; line coverage **97.72% ≥ 95%** |
| 6 — gated live issuance | US2, FR-006/007/008/009, SC-004/005 | `cargo test -p cleverbase-attestation --test live_issuance` | self-skips when `ATT_ISSUER` unset (opt-in workflow only) |

**Experimental-standards caveat (recorded per T034):** Scenario 3's qualified-status gate implements
**TS 119 615 v1.4.1 cl. 4.12**, which is **pre-operational** — it is opt-in, off by default, and
version-pinned; enabling it never changes the always-on verdict (SC-007), and missing/ambiguous TL
data yields `Indeterminate` (never a false "qualified"). Scenario 4's independent cross-check is the
FR-013 signal but requires an external different-language reference verifier (Kotlin
`eudi-lib-jvm-sdjwt-kt` / TS `mdoc-ts`), which is not packaged with the SDK; the harness self-skips
when it is absent (the opt-in `attestation-crosscheck.yml` workflow wires it).
