# Feature 004 — Standards Conformance Audit (consolidated)

**Date:** 2026-06-26 · **Branch:** `feature/004-attestation-and-verification` · **Method:** 9 parallel
agents, each fetching the authoritative spec **online** (not training data) and auditing its module
against the normative MUST/SHALL requirements. Each emitted a `requirement → §ref+URL → our behavior
(file:line) → verdict → severity` matrix; this is the consolidation.

## Executive summary

**No unconditional false-accept was found in any of the 9 specs.** The core cryptographic verification —
signature verification (raw r‖s, no DER; alg pinned), selective-disclosure integrity (SD-JWT digest walk +
mdoc valueDigests over verbatim on-wire bytes), multi-document defenses, replay/audience binding, and the
OpenID4VP §B.2.6 handover (byte-reproduced against the spec's published example hash `048bc053…`) — is
**conformant and confirmed solid**. The 50+ review-loop fixes landed correctly.

The remaining gaps are **conformance-completeness**, clustering into 7 coherent themes (below). Most are
*robustness* (a normative MUST that bites only a non-conformant **trusted** issuer, not a holder/attacker)
or *over-strict false-rejects* (we reject a conformant credential). The genuine **false-trust** items are
all **conditional** (on chain-to-root anchoring, the opt-in qualified gate, or the experimental XML TL path)
or **forward-compat** (`crit`).

Counts (deduped, genuine in-scope gaps): **false-trust 6 · false-reject (incl. 1 HIGH) 6 · robustness ~12 ·
cosmetic ~5**. Plus the **OpenID4VCI draft-vs-1.0** cluster (gated path). Legitimate documented scope cuts
are listed separately.

---

## A. Genuine gaps to fix (by theme)

### Theme 1 — X.509 / certificate-profile completeness (`trust/chain.rs` leaf-purpose + path layer)
The single highest-leverage cluster; 4 agents (RFC 5280, ISO mdoc, eIDAS/ARF, ETSI) converge here.

| ID | Finding | §ref | Verdict | Sev |
|----|---------|------|---------|-----|
| T1.1 | **Unknown *critical* extension not rejected** — only BC/KU/EKU understood; a critical `nameConstraints`/`policyConstraints`/unknown OID is silently accepted | RFC 5280 §6.1.4(o)/§6.1.5(f), §6 | Gap | **false-trust** (gateway) |
| T1.2 | **Name constraints not processed** — a CA scoping a sub-CA's namespace is ignored → scope-escape. **Coupled to T1.1** (nameConstraints MUST be critical, so T1.1 makes it fail-closed) | RFC 5280 §6.1.3(b)(c), §6.1.4(g) | Gap | **false-trust** |
| T1.3 | **QcStatement/QcType never inspected** — under chain-to-root anchoring a plain eSeal/EAA cert sharing a QTSP root is trusted as PID/QEAA | ETSI TS 119 412-6 PID-4.5-01 (`id-etsi-qct-pid 0.4.0.194126.1.1`); QcCompliance for QEAA | Gap | **false-trust** (conditional) |
| T1.4 | **mdoc DS leaf `keyUsage=digitalSignature` not enforced** (only EKU is) | ISO 18013-5 Annex B Table B.3 | Gap | false-trust (low) |
| T1.5 | **mdoc DS leaf `basicConstraints cA=FALSE` not enforced on the leaf** — a `cA=TRUE` leaf with the mdlDS EKU passes | ISO 18013-5 Annex B Table B.3 (`mc`) | Gap | false-trust (low) |
| T1.6 | SD-JWT issuer leaf `keyUsage` **absent** allowed (laxer than the SHALL-present profile) | ETSI EN 319 412-2 §4.3.x | Partial | robustness |
| T1.7 | Inner/outer `signatureAlgorithm` consistency not checked | RFC 5280 §4.1.1.2/§4.1.2.3 | Partial | robustness |

### Theme 2 — `crit` (critical header) handling (COSE **and** JOSE) — one concept, two sites
| ID | Finding | §ref | Verdict | Sev |
|----|---------|------|---------|-----|
| T2.1 | COSE_Sign1 `crit` never processed — a legitimately-signed message marking a critical header we don't understand is accepted | RFC 9052 §3.1 | Gap | false-trust (fwd-compat) |
| T2.2 | JWS `crit` never processed (issuer JWT + KB-JWT) | RFC 7515 §4.1.11 | Gap | false-accept-class (fwd-compat) |

### Theme 3 — DS-cert validity at the *signing* time (`mdoc` + `trust` seam) — the one HIGH false-reject
| ID | Finding | §ref | Verdict | Sev |
|----|---------|------|---------|-----|
| T3.1 | **DS cert validity checked at `now`, not the MSO `signed` time.** DS certs rotate (~months) while mDLs live ~years → conformant mDLs false-rejected once the DS cert expires. Architectural cause: `TrustAnchorSource::resolve()` is time-less and runs before `signed` is parsed | ISO 18013-5 §9.3.1 | Gap | **false-reject (HIGH)** |

### Theme 4 — Verifier "did I get what I requested" gate (`verify`/`openid4vp` + `sdjwtvc` vct)
| ID | Finding | §ref | Verdict | Sev |
|----|---------|------|---------|-----|
| T4.1 | **DCQL satisfaction not validated** — a trusted, freshly-bound credential of the **wrong `vct`/`doctype`, or missing requested claims**, passes as VALID; DCQL carried opaquely | OpenID4VP 1.0 §VP-Token-Validation steps 2.2 + 3 | Gap | **false-trust** |
| T4.2 | **`vct` never validated** (REQUIRED, Collision-Resistant Name) — `valid`/`Trusted` for missing/arbitrary credential type. (research.md D2 committed an in-house `vct` layer that wasn't built) | SD-JWT VC §claims/§type-claim | Gap | false-trust |
| T4.3 | **`IssuerRole` is caller-supplied** (default `Pid`), never derived/verified from `vct`/`docType` → per-role anchoring only as good as the host's role input | EUDI ARF per-role lists | Gap | robustness |

### Theme 5 — ETSI trusted-list / qualified-gate (opt-in / experimental path)
| ID | Finding | §ref | Verdict | Sev |
|----|---------|------|---------|-----|
| T5.1 | **Always-on `NativeTrustEngine` XML path ignores `<ServiceStatus>` + `<ServiceTypeIdentifier>`** — a **withdrawn** QTSP cert still anchors trust; service type unread. **Undocumented.** (The qualified *gate* honors both correctly) | ETSI TS 119 612 §5.5.1/§5.5.4 | Gap | **false-trust** |
| T5.2 | Missing `urn:etsi:eaa:eu:qualified` type-indication precondition — can report `Qualified` where spec requires `Indeterminate` | ETSI TS 119 615 PRO-4.12.4-03 | Gap | false-trust |
| T5.3 | XAdES TL signature never cryptographically verified; `chain_only=true` opt-in is forgeable (default fails closed). Documented in code, **not** in standards-conformance.md | ETSI TS 119 612 §5.7 / Annex B | Partial / scope-cut | false-trust (if `chain_only` used in prod) |
| T5.4 | Exact-DER cert↔service matching (vs CA / SubjectName+SKI) → false-rejects a valid QEAA whose Sdi lists the issuing CA | ETSI TS 119 612 §5.5.3; 615 cl.4.3 | Partial | false-reject |
| T5.5 | National-TL `NextUpdate` hard-fail (we treat as fatal; ETSI = warning for the national TL) | ETSI TS 119 615 PRO-4.2.4-10/12 | Over-strict | false-reject (security-positive) |

### Theme 6 — SD-JWT VC robustness MUSTs (`sdjwtvc`)
| ID | Finding | §ref | Verdict | Sev |
|----|---------|------|---------|-----|
| T6.1 | Issuer JWT `typ` (`dc+sd-jwt`/`vc+sd-jwt`) not checked (KB-JWT `typ=kb+jwt` **is**, via the pinned dep) | RFC 9901 §9.11; SD-JWT VC §JOSE-Header | Gap | robustness |
| T6.2 | Disclosure claim-name `_sd`/`...` not rejected | RFC 9901 §7.1 step 3.c.ii.2 | Gap | robustness |
| T6.3 | Validity read only from the clear payload (a selectively-disclosable `exp` reads unbounded); KB-JWT `iat` has no acceptable-window check; top-level `aud` ignored | RFC 9901 §9.7, §7.3 step 5.e | Partial | robustness |
| T6.4 | Nested `_sd_alg` not rejected | RFC 9901 §4.1.1 | Gap | cosmetic |

### Theme 7 — JOSE/CBOR + misc over-strict
| ID | Finding | §ref | Verdict | Sev |
|----|---------|------|---------|-----|
| T7.1 | Fractional `NumericDate` (`exp`/`nbf`/`iat`) rejected — RFC permits non-integer | RFC 7519 §2 | Over-strict | false-reject |
| T7.2 | Indefinite-length CBOR not rejected at the top-level `DeviceResponse` decode (integrity path still fails closed) | RFC 8949 §4.2.1 | Partial | robustness |
| T7.3 | Trust-anchor's own validity enforced (TA is a §6.1 input, not a path cert) | RFC 5280 §6.1.1/§6.2 | Over-strict | false-reject (defensible) |
| T7.4 | ES384/512/PSS/EdDSA → honest `UnsupportedAlgorithm` (ES256 is the EUDI baseline) | RFC 7518/9053 | scope-cut | false-reject (low) |
| T7.5 | `documentErrors` present → reject whole response (over-strict for a partially-fulfilled multi-doc request) | ISO 18013-5 §8.3 | Over-strict | false-reject (low) |

### Theme 8 — OpenID4VCI 1.0 alignment (GATED / forward-looking path; default `IssuerBackend::None`)
The implemented wire shapes track **draft-13, not 1.0 final** — silent because the in-test issuer double speaks the same dialect. Zero production-verification impact, but the docs claim plain "OpenID4VCI 1.0".
| ID | Finding | §ref | Verdict | Sev |
|----|---------|------|---------|-----|
| T8.1 | Credential Request `proof` (singular) → 1.0 requires `proofs: { jwt: [...] }` | OpenID4VCI 1.0 §Credential-Request | Gap | critical (interop) |
| T8.2 | `c_nonce` read from token response → 1.0 moved it to a dedicated **Nonce Endpoint** | OpenID4VCI 1.0 §Nonce-Endpoint | Gap | critical (interop) |
| T8.3 | Credential Response `credential` (string) → 1.0 is `credentials: [{ credential }]` | OpenID4VCI 1.0 §Credential-Response | Gap | critical (interop) |
| T8.4 | `tx_code`, `credential_identifier`/`authorization_details`, 202/deferred, DPoP unmodeled | OpenID4VCI 1.0 §6/§8 | Gap | false-reject/robustness |

### Cosmetic / doc
- MSO `version` + DeviceResponse `version` not checked (mdoc); DN binary-match + `MAX_PATH_LEN` ceiling (RFC 5280); over-permissive COSE tag-strip (any tag vs tag 18).
- Doc nits: `TS_119_615_VERSION="1.4.1"` vs module doc "v1.3.1"; chain.rs comments attribute "BC MUST be critical" to §6.1.4(k) (correct ref is §4.2.1.9); `standards-conformance.md` doesn't disclose the XAdES / QcType / DS-profile / DCQL scope cuts.

---

## B. Legitimate documented scope cuts (record, don't fix)
- **DeviceMac** (ISO device-retrieval) — N/A for OID4VP-redirect (no EReaderKey ECDH secret exists). ✔ confirmed defensible.
- **DC-API handover** (`OpenID4VPDCAPIHandover`, origin-based) + **encrypted responses** (`direct_post.jwt`).
- **LOTL/OJEU fetch + authentication** + LOTL→national-TL pointer discovery (sans-IO; host supplies resolved scheme anchors).
- **Full XAdES** C14N/Reference-digest verification of the TL (fail-closed default; `chain_only` opt-in).
- **JWT VC Issuer Metadata** key discovery + **`vct#integrity`/Type-Metadata** fetch (network; sans-IO core).
- **ES384/512/PSS/EdDSA** (ES256 is the EUDI mandatory baseline).
- **RP access certificates** (ETSI TS 119 471/475) + **wallet/key attestation** trust.
- `require_cryptographic_holder_binding:false` non-bound presentations (we always require binding — secure default).

These are real and reasonable — the action is to **state them explicitly in `standards-conformance.md`** so each is a reasoned cut, not a silent omission (several currently are silent).

---

## C. What the audit RATIFIED (conformant — no action)
RFC 5280 core path (signature/validity/basicConstraints+critical/pathLen+self-issued/keyCertSign/leaf-EKU);
COSE raw-r‖s/alg-pinned/Sig_structure/detached-guard; SD-JWT digest-walk/forged-disclosure-rejection/
KB-verified-when-present/cnf-bound/array-redaction-one-key/nested-reconstruction; mdoc valueDigests-over-
verbatim-bytes/digestID-uniqueness/all-documents-loop/§B.2.6-handover; OpenID4VP nonce+audience binding
(both formats)/handover byte-reproduced against the spec example; qualified gate now-vs-relevant-time split;
per-role `(role,format)` anchoring; the JWT-NumericDate vs mdoc-RFC3339 two-parser split; PoP-JWT
typ/alg/aud/iat/no-private-key/cnf-binding.
