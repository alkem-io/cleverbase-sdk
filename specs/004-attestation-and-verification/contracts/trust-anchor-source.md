# Contract: pluggable trust-anchor source (EU trust lists)

Anchors issuer trust for verification. A **native Rust** engine (no Rust tooling exists for TS 119 612/602/
LOTL — the biggest build, research D5). Pluggable: production EU lists vs a configured **test anchor** for
the offline suite (FR-003/FR-004). EU DSS is a **test-only** cross-language parity oracle, never a runtime
dependency.

## Operations

```
resolve(role, format, issuerCert) -> TrustDecision { trusted: bool, entry?: TrustListEntry }
refresh() -> ()    // fetch + cache signed trust-list XML/JSON; host-driven, not per-verification
```

## Trust anchoring is per role/format (research D5)

| Issuer role / format | Anchor |
|----------------------|--------|
| **QEAA** | EU LOTL + national Trusted Lists (ETSI TS 119 612 v2.4.1 / TLv6) |
| **PID provider** | Commission list under eIDAS Art. 5a(18) |
| **PuB-EAA provider** | Commission list under Art. 45f(3) |
| **mdoc (ISO 18013-5)** | IACA root trust anchor (optionally distributed via VICAL) |
| (new) **LoTE** | ETSI TS 119 602 "Lists of Trusted Entities" JSON/XML (coexists with TS 119 612) |
| **test/offline** | a configured self-signed test root / IACA (the offline suite's anchor) |

## Leaf key-purpose (per role/format)

`resolve` chain-validates the signing leaf via `trust::chain::verify_chain`, which enforces the
role/format-appropriate **leaf key purpose** so a genuinely-chained-but-WRONG-PURPOSE leaf is rejected
(a TLS `serverAuth` cert under the same root, or an mdoc-DS cert presented as the SD-JWT VC issuer leaf):

- **mdoc DS** (ISO/IEC 18013-5:2021 Annex B) — the Document Signer leaf MUST carry `extendedKeyUsage`
  containing `id-mso-mdl-DS` = `1.0.18013.5.1.2` (criticality not required — RFC 5280 §4.2.1.12).
- **SD-JWT VC issuer** — no spec mandates an EKU (verified online: IETF SD-JWT VC §2.5 / HAIP §6.1.1 /
  EUDI ARF are silent, the latter distinguishing issuers by QcStatement OIDs); the enforced floor is
  "leaf is NOT a CA, and if `keyUsage` is present it asserts a signing bit". See `standards-conformance.md` §1.1.
- **Trust-list signer** authentication imposes no credential-leaf purpose (a separate ETSI profile).

The path build is a **backtracking** DFS (a cross-cert / alternate intermediate reaching the anchor is
accepted, not greedily false-rejected) and excludes self-issued key-rollover certs from `pathLenConstraint`
(RFC 5280 §4.2.1.9 / §6.1.4 (l)).

## Invariants

- The engine **authenticates** each trust list (the LOTL signs national-TL pointers; each national TL is
  signed) before trusting its entries — `quick-xml` + the existing X.509 stack; no hand-rolled crypto.
- **Reachability is fail-closed by default** (configurable): an unreachable/stale LOTL or national TL for
  qualified verification yields an explicit outcome, never a silent "trusted".
- Trust-list fetch/refresh is **cached** (not per-verification); the core stays sans-IO (the host drives
  `refresh()`; `resolve()` works on the cached, in-memory anchors).
- Production-grade caveat: TS 119 612 (v2.4.1/TLv6) and TS 119 602 (LoTE) are mid-rollout — pin the targeted
  profile versions.

## Tests (must fail first)

- An issuer present on the configured (test) anchor → trusted; an issuer absent / with an expired/withdrawn
  entry → untrusted with the specific reason; an unreachable list → fail-closed. Parity-checked against EU
  DSS's trust-list determination on the same fixtures (cross-language oracle).
</content>
