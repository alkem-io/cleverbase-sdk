<!--
SYNC IMPACT REPORT
==================
Version change: 1.0.0 → 1.1.0
Bump rationale: MINOR — added one new principle (VIII. Engineering Discipline) and
                materially expanded Principle VI (added the ≥95% unit-coverage gate).
                No backward-incompatible removals/redefinitions.

Principles:
  I.    Production-Grade Completeness (NON-NEGOTIABLE)        [unchanged]
  II.   Standards-First Conformance                           [unchanged]
  III.  Single Rust Core, Idiomatic Bindings                  [unchanged]
  IV.   Security & Cryptographic Rigor                        [unchanged]
  V.    Own the Full AdES Stack                               [unchanged]
  VI.   Test-First & Contract-Tested (NON-NEGOTIABLE)         [expanded: ≥95% unit coverage]
  VII.  Versioning & ABI Stability                            [unchanged]
  VIII. Engineering Discipline: DRY, RCA, No Opportunistic Changes  [NEW]

Added sections: Principle VIII. Expanded: Principle VI; Development Workflow & Quality Gates.
Removed sections: none.

Templates / artifacts reviewed:
  - .specify/templates/plan-template.md   ✅ no change (Constitution Check gate is dynamic)
  - .specify/templates/spec-template.md   ✅ no change (generic; no principle conflict)
  - .specify/templates/tasks-template.md  ✅ already test-required (v1.0.0); inherits the
       ≥95% coverage and engineering-discipline gates via the dynamic Constitution Check
  - CLAUDE.md / AGENTS.md                  ✅ updated with the new engineering rules
  - .specify/extensions.yml hooks          ✅ no before/after_constitution hooks defined

Deferred TODOs: none.
-->

# Cleverbase SDK Constitution

The Cleverbase SDK is a production-grade, polyglot SDK that integrates Cleverbase
(a Dutch Qualified Trust Service Provider) qualified electronic signing, identification,
and authentication — and, on the roadmap, EUDI attestation — into applications. Its first
consumer is the Alkemio platform (github.com/alkem-io), but it is designed and released as
a standalone product. Cleverbase publishes no official SDK; this project is the first real
client built against their OAuth 2.0 / OpenID Connect Identification API and their Cloud
Signature Consortium (CSC) signing API.

## Core Principles

### I. Production-Grade Completeness (NON-NEGOTIABLE)

Every feature that ships MUST be complete and production-grade. There are no half-features,
stubs-passing-as-features, or "good enough to demo" shortcuts. "Demos" are examples of using
the finished SDK; they MUST NOT drive scope reduction of the SDK itself.

Phasing decides WHAT ships WHEN, never HOW COMPLETE a shipped capability is. A phase delivers
a smaller set of fully-finished capabilities — not a larger set of partial ones. Example: it
is correct to ship PAdES B-B and B-T complete in phase 1 while deferring B-LTA to a later
phase; it is a violation to ship a half-implemented B-LTA.

**Rationale**: This SDK creates legally binding qualified signatures and identity assertions.
Partial implementations of trust-critical functionality are not merely low-quality — they are
unsafe and erode the legal validity the SDK exists to provide.

### II. Standards-First Conformance

The SDK MUST conform to the published standards it implements; proprietary shortcuts that
diverge from a spec are prohibited. Governing standards include, non-exhaustively: eIDAS
(Regulation (EU) 910/2014 as amended by (EU) 2024/1183), the CSC API (v1 and v2), OAuth 2.0
(RFC 6749), OpenID Connect Core 1.0, PAdES (ETSI EN 319 142), CAdES (ETSI EN 319 122),
RFC 3161 timestamping, signature validation (ETSI TS 119 615), trusted lists (ETSI TS 119 612),
and — for the attestation roadmap — OpenID4VCI, OpenID4VP, SD-JWT VC, and ISO/IEC 18013-5 mdoc.

Implementations MUST cite the specific standard and version they target. Specifications drift:
the project MUST track CSC, eIDAS, and EUDI/OpenID4VC version changes and record the targeted
versions in plans and code.

**Rationale**: Interoperability and legal recognition depend on faithful conformance. The
external ecosystem (validators, wallets, Trusted Lists, relying parties) is the source of
truth, not our convenience.

### III. Single Rust Core, Idiomatic Bindings

Protocol orchestration and cryptography MUST live in ONE memory-safe Rust core, exposed over a
stable, coarse C-ABI (CBOR request in / result out). Language bindings — Python (PyO3),
TypeScript/Node (napi-rs, plus a WASM build), and Go (cgo) — MUST be thin, idiomatic shims over
that core. Crypto or protocol logic MUST NOT be duplicated or re-implemented per language.

Rust is the core because it produces a clean C-ABI artifact with no managed runtime, unlike a
Go `c-shared` core which would drag the Go runtime/GC into every host language.

**Rationale**: One source of truth means a bug or spec update is fixed once and inherited
everywhere; the per-language surface stays small, idiomatic, and auditable.

### IV. Security & Cryptographic Rigor

The core MUST be memory-safe. The project MUST NOT hand-roll cryptography where a vetted
standard library exists. Secrets — `client_secret`, Signature Activation Data (SAD), access
tokens, private keys — MUST remain server-side and MUST NEVER reach the frontend. The optional
thin TypeScript frontend helper performs redirect orchestration and status polling ONLY, and
MUST contain no cryptographic operations and handle no secrets. No wallet is embedded; user
sole-control consent happens in Cleverbase's own wallet app.

**Rationale**: A trust-services SDK is a high-value attack target; the security model must be
explicit, minimal in its trusted surface, and incapable of leaking sole-control material to a
browser.

### V. Own the Full AdES Stack

Cleverbase signs hashes only — it provides no document/container assembly, no timestamping, no
LTV material, and no validation in any mode (verified against the live CSC service). Therefore
the SDK OWNS the entire Advanced Electronic Signature stack: container assembly, timestamping
(via an external qualified TSA), long-term validation (LTV), B-LTA archival, and signature
validation. There is no offload path; designs MUST NOT assume one.

The signing pipeline MUST be architected from day one as a staged augmentation flow
(Sign → +Timestamp → +Revocation/LTV → +Archive Timestamp → Validate) with all extension seams
present, and MUST handle both ECDSA P-256 (CSC v2) and RSA (CSC v1). Formal eIDAS
validation/qualification MUST be reached through a pluggable validation backend; the production
default is a self-hosted reference engine sidecar (EU DSS, or pyHanko as a lighter alternative),
never an external hosted service that would receive private documents.

**Rationale**: Because no part of the AdES burden can be delegated to the QTSP, the
architecture must be honest about that from the start, or it will be unable to grow to legally
durable (B-LTA) signatures.

### VI. Test-First & Contract-Tested (NON-NEGOTIABLE)

Tests MUST be written and approved before implementation, and MUST fail before the
implementation makes them pass. Every binding and the core MUST carry tests. Contract tests
MUST validate behavior against the real Cleverbase API surface (acceptance environment and/or
documented stubs). Signatures the SDK produces MUST be validated against independent reference
tools (e.g. the EU DSS validator) as part of the test suite.

Unit-test coverage MUST be at least 95%, measured per crate/package. A change that drops
coverage below 95% MUST NOT be merged. Coverage is a floor, not a target: it does not excuse
missing contract, integration, or conformance tests.

**Rationale**: Trust-critical output cannot be trusted on self-assertion; conformance must be
demonstrated against the actual external services and independent validators, and a high
coverage floor keeps the memory-safe core's branches and error paths exercised.

### VII. Versioning & ABI Stability

The project MUST follow Semantic Versioning. The Rust core's C-ABI surface MUST be stable
within a major version; bindings MUST remain backward-compatible within a major version. Every
breaking change MUST be documented with a migration note and justified. Binding releases MUST
declare which core version they wrap.

**Rationale**: Consumers (starting with Alkemio, in three languages) need predictable upgrades;
an FFI boundary makes silent ABI breakage especially dangerous.

### VIII. Engineering Discipline: DRY, RCA, No Opportunistic Changes

- **DRY (Don't Repeat Yourself)**: Logic, constants, configuration, and protocol/crypto
  definitions MUST have a single authoritative source. Duplication — copy-paste, parallel
  re-implementations, repeated magic literals — is prohibited; extract and reuse instead. This
  extends Principle III's cross-language no-duplication rule down to within each codebase.
- **Always Root-Cause Analysis (RCA)**: Every bug fix MUST identify and address the underlying
  root cause, not the surface symptom. Symptom-masking patches, retries wrapped around a defect,
  and swallowed errors are prohibited. The RCA — what failed, why, and why it was not caught —
  MUST be recorded in the change/PR.
- **No opportunistic edits or fixes**: A change MUST stay scoped to its stated task. Unrelated
  "while I'm here" edits, drive-by refactors, and reformatting outside the task MUST NOT be
  mixed in. Genuine unrelated issues discovered MUST be tracked separately and addressed in
  their own scoped change.

**Rationale**: In trust-critical code, duplicated logic drifts out of sync until one copy is
silently wrong; symptom fixes leave the real defect live; and scope-creeping diffs defeat the
review that is the safety net for legally binding output.

## Security & Compliance Requirements

- **Qualified signatures (eIDAS)**: The SDK targets Qualified Electronic Signatures. It MUST
  preserve the QTSP's sole-control / Sole Control Assurance Level (SCAL) model — user
  authorization and consent occur in Cleverbase's wallet; the SDK never reconstructs or bypasses
  that control.
- **Qualified TSA dependency**: B-T and above REQUIRE an external qualified Time-Stamping
  Authority (Cleverbase provides none). The TSA MUST be configurable behind an interface and its
  procurement tracked as a delivery dependency.
- **EU Trusted List validation**: Validation MUST anchor trust in the EU LOTL and national
  Trusted Lists (ETSI TS 119 612) and determine qualification status per ETSI TS 119 615 — via
  the pluggable validation backend, not bespoke trust logic where the reference engine suffices.
- **Data handling & residency**: Documents and personal/identity data MUST stay within the
  operator's infrastructure. No private document or identity attribute may be sent to any
  third-party hosted service that is not a contracted trust-service provider in the flow.
- **Secret custody**: All Cleverbase client credentials and signing tokens are confidential and
  server-side only (see Principle IV).

## Development Workflow & Quality Gates

- **Constitution gate**: Every plan MUST pass a Constitution Check before design and re-check
  after design. Violations MUST be recorded in the plan's Complexity Tracking with justification
  or the design MUST change.
- **Review**: All changes go through PR review that explicitly verifies conformance to these
  principles — standards conformance (II), the single-core rule (III), security (IV),
  test-first + ≥95% coverage (VI), and engineering discipline (VIII: DRY, a recorded RCA for any
  fix, and no opportunistic out-of-scope edits).
- **CI**: CI MUST build and test the Rust core and all three bindings, MUST enforce the ≥95%
  unit-coverage floor, and MUST run the reference-validator checks on produced signatures (VI).
- **Complexity justification**: Added complexity (extra services, extra languages in the core,
  re-implemented standard logic, duplicated logic) MUST be justified against a simpler rejected
  alternative.

## Governance

This constitution supersedes other development practices. Where any guidance conflicts with it,
this document prevails.

**Amendments**: Changes MUST be proposed via PR, documented with rationale, and version-bumped
per the policy below. Amendments that alter trust-critical behavior MUST include a migration and
compatibility note.

**Versioning policy** (of this constitution): MAJOR for backward-incompatible governance or
principle removals/redefinitions; MINOR for a new principle/section or materially expanded
guidance; PATCH for clarifications and non-semantic refinements.

**Compliance review**: PRs and plans MUST verify compliance. Persistent or unjustified
violations block merge. The dependent Spec Kit templates (plan, spec, tasks) and the agent
context files (CLAUDE.md / AGENTS.md) MUST be kept in sync with amendments.

**Version**: 1.1.0 | **Ratified**: 2026-06-22 | **Last Amended**: 2026-06-22
