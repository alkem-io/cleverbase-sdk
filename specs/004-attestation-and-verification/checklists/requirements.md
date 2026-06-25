# Specification Quality Checklist: EUDI attestation — verification now, issuance forward-looking

**Purpose**: Validate specification completeness and quality before proceeding to planning
**Created**: 2026-06-25
**Feature**: [spec.md](../spec.md)

## Content Quality

- [x] No implementation details (languages, frameworks, APIs)
- [x] Focused on user value and business needs
- [x] Written for non-technical stakeholders
- [x] All mandatory sections completed

## Requirement Completeness

- [x] No [NEEDS CLARIFICATION] markers remain
- [x] Requirements are testable and unambiguous
- [x] Success criteria are measurable
- [x] Success criteria are technology-agnostic (no implementation details)
- [x] All acceptance scenarios are defined
- [x] Edge cases are identified
- [x] Scope is clearly bounded
- [x] Dependencies and assumptions identified

## Feature Readiness

- [x] All functional requirements have clear acceptance criteria
- [x] User scenarios cover primary flows
- [x] Feature meets measurable outcomes defined in Success Criteria
- [x] No implementation details leak into specification

## Notes

- The decisive scope fork was **pre-resolved at spec time** by a Cleverbase-feasibility check + a user
  decision (see the Clarifications section): Cleverbase has **no integratable EUDI attestation issuance API
  today**, so **verification is built now** (standards-based, Cleverbase-independent) and **issuance/holding
  is forward-looking and gated** on a real issuer API (the spec-003 live-signing gating pattern).
- Standards/protocol terms (SD-JWT VC, ISO mdoc, OpenID4VCI/VP, EU Trusted Lists, eIDAS) are domain terms
  from the EUDI surface this feature targets — their presence is intentional, not implementation leakage.
- All material scope decisions are **resolved** in the Clarifications section (no open markers): (1) EUDI
  verifiable-credential sense; (2) verify-now + issuance-forward-looking-gated; (3) **both** formats
  (SD-JWT VC + mdoc) delivered together, no phasing; (4) verification depth = always-on crypto + trust-list
  bar with **opt-in** eIDAS qualified-status determination (ETSI TS 119 615); (5) **full verifier** — the
  SDK builds the OpenID4VP request (nonce + audience) and verifies the response is bound to it.
</content>
