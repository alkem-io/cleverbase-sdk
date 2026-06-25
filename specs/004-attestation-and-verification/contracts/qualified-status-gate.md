# Contract: opt-in eIDAS qualified-status determination (ETSI TS 119 615 cl. 4.12)

An **opt-in** determination (off by default) layered over the always-on bar — never instead of it (the
spec-003 always-on-bar + opt-in-gate pattern). Decides whether the attestation is a **Qualified** EAA from a
qualified issuer. **Native Rust logic** (no reference engine computes QEAA qualification today); reuses the
trust-list primitives (`trust-anchor-source.md`) — DRY with the always-on bar.

## Operation

```
qualifiedStatus(issuer, relevantTime, anchors) -> Qualified | NotQualified | Indeterminate
```

Enabled via `VerificationPolicy.qualifiedGate = true`; the result populates `VerificationResult.qualifiedStatus`.

## Determination (TS 119 615 v1.4.1 cl. 4.12)

1. Authenticate the LOTL → select the relevant national Trusted List.
2. Match the issuer's service entry by signing cert + **service type** `…/Svctype/EAA/Q` (URN
   `urn:etsi:eaa:eu:qualified`).
3. Read the current/historical `granted` / `withdrawn` status **at the relevant time** (the credential's
   issuance/relevant time, NOT "now").
4. Conclude **Qualified** (granted at the relevant time) / **NotQualified** / **Indeterminate**.

## Invariants

- **No false "qualified"** (SC-007): `Qualified` is returned only on a positive determination; absent/
  ambiguous trust-list data ⇒ honest **`Indeterminate`** (never assume qualified).
- **Disabling the gate does not change the always-on bar** (SC-007): the always-on crypto + trust-list
  membership verdict is identical whether the gate runs or not.
- **Experimental + version-pinned**: cl. 4.12 is newly standardized + pre-operational (national TLs are
  only beginning to carry `EAA/Q` entries); pin TS 119 615 v1.4.1 and surface the experimental status.

## Tests (must fail first; opt-in / self-skip if TL fixtures absent)

- A qualified-issuer fixture (granted at the relevant time) → `Qualified`; a trusted-but-non-qualified
  issuer → `NotQualified` and the verdict is VALID-but-not-QUALIFIED (no false "qualified"); missing TL data
  → `Indeterminate`. With the gate disabled, the always-on verdict is unchanged.
</content>
