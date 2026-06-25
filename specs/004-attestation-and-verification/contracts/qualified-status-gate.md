# Contract: opt-in eIDAS qualified-status determination (ETSI TS 119 615 cl. 4.12)

An **opt-in** determination (off by default) layered over the always-on bar — never instead of it (the
spec-003 always-on-bar + opt-in-gate pattern). Decides whether the attestation is a **Qualified** EAA from a
qualified issuer. **Native Rust logic** (no reference engine computes QEAA qualification today); reuses the
trust-list primitives (`trust-anchor-source.md`) — DRY with the always-on bar.

## Operation

```
qualifiedStatus(issuer, now, relevantTime, anchors) -> Qualified | NotQualified | Indeterminate
```

Enabled via `VerificationPolicy.qualifiedGate = true`; the result populates `VerificationResult.qualifiedStatus`.

## Two distinct times — authenticate at `now`, read status at the relevant time

The determination takes **two** instants, used for two different jobs (do not conflate them):

- **`now`** (the verification instant / real "now") — used to **authenticate the Trusted List**: the
  freshness/staleness check (`now >= NextUpdate ⇒ stale`) **and** the TL-signer certificate's chain
  validity (`notBefore`/`notAfter`). Whether the LOTL/national-TL snapshot you hold is itself *currently*
  fresh and signed by a *currently* valid scheme operator is a **now** property — you MUST NOT trust a
  stale or expired-signer TL just because the credential being checked is old.
- **`relevantTime`** (the credential's issuance/relevant time) — used **only** to read the issuer's
  `granted`/`withdrawn` status (step 3). Per eIDAS this is "status at the relevant time": an issuer not yet
  granted `EAA/Q` when it signed a credential, but granted later, is NOT `Qualified` for that credential.

> **RCA (the false-`Qualified` bug this contract fixes):** a prior fix correctly derived the relevant time
> for the *status read* from the credential, but passed that same old time into TL authentication, so the
> freshness/staleness and TL-signer-validity checks were evaluated at the credential's issuance time. A TL
> whose `NextUpdate` is in the past relative to real `now` (stale) but in the future relative to an old
> credential's issuance time authenticated as "fresh" → a stale/withdrawn-since TL produced a false
> `Qualified`. Authentication MUST use `now`; only the status read uses `relevantTime`.

## Determination (TS 119 615 v1.4.1 cl. 4.12)

1. Authenticate the LOTL / national Trusted List **at `now`** (freshness `now >= NextUpdate` + the
   TL-signer's chain validity). A stale-at-`now` / unsigned / forged / unchained list — or no scheme anchor
   — fails closed → **Indeterminate** before any status is read. Then select the relevant national TL.
2. Match the issuer's service entry by signing cert + **service type** `…/Svctype/EAA/Q` (URN
   `urn:etsi:eaa:eu:qualified`).
3. Read the current/historical `granted` / `withdrawn` status **at the relevant time** (the credential's
   issuance/relevant time, NOT "now"). The relevant time is derived from the **credential**: SD-JWT VC `iat`
   (fallback `nbf`); mdoc MSO `validityInfo.signed` (fallback `validFrom`). A credential with no issuance
   time at all fails closed → **Indeterminate** (the verification instant is NEVER silently substituted).
4. Conclude **Qualified** (granted at the relevant time) / **NotQualified** / **Indeterminate**.

## Invariants

- **No false "qualified"** (SC-007): `Qualified` is returned only on a positive determination; absent/
  ambiguous trust-list data ⇒ honest **`Indeterminate`** (never assume qualified).
- **Only meaningful for a VALID credential** (SC-002/SC-007): the determination matches the credential's
  *claimed* signing cert against the TL **without** re-verifying its signature (X.509 certs are public, so
  an attacker could embed a real qualified issuer's cert). The gate is therefore computed only when the
  always-on verdict is **VALID** — only then has the bar signature-verified + trust-anchored that exact
  cert. On an INVALID credential `qualifiedStatus` is absent (never a `Qualified` off an unverified cert).
- **Relevant time from the credential, never "now"** (SC-007): the status is read at the credential's
  issuance/relevant time (SD-JWT VC `iat`/`nbf`; mdoc MSO `signed`/`validFrom`); a credential with no
  issuance time fails closed to `Indeterminate`. An issuer granted only *after* it issued a credential is
  never `Qualified` for that earlier credential.
- **TL authentication at `now`, never the relevant time** (SC-007): TL freshness (`now >= NextUpdate`) and
  the TL-signer certificate's chain validity are evaluated at the **verification instant `now`**, NOT at the
  credential's (older) relevant time. A TL that is stale at `now` — or whose signer cert has expired by
  `now` — fails closed to `Indeterminate` **even if** it was fresh / its signer valid at the credential's
  issuance time. The two times are independent: authenticate at `now`, read status at the relevant time.
- **Disabling the gate does not change the always-on bar** (SC-007): the always-on crypto + trust-list
  membership verdict is identical whether the gate runs or not.
- **Experimental + version-pinned**: cl. 4.12 is newly standardized + pre-operational (national TLs are
  only beginning to carry `EAA/Q` entries); pin TS 119 615 v1.4.1 and surface the experimental status.

## Tests (must fail first; opt-in / self-skip if TL fixtures absent)

- A qualified-issuer fixture (granted at the relevant time) → `Qualified`; a trusted-but-non-qualified
  issuer → `NotQualified` and the verdict is VALID-but-not-QUALIFIED (no false "qualified"); missing TL data
  → `Indeterminate`. With the gate disabled, the always-on verdict is unchanged.
- **now-vs-relevant split**: a properly-signed TL that is STALE at `now` (`NextUpdate < now`) but whose
  `NextUpdate` is AFTER the credential's issuance time → `Indeterminate` (NOT `Qualified`) — even though the
  issuer is granted at the relevant time. A TL whose signer cert has EXPIRED by `now` but was valid at the
  credential's issuance time → `Indeterminate` (authentication fails). These prove authentication uses `now`
  while the status read uses the relevant time.
</content>
