# Contract: opt-in eIDAS qualified-status determination (ETSI TS 119 615 cl. 4.12)

An **opt-in** determination (off by default) layered over the always-on bar — never instead of it (the
spec-003 always-on-bar + opt-in-gate pattern). Decides whether the attestation is a **Qualified** EAA from a
qualified issuer. **Native Rust logic** (no reference engine computes QEAA qualification today); reuses the
trust-list primitives (`trust-anchor-source.md`) — DRY with the always-on bar.

## Operation

```
qualifiedStatus(issuer, now, relevantTime, trustList, schemeAnchors, typeIndication)
    -> Qualified | NotQualified | Indeterminate
```

`typeIndication` is the credential's self-declared qualified-EAA type — the PRO-4.12.4-03 input (step 2
below). Per **ETSI TS 119 472-1** it is the issuer-signed **`category`** claim (SD-JWT VC) / **`category`
data element** in namespace `org.etsi.01947201.010101` (ISO mdoc), carrying the URN
`urn:etsi:esi:eaa:eu:qualified` for a qualified EAA. It is **NOT** the `vct`/`docType` (the
credential-TYPE identifier, e.g. `urn:eudi:pid:1`, which is never the qualified URN). The precondition is
enforced for **both** formats: an absent `category` (an ordinary EAA, which TS 119 472-1 EAA-5.2.2.1-01
says MUST NOT carry `category`; or an mdoc document that did not disclose the element) ⇒ **Indeterminate**
(fail closed — never a false "qualified").

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
2. **QEAA type-indication precondition (PRO-4.12.4-03).** Check that the attestation self-declares the
   qualified-EAA type via the URN **`urn:etsi:esi:eaa:eu:qualified`**. Per **ETSI TS 119 472-1** this URN
   is carried in the issuer-signed **`category`** claim (SD-JWT VC) / the **`category` data element** in
   namespace `org.etsi.01947201.010101` (ISO mdoc) — **NOT** the `vct`/`docType`. If it is **not** present
   (or not that exact URN), set the result to **Indeterminate**
   (`ERROR_NO_ETSI_QEAA_TYPE_INDICATION_FOUND`) and STOP — never `Qualified`. The type indication is
   threaded from `verify()` for **both** formats: SD-JWT VC `issuer_category` (the `category` claim); ISO
   mdoc the per-document `category` data element surfaced by the always-on bar
   (`MdocVerifyMeta.categories`). An ordinary EAA (which TS 119 472-1 EAA-5.2.2.1-01 says MUST NOT carry
   `category`), or an mdoc document that did not disclose the element, has an absent indication ⇒
   Indeterminate (fail closed — the precondition is enforced for mdoc too, no longer skipped). **Version
   notes:** the URN is TS 119 615 v1.4.1's form (`…:esi:eaa:…`); v1.3.1 used the shorter
   `urn:etsi:eaa:eu:qualified`. The `category`-claim carrier is ETSI TS 119 472-1 v1.2.1 (verified online).
3. Match the issuer's signing cert against an `…/Svctype/EAA/Q` service's **service digital identity
   (Sdi, TS 119 612 §5.5.3)** by any of: exact **X509Certificate** DER, **X509SKI**
   (`SubjectKeyIdentifier`), or the **issuing-CA** relationship. The issuing-CA match is **fail-closed**:
   the leaf's `issuer` DN must equal the Sdi cert's `subject` DN **AND** the leaf's `AuthorityKeyIdentifier`
   must equal the Sdi cert's `SubjectKeyIdentifier` (both present and equal). A **bare issuer-DN collision
   is NOT sufficient** — two distinct CAs can share a subject DN, and chaining to *some* configured anchor
   does not prove the leaf was issued by *this* Sdi's CA (a false `Qualified` otherwise — SC-007). When the
   AKI/SKI key-identifier tie cannot be established, the issuing-CA path does not match. `X509SubjectName`
   is NOT machine-matched (§5.5.3: it *"should not be used by applications in machine processable way"*;
   EU DSS matches X509Certificate only).
4. Read the current/historical `granted` / `withdrawn` status **at the relevant time** (the credential's
   issuance/relevant time, NOT "now"). The relevant time is derived from the **credential**: SD-JWT VC `iat`
   (fallback `nbf`); mdoc MSO `validityInfo.signed` (fallback `validFrom`). A credential with no issuance
   time at all fails closed → **Indeterminate** (the verification instant is NEVER silently substituted).
5. Conclude **Qualified** (self-declared QEAA type AND granted at the relevant time) / **NotQualified**
   (self-declared, found, but not granted-`EAA/Q` at the relevant time) / **Indeterminate**.

## Invariants

- **No false "qualified"** (SC-007): `Qualified` is returned only on a positive determination; absent/
  ambiguous trust-list data ⇒ honest **`Indeterminate`** (never assume qualified).
- **QEAA type-indication precondition** (PRO-4.12.4-03): the attestation MUST self-declare the
  qualified-EAA type via the URN `urn:etsi:esi:eaa:eu:qualified` in its issuer-signed **`category`**
  (SD-JWT VC claim / mdoc `category` data element in namespace `org.etsi.01947201.010101`, per ETSI TS
  119 472-1) before a `Qualified` verdict; an attestation whose `category` is absent or ≠ the URN ⇒
  **`Indeterminate`**, even when the issuer is a granted `EAA/Q` QTSP. Enforced for **both** formats
  (mdoc is no longer exempt): a QEAA that does not carry the `category` URN is never `Qualified`.
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

- A qualified-issuer fixture (self-declared QEAA type, granted at the relevant time) → `Qualified`; a
  trusted-but-non-qualified issuer → `NotQualified` and the verdict is VALID-but-not-QUALIFIED (no false
  "qualified"); missing TL data → `Indeterminate`. With the gate disabled, the always-on verdict is unchanged.
- **Type-indication precondition (PRO-4.12.4-03)**: a granted-`EAA/Q` issuer signing an attestation
  WITHOUT the URN `urn:etsi:esi:eaa:eu:qualified` → `Indeterminate`; WITH the URN → `Qualified`.
- **Sdi matching (§5.5.3)**: a QEAA whose service entry lists the **issuing CA** (with the leaf's
  `AuthorityKeyIdentifier` matching the CA Sdi's `SubjectKeyIdentifier`) or a **X509SKI**, not the
  byte-identical leaf, is still matched → `Qualified` (not false-rejected as `Indeterminate`). The
  issuing-CA path is **fail-closed on the AKI==SKI tie**: a bare issuer-DN collision without that
  key-identifier match does NOT confer `Qualified` (a different CA sharing a subject DN must never
  mislabel a non-qualified issuer's credential — SC-007 "no false qualified").
- **now-vs-relevant split**: a properly-signed TL that is STALE at `now` (`NextUpdate < now`) but whose
  `NextUpdate` is AFTER the credential's issuance time → `Indeterminate` (NOT `Qualified`) — even though the
  issuer is granted at the relevant time. A TL whose signer cert has EXPIRED by `now` but was valid at the
  credential's issuance time → `Indeterminate` (authentication fails). These prove authentication uses `now`
  while the status read uses the relevant time.
</content>
