//! Revocation / status check (status list / CRL) with a fail-closed reachability policy (T014).
//!
//! The always-on bar (FR-003) includes revocation: a credential whose status mechanism says it is
//! revoked → INVALID `revoked`; one whose status cannot be reached → fail-closed by default →
//! INVALID `status_unavailable` (never a silent VALID). This module evaluates that check.
//!
//! ## Sans-IO (host seam — like the trust engine)
//!
//! The core performs no network I/O. A credential references its status mechanism (a Token Status
//! List pointer `uri`+`idx`, or a CRL the integrator names); the **host** fetches the referenced
//! status document and supplies its bytes, exactly as the trust engine takes fetched trust-list
//! bytes through `TrustListFetcher`. The fetch (network, caching, freshness of the *transport*) is
//! the host's; the *evaluation* and the **fail-closed policy** are the core's.
//!
//! Two host seams exist, at different trust levels:
//!
//! - **Authenticated in-core (the authoritative path, [`verify_status_list_token`]).** The host
//!   fetches the *signed* Token Status List Token by URI and hands the RAW token bytes to the core,
//!   which then AUTHENTICATES it end-to-end — verifies the JWS/`COSE_Sign1` signature under a key the
//!   caller's trust closure authorizes, binds `sub` to the credential's list URI, checks `exp`/`ttl`,
//!   zlib-inflates the bitstring, and reads the status bit itself. The core no longer trusts a
//!   host-supplied *outcome*; it re-derives it from the signed artifact (fail-closed on any doubt).
//!   The always-on [`verify()`](crate::verify()) entry point uses this whenever a credential declares a
//!   Token Status List reference and the host supplied the matching token.
//! - **Host-pre-resolved ([`StatusSource`] / [`check_status`]).** The legacy seam where the host has
//!   already authenticated + unpacked the status document and supplies the byte-per-entry array; the
//!   core only reads the bit under the fail-closed policy. Retained for CRL (host-resolved) and as the
//!   positional fallback when no signed token is supplied for a given list URI.
//!
//! ## Status mechanisms
//!
//! - **Token Status List** (IETF `draft-ietf-oauth-status-list` — the EUDI/HAIP baseline): a
//!   credential carries a `status.status_list = { idx, uri }`; the referenced list is a packed
//!   bit-array (1 or 2 bits per entry). A non-zero status value at `idx` is revoked/suspended.
//! - **CRL** (X.509 Certificate Revocation List): a credential is identified by an issuer-assigned
//!   serial; the referenced CRL enumerates revoked serials. Modelled abstractly here (the integrator
//!   supplies the parsed revoked-serial set) so the same fail-closed policy covers both.
//!
//! The decision maps to a single canonical [`StatusOutcome`] that the per-format verifiers consume
//! through their status seam (one authoritative status type — DRY).

use std::collections::BTreeMap;

use base64ct::{Base64UrlUnpadded, Encoding as _};
use ciborium::value::Value as CborValue;
use coset::{CoseSign1, Label, TaggedCborSerializable as _};
use p256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::datetime::{round_numeric_date_seconds, DateRounding};
use crate::types::StatusReachability;

/// The default per-document/per-credential status seam: a single [`StatusOutcome::NoStatus`] entry.
///
/// Used as the offline-suite / single-credential default for the positional `statuses` seam
/// ([`crate::verify::VerifyContext::statuses`], [`crate::mdoc`]'s params). It covers exactly ONE
/// document: an mdoc `DeviceResponse` carrying MORE than one document needs one [`StatusOutcome`] per
/// document (the per-document revocation check is positional), so an under-supplied multi-document
/// response fails closed to [`StatusOutcome::Unavailable`] rather than reusing one outcome for all.
pub const DEFAULT_STATUSES: &[StatusOutcome] = &[StatusOutcome::NoStatus];

/// The offline/typed default host-supplied Token Status List token map: EMPTY. Mirrors
/// [`DEFAULT_STATUSES`] as the `'static` default for the by-reference token seam
/// ([`crate::verify::VerifyContext::status_tokens`] — uri → the fetched *signed* status-list token
/// bytes). With no token supplied for a credential's list URI, the in-core authenticated path is not
/// taken and the verifier falls back to the positional [`StatusOutcome`] seam (host pre-resolved) —
/// so an empty map preserves the pre-existing behavior exactly (a credential with no status reference,
/// or no supplied token, verifies as before). Provided as a `static` (not a `const`) so a `&'static`
/// reference can back the offline `Default` without allocating a fresh map per call.
pub static DEFAULT_STATUS_TOKENS: BTreeMap<String, Vec<u8>> = BTreeMap::new();

/// The canonical outcome of the revocation/status check, consumed by both per-format verifiers'
/// status seam (the single authoritative status type — DRY, Principle III).
///
/// The per-format `verify` paths translate this into their reject reason: [`Self::Revoked`] →
/// [`ReasonCode::Revoked`], [`Self::Unavailable`] → [`ReasonCode::StatusUnavailable`], and
/// [`Self::NoStatus`]/[`Self::Good`] continue the bar. Carried across the C-ABI as CBOR (the host
/// resolves it through [`check_status`] and passes the outcome in), hence the `serde` derives.
///
/// [`ReasonCode::Revoked`]: crate::types::ReasonCode::Revoked
/// [`ReasonCode::StatusUnavailable`]: crate::types::ReasonCode::StatusUnavailable
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusOutcome {
    /// The credential declares no status mechanism — nothing to check (continue the bar).
    NoStatus,
    /// The status mechanism was reachable and says the credential is current.
    Good,
    /// The status mechanism says the credential is revoked or suspended.
    Revoked,
    /// The status document was unreachable (or unparseable) and the policy is fail-closed — never a
    /// silent VALID.
    Unavailable,
}

/// What a credential declares about its status mechanism (parsed from the credential), or the
/// absence of one.
///
/// This is the *reference* the host resolves: a Token Status List pointer (`uri`+`idx`), or a CRL
/// entry (a CRL location plus the credential's serial). The host fetches the referenced document and
/// supplies it via the [`StatusSource`] seam; the core then evaluates `idx`/serial against it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusReference {
    /// The credential declares no status mechanism.
    None,
    /// The credential declares a status mechanism (a `status_list` object IS present) but it is
    /// **unusable**: an empty/absent `uri`, a non-integer/absent `idx`, or the wrong CBOR/JSON types.
    /// This is DISTINCT from [`Self::None`] (no status claim at all): a present-but-malformed status
    /// reference MUST fail closed ([`StatusOutcome::Unavailable`]) — never fall through to a
    /// host-supplied positional `Good` — because the credential DID declare a revocation mechanism the
    /// core cannot evaluate, so it cannot prove the credential is current (SC-002, fail-closed).
    Malformed,
    /// A Token Status List reference: the index of this credential's entry and the list URI the host
    /// fetches.
    StatusList {
        /// The credential's entry index in the referenced status list.
        index: u64,
        /// The status-list URI the host resolves to the packed status document.
        uri: String,
    },
    /// A CRL reference: the credential's serial and the CRL location the host fetches.
    Crl {
        /// The credential's issuer-assigned serial (as bytes — X.509 serials are big integers).
        serial: Vec<u8>,
        /// The CRL distribution-point URI the host resolves to the revoked-serial set.
        uri: String,
    },
}

/// A host-driven source of fetched status documents (keeps the core sans-IO — Principle III).
///
/// Mirrors `crate::trust::engine::TrustListFetcher`: the core never performs network I/O; the host
/// fetches the referenced status document (network, transport caching) and returns its parsed form,
/// or `None` when it is unreachable. A `None` under [`StatusReachability::FailClosed`] is the
/// fail-closed reject; under [`StatusReachability::BestEffort`] it is tolerated.
///
/// **Host obligation on THIS seam — authenticate the status document.** A Token Status List (or CRL)
/// is a *signed* artifact (draft-ietf-oauth-status-list: a JWT/CWT signed by the status provider). This
/// seam receives the ALREADY-AUTHENTICATED, unpacked status array — a host using it MUST verify the
/// status-list token's signature (and that its signer is the credential's authorized status provider)
/// BEFORE unpacking and returning the bytes, because [`check_status`] does not see the signed token.
///
/// **Prefer the in-core authenticated path.** For a Token Status List the authoritative surface is
/// [`verify_status_list_token`], which takes the RAW signed token and authenticates it end-to-end
/// inside the core (signature + `sub` binding + freshness + bit read) — so a host that returned an
/// unauthenticated (e.g. attacker-served) array here would NOT defeat revocation, because the
/// always-on verifier reads the bit from the signed token itself when one is supplied. This seam
/// remains for CRL (host-resolved) and as the positional fallback when no signed token is available.
pub trait StatusSource {
    /// Fetch the packed Token Status List bytes for `uri`, or `None` if unreachable.
    ///
    /// The bytes are the **unpacked** status array: one byte per entry holding that entry's status
    /// value (`0` = valid; non-zero = revoked/suspended). The host is responsible for decompressing /
    /// bit-unpacking the wire form (the CBOR/JWT-wrapped, optionally DEFLATE-compressed bitstring)
    /// into this byte-per-entry view. (The in-core [`verify_status_list_token`] path instead
    /// zlib-inflates the bitstring itself — this pre-unpacked seam is the host-pre-resolved fallback.)
    fn fetch_status_list(&self, uri: &str) -> Option<Vec<u8>>;

    /// Fetch the set of revoked serials for the CRL at `uri`, or `None` if unreachable.
    ///
    /// Each entry is a revoked credential serial (big-endian bytes). The host parses the DER CRL (or
    /// its cached form) into this set; the core checks membership.
    fn fetch_crl_revoked_serials(&self, uri: &str) -> Option<Vec<Vec<u8>>>;
}

/// Evaluate a credential's status against the host-supplied status documents, applying the
/// fail-closed reachability policy.
///
/// - [`StatusReference::None`] → [`StatusOutcome::NoStatus`].
/// - [`StatusReference::Malformed`] → [`StatusOutcome::Unavailable`] (a declared-but-uninterpretable
///   status reference fails closed regardless of reachability — never a silent VALID).
/// - A reachable status list / CRL → [`StatusOutcome::Revoked`] if the entry is revoked, else
///   [`StatusOutcome::Good`].
/// - An **unreachable** status document → [`StatusOutcome::Unavailable`] under
///   [`StatusReachability::FailClosed`] (the secure default), or [`StatusOutcome::Good`] under
///   [`StatusReachability::BestEffort`] (the credential is not failed on reachability alone).
///
/// Sans-IO: the status documents are supplied through `source`; this performs no network I/O.
#[must_use]
pub fn check_status<S: StatusSource + ?Sized>(
    reference: &StatusReference,
    source: &S,
    reachability: StatusReachability,
) -> StatusOutcome {
    match reference {
        StatusReference::None => StatusOutcome::NoStatus,
        // A present-but-uninterpretable status reference fails closed (never reachability-dependent):
        // the credential declared a mechanism the core cannot evaluate, so it cannot be proven current.
        StatusReference::Malformed => StatusOutcome::Unavailable,
        StatusReference::StatusList { index, uri } => source.fetch_status_list(uri).map_or_else(
            || unreachable_outcome(reachability),
            |list| evaluate_status_list(&list, *index),
        ),
        StatusReference::Crl { serial, uri } => source.fetch_crl_revoked_serials(uri).map_or_else(
            || unreachable_outcome(reachability),
            |revoked| {
                if revoked.iter().any(|s| s == serial) {
                    StatusOutcome::Revoked
                } else {
                    StatusOutcome::Good
                }
            },
        ),
    }
}

/// Map an unreachable status document to the policy outcome: fail-closed → `Unavailable` (the secure
/// default, never a silent VALID); best-effort → `Good` (tolerate, do not fail on reachability).
const fn unreachable_outcome(reachability: StatusReachability) -> StatusOutcome {
    match reachability {
        StatusReachability::FailClosed => StatusOutcome::Unavailable,
        StatusReachability::BestEffort => StatusOutcome::Good,
    }
}

/// Read the status value at `index` in an unpacked status array (one byte per entry). A `0` value is
/// valid; any non-zero value (revoked / suspended / application-defined) is treated as revoked. An
/// out-of-range index is a malformed/short list → fail-closed `Unavailable` (the core cannot prove
/// the credential is current).
fn evaluate_status_list(list: &[u8], index: u64) -> StatusOutcome {
    match usize::try_from(index).ok().and_then(|i| list.get(i)) {
        Some(0) => StatusOutcome::Good,
        Some(_) => StatusOutcome::Revoked,
        None => StatusOutcome::Unavailable,
    }
}

// =================================================================================================
// IN-CORE Token Status List verifier (draft-ietf-oauth-status-list-21).
//
// The [`StatusSource`] seam above trusts a host-supplied, already-authenticated status array. This
// section is the SECURITY CORE that removes that trust: given the *signed* Status List Token the host
// fetched by URI (still sans-IO — the host does the network), the core AUTHENTICATES it end-to-end and
// reads the status bit itself. Every check below is fail-closed: on ANY doubt the outcome is
// [`StatusOutcome::Unavailable`], NEVER [`StatusOutcome::Good`] (a false-VALID is the one outcome a
// revocation check must never produce). The signing-key TRUST decision (does the signer chain to the
// credential's anchor + bear the status-signing EKU, or is it the issuer's own key?) is deliberately
// NOT made here — it needs the trust anchors, which live in `crate::trust`; this module hands the
// token's embedded signer hint to a caller-supplied closure and verifies the signature with the key
// that closure authorizes (sans-IO / DRY — trust has one home).
// =================================================================================================

/// The compact-JWS (JOSE) Status List Token protected-header `typ` — REQUIRED to be exactly this
/// (draft-ietf-oauth-status-list-21 §5.1); any other/absent `typ` is rejected. This is the SD-JWT VC
/// baseline form.
const JWT_TYP: &str = "statuslist+jwt";

/// The JOSE `alg` the EUDI baseline pins for the Status List Token JWS — ES256 only; any other `alg`
/// (or a `crit` header) is rejected.
const JOSE_ALG_ES256: &str = "ES256";

/// The COSE protected-header `typ` parameter label (RFC 9596 registers `typ` at COSE label 16). The
/// CWT Status List Token carries its media type here; a status-list CWT REQUIRES this label to hold
/// [`COSE_TYP_VALUE`] (draft-ietf-oauth-status-list-21 §5.2).
const COSE_HEADER_TYP_LABEL: i64 = 16;

/// The CWT (COSE) Status List Token protected-header `typ` value — REQUIRED to be exactly this. The
/// mdoc baseline form.
const COSE_TYP_VALUE: &str = "application/statuslist+cwt";

// --- CWT claim keys (integer labels). Standard claims are RFC 8392; the status-list claims are ------
//     PROVISIONAL per draft-ietf-oauth-status-list-21 (marked TBD, pending IANA registration) and are
//     single-sourced here so an eventual reassignment is a one-line change.
/// CWT `sub` claim key (RFC 8392) — the Status List Token's own URI, bound to the credential's
/// `status_list.uri`.
const CWT_CLAIM_SUB: i128 = 2;
/// CWT `exp` claim key (RFC 8392).
const CWT_CLAIM_EXP: i128 = 4;
/// CWT `iat` claim key (RFC 8392).
const CWT_CLAIM_IAT: i128 = 6;
/// CWT `ttl` claim key — **PROVISIONAL** (draft-ietf-oauth-status-list-21 §5.2; TBD, pending IANA).
const CWT_CLAIM_TTL: i128 = 65_534;
/// CWT `status_list` claim key — **PROVISIONAL** (draft-ietf-oauth-status-list-21 §5.2; TBD, pending
/// IANA).
const CWT_CLAIM_STATUS_LIST: i128 = 65_533;

/// The optional RFC 8392 CWT CBOR tag (`#6.61`). A Status List Token's `COSE_Sign1` payload is the bare
/// CWT Claims Set map, but a producer MAY wrap it in this tag; unwrapped defensively.
const CWT_CBOR_TAG: u64 = 61;

/// A decompression-bomb guard: the maximum accepted DECOMPRESSED status-list size (64 MiB). A single
/// Token Status List of 64 MiB covers a national-population list even at the widest 8-bit entries
/// (≈67M entries) / 512M entries at 1 bit, so this never clips a realistic list; a compressed input
/// that would inflate beyond it fails closed to [`StatusOutcome::Unavailable`] rather than risking OOM.
/// Decompression only ever runs AFTER the token signature is verified (so the input is from a signer
/// the caller authorized), but this bounds the blast radius regardless (`miniz_oxide`'s own docs advise
/// against unbounded inflate outside tests).
const MAX_STATUS_LIST_BYTES: usize = 64 * 1024 * 1024;

/// The X.509 Extended Key Usage `KeyPurposeId` that authorizes a certificate to sign a Token Status
/// List — `id-kp-oauthStatusSigning` (draft-ietf-oauth-status-list-21 §13).
///
/// **PLACEHOLDER — `id-kp-oauthStatusSigning` is IANA-TBD.** The draft defines this as `{ id-kp TBD }`:
/// the PKIX `id-kp` arc (OID `1.3.6.1.5.5.7.3` = `iso(1) identified-organization(3) dod(6) internet(1)
/// security(5) mechanisms(5) pkix(7) kp(3)`) with a FINAL sub-arc that IANA has **not yet assigned**.
/// The real id-kp sub-arcs start at `.1` (serverAuth=`.1`, clientAuth=`.2`, …), so this placeholder uses
/// the **`.0`** terminal arc — a syntactically valid OID that matches **NO** real certificate
/// (fail-closed). It keeps the distinct status-signer authorization path wired + testable via an EXACT
/// OID match (never a prefix/arc match, which would unsoundly accept serverAuth/clientAuth as
/// status-signing). Replace this ONE constant with the assigned OID when IANA publishes — a single-line,
/// single-place update (DRY); the exact-match consumer needs no other change.
///
/// The EKU authorization DECISION is **not** made in this sans-IO module — it lives in `crate::trust`
/// (layer 2), whose `leaf_has_status_signing_eku` consumes this constant to check
/// whether a status-list signer's leaf certificate bears EXACTLY the status-signing purpose. It is
/// exposed here only so the value has one authoritative home.
pub const STATUS_SIGNING_EKU_OID_PLACEHOLDER: &str = "1.3.6.1.5.5.7.3.0";

/// The signer-identifying material a Status List Token embeds, handed to the caller's key-resolution
/// closure ([`verify_status_list_token`]'s `resolve_key`) so that `crate::trust` (layer 2) can
/// AUTHORIZE the signer WITHOUT this sans-IO module holding any trust anchors. The module extracts
/// this from the token header and performs the signature verification with whatever [`VerifyingKey`]
/// the closure returns; the trust/EKU policy is entirely the closure's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignerKeyMaterial {
    /// The signer's X.509 certificate chain (DER, **leaf-first**), from the token's `x5c` (JOSE, RFC
    /// 7515 §4.1.6 — base64 *standard*) or `x5chain` (COSE label 33, RFC 9360 — `bstr`/array of
    /// `bstr`) header. Empty when the token carries no chain (a `kid`-only token — the closure then
    /// resolves against the credential's own issuer key, or rejects).
    ///
    /// A `kid` header is intentionally NOT surfaced: the reworked signer authorization
    /// (`authorize_status_signer`) grants nothing off a `kid` — a chain-less token is authorized ONLY
    /// to the credential's own issuer key (and then only if the signature verifies under it), so the
    /// raw `kid` bytes carry no authorization weight and are not parsed.
    pub x5chain: Vec<Vec<u8>>,
}

/// Authenticate a *signed* Token Status List Token and read this credential's status bit from it,
/// returning the canonical [`StatusOutcome`] (draft-ietf-oauth-status-list-21). Both wire forms are
/// accepted and auto-detected: a compact JWS (`statuslist+jwt`, SD-JWT VC baseline — pure ASCII) or a
/// tagged `COSE_Sign1` CWT (`application/statuslist+cwt`, mdoc baseline — binary CBOR beginning with
/// the tag-18 byte `0xD2`). The host fetched `token` by URI (sans-IO — the network is the host's); this
/// verifies it in-core.
///
/// Fail-closed contract: EVERY check must hold, else the result is [`StatusOutcome::Unavailable`],
/// NEVER [`StatusOutcome::Good`]. In order:
/// 1. **Signature** — JWS ES256 / `COSE_Sign1` ES256 under the key `resolve_key` authorizes; a bad
///    signature, non-ES256 `alg`, wrong `typ`, present `crit`, or `COSE_Mac0` (tag 17) → `Unavailable`.
/// 2. **Subject binding** — the token's `sub` MUST byte-exactly equal `expected_uri` (the credential's
///    `status_list.uri`); a validly-signed list for a *different* URI is rejected.
/// 3. **Freshness** — a present `exp` MUST be `> now_unix`; a present `ttl` requires `iat + ttl >=
///    now_unix` (else the cached token is stale). `iat` is REQUIRED.
/// 4. **Bit** — the `lst` bitstring is zlib-inflated and the `bits`-wide, LSB-first entry at `idx` is
///    read (an out-of-range `idx` → `Unavailable`, never `Good`) and mapped through the status
///    registry (0=VALID→`Good`, 1=INVALID→`Revoked`, 2=SUSPENDED→`Revoked`, else→`Unavailable`).
///
/// `resolve_key` receives the token's parsed [`SignerKeyMaterial`] and returns the [`VerifyingKey`] to
/// verify under (or `Err(())` to reject). The signing-key TRUST/EKU decision is the closure's — layer 2
/// implements it against `crate::trust`; this module only parses the hint and does the crypto.
#[must_use]
pub fn verify_status_list_token<F>(
    token: &[u8],
    expected_uri: &str,
    idx: u64,
    now_unix: i64,
    resolve_key: F,
) -> StatusOutcome
where
    F: FnOnce(&SignerKeyMaterial) -> Result<VerifyingKey, ()>,
{
    // The public entry authenticates + inflates afresh (no shared memo — a single-token caller). The
    // multi-document mdoc path uses [`verify_status_list_token_cached`] to share the inflate per URI.
    verify_status_list_token_cached(
        token,
        expected_uri,
        idx,
        now_unix,
        resolve_key,
        &mut StatusListInflateCache::new(),
    )
}

/// A per-verify memo of the zlib-inflated Token Status List bytes, keyed by the credential's list URI.
///
/// Threaded through a multi-document mdoc verify so the (attacker-multipliable) up-to-
/// [`MAX_STATUS_LIST_BYTES`] inflate runs ONCE per distinct list URI rather than once per document that
/// references it: a `DeviceResponse` replaying one credential N times inflates the shared list ONCE,
/// not N times (a decompression-DoS-amplification cap). The stored `Option` also caches a FAILED inflate
/// (a cap-exceeding / corrupt `lst` → `None`) so a re-referenced bad list is not re-inflated per document.
///
/// **Soundness (no false-accept).** Memoizing by URI is safe because the inflate is a pure function of
/// the single, host-fetched-by-URI token — trust-context-INDEPENDENT. Every document still independently
/// runs the signer authorization, the ES256 signature verification, the `sub` binding, and the freshness
/// check BEFORE this memo is consulted (it is reached only inside [`evaluate_status_claims`], after those
/// pass), so a document whose token fails to authenticate returns `Unavailable` without ever reaching
/// (or benefiting from) the cache. Each document then reads its OWN `idx` from the shared decompressed
/// bytes (the bit read is per-`idx`; only the verify-preceding inflate is shared per URI).
pub(crate) type StatusListInflateCache = BTreeMap<String, Option<Vec<u8>>>;

/// [`verify_status_list_token`] threading a per-verify [`StatusListInflateCache`] so a status list that
/// several documents of one `DeviceResponse` reference is zlib-inflated ONCE per URI (see the cache's
/// soundness note). Identical semantics to the public entry for any single document; only the inflate is
/// shared. The form detection + all fail-closed checks are unchanged.
#[must_use]
pub(crate) fn verify_status_list_token_cached<F>(
    token: &[u8],
    expected_uri: &str,
    idx: u64,
    now_unix: i64,
    resolve_key: F,
    inflate_cache: &mut StatusListInflateCache,
) -> StatusOutcome
where
    F: FnOnce(&SignerKeyMaterial) -> Result<VerifyingKey, ()>,
{
    // Form detection: a compact JWS is entirely ASCII (the base64url alphabet + `.`), whereas a tagged
    // `COSE_Sign1` CWT is binary CBOR whose first byte is the tag-18 marker `0xD2` (non-ASCII). So an
    // all-ASCII token takes the JOSE path and everything else the COSE path; a blob that matches
    // neither form's structure fails its path and folds to `Unavailable` below (never re-tried as the
    // other form — a mis-shaped token is simply rejected, fail-closed).
    let outcome = match core::str::from_utf8(token) {
        Ok(text) if token.is_ascii() => verify_jwt_status_list(
            text,
            expected_uri,
            idx,
            now_unix,
            resolve_key,
            inflate_cache,
        ),
        _ => verify_cwt_status_list(
            token,
            expected_uri,
            idx,
            now_unix,
            resolve_key,
            inflate_cache,
        ),
    };
    // Any hard failure (`None`) OR an unknown status value collapses to the fail-closed outcome; only a
    // fully authenticated token with a known status value yields `Good`/`Revoked`.
    outcome.unwrap_or(StatusOutcome::Unavailable)
}

/// The wire-independent Status List claims both forms parse into, so authentication finishes through
/// one shared evaluator ([`evaluate_status_claims`]) — DRY. `lst` holds the still-COMPRESSED
/// (zlib) bitstring (already base64url-decoded on the JOSE path; the raw `bstr` on the COSE path).
struct StatusListClaims {
    sub: String,
    iat: i64,
    exp: Option<i64>,
    ttl: Option<i64>,
    bits: u8,
    lst: Vec<u8>,
}

/// Verify a compact-JWS (JOSE) Status List Token. Returns `None` on ANY deviation (the caller maps
/// `None` → [`StatusOutcome::Unavailable`]).
fn verify_jwt_status_list<F>(
    token: &str,
    expected_uri: &str,
    idx: u64,
    now_unix: i64,
    resolve_key: F,
    inflate_cache: &mut StatusListInflateCache,
) -> Option<StatusOutcome>
where
    F: FnOnce(&SignerKeyMaterial) -> Result<VerifyingKey, ()>,
{
    // Compact JWS framing: EXACTLY three `.`-segments (header.payload.signature) — the shared framing
    // check ([`crate::sdjwtvc::split_compact_jws`], DRY — the SD-JWT VC issuer path uses the same).
    let (header_b64, payload_b64, sig_b64) = crate::sdjwtvc::split_compact_jws(token)?;

    // Protected header (base64url → JSON) + the mandated header gates.
    let header: JsonValue = decode_json_b64url(header_b64)?;
    if header.get("typ").and_then(JsonValue::as_str) != Some(JWT_TYP) {
        return None; // wrong/absent media type — not a Status List Token JWS
    }
    if header.get("alg").and_then(JsonValue::as_str) != Some(JOSE_ALG_ES256) {
        return None; // non-ES256 rejected on the algorithm alone, before any signature math
    }
    if header.get("crit").is_some() {
        // This verifier implements no critical extension header; RFC 7515 §4.1.11 makes any listed
        // `crit` extension we do not understand fatal — reject a present `crit` of any shape.
        return None;
    }

    // Parse the signer hint, let the caller authorize + resolve the key, THEN verify the signature over
    // the ASCII `header.payload` signing input (the shared [`crate::sdjwtvc::verify_es256_signing_input`]
    // — raw `r‖s` ES256, the crate's one JOSE signing-input verify). The header gate + key resolution
    // still precede the signature exactly as before.
    let material = jose_signer_material(&header)?;
    let key = resolve_key(&material).ok()?;
    crate::sdjwtvc::verify_es256_signing_input(header_b64, payload_b64, sig_b64, &key).ok()?;

    // Only now (authenticated) parse the payload claims + evaluate.
    let payload: JsonValue = decode_json_b64url(payload_b64)?;
    let claims = jose_status_claims(&payload)?;
    evaluate_status_claims(&claims, expected_uri, idx, now_unix, inflate_cache)
}

/// Base64url-unpadded-decode a compact-JWS segment and parse it as JSON.
fn decode_json_b64url(segment: &str) -> Option<JsonValue> {
    let raw = Base64UrlUnpadded::decode_vec(segment).ok()?;
    serde_json::from_slice(&raw).ok()
}

/// Parse the JOSE signer hint from a Status List Token header: the `x5c` chain (base64 *standard* DER,
/// leaf-first — RFC 7515 §4.1.6). A present-but-malformed `x5c` (not an array, or an entry that is not
/// base64) → `None` (fail-closed); an absent `x5c` yields an empty chain (a chain-less token — the
/// closure resolves against the credential's own issuer key). The per-entry base64-DER decode is the
/// shared [`crate::sdjwtvc::x5c_entries_from_json_array`] (DRY — the SD-JWT VC issuer path uses the same,
/// with its own present-and-non-empty-required policy).
fn jose_signer_material(header: &JsonValue) -> Option<SignerKeyMaterial> {
    let x5chain = match header.get("x5c") {
        None => Vec::new(),
        Some(x5c) => crate::sdjwtvc::x5c_entries_from_json_array(x5c.as_array()?)?,
    };
    Some(SignerKeyMaterial { x5chain })
}

/// Parse the Status List Token JSON payload claims. `sub` and `status_list` are REQUIRED; `iat` is a
/// REQUIRED NumericDate; `exp`/`ttl` are OPTIONAL but, when present, MUST be numbers (a present-but-
/// non-numeric bound is malformed → `None`, fail-closed — never silently ignored). RFC 7519 §2 permits
/// a FRACTIONAL NumericDate, so `iat`/`exp`/`ttl` accept a JSON number and round it to whole seconds
/// through the shared [`round_numeric_date_seconds`] core (a conformant `"exp": 1893456000.5` is no
/// longer false-rejected). All three round **up** ([`DateRounding::Up`]): `exp` keeps the exclusive-
/// upper `now >= exp` semantics against the whole-second clock, and rounding both `iat` and `ttl` up
/// keeps the freshness deadline `iat + ttl >= now` from prematurely marking a conformant token stale.
fn jose_status_claims(payload: &JsonValue) -> Option<StatusListClaims> {
    let sub = payload.get("sub").and_then(JsonValue::as_str)?.to_owned();
    let iat = json_numeric_seconds(payload.get("iat")?, DateRounding::Up)?;
    let exp = optional_numeric_date(payload.get("exp"), |v| {
        json_numeric_seconds(v, DateRounding::Up)
    })
    .ok()?;
    let ttl = optional_numeric_date(payload.get("ttl"), |v| {
        json_numeric_seconds(v, DateRounding::Up)
    })
    .ok()?;
    let status_list = payload.get("status_list")?;
    let bits = status_list
        .get("bits")
        .and_then(JsonValue::as_u64)
        .and_then(validate_bits)?;
    let lst_b64url = status_list.get("lst").and_then(JsonValue::as_str)?;
    let lst = Base64UrlUnpadded::decode_vec(lst_b64url).ok()?;
    Some(StatusListClaims {
        sub,
        iat,
        exp,
        ttl,
        bits,
        lst,
    })
}

/// Read an OPTIONAL numeric claim, distinguishing all three states: `Ok(None)` when absent,
/// `Ok(Some(v))` when `extract` yields a value, `Err(())` when present-but-`extract`-rejected (malformed
/// → the call site's `.ok()?` turns that into the fail-closed reject). A `Result` (not `Option<Option>`)
/// so the "absent vs malformed" distinction is explicit. Generic over the value type so the JOSE
/// (`JsonValue`, via [`json_numeric_seconds`]) and CWT (`CborValue`, via [`cbor_numeric_seconds`]) paths
/// share one shape (DRY — Principle III).
fn optional_numeric_date<T>(
    value: Option<&T>,
    extract: impl FnOnce(&T) -> Option<i64>,
) -> Result<Option<i64>, ()> {
    value.map_or(Ok(None), |v| extract(v).map(Some).ok_or(()))
}

/// Reduce a present JSON NumericDate value to whole `i64` seconds (RFC 7519 §2 permits a FRACTIONAL
/// NumericDate): a canonical integer that fits `i64` is taken verbatim; any other JSON number is
/// rounded in `rounding`'s direction through the shared [`round_numeric_date_seconds`] core; a
/// non-number (or one that rounds outside `i64`) → `None` (the caller fails closed).
fn json_numeric_seconds(value: &JsonValue, rounding: DateRounding) -> Option<i64> {
    value.as_i64().or_else(|| {
        value
            .as_f64()
            .and_then(|s| round_numeric_date_seconds(s, rounding))
    })
}

/// Verify a tagged `COSE_Sign1` (CWT) Status List Token. Returns `None` on ANY deviation (the caller
/// maps `None` → [`StatusOutcome::Unavailable`]).
fn verify_cwt_status_list<F>(
    token: &[u8],
    expected_uri: &str,
    idx: u64,
    now_unix: i64,
    resolve_key: F,
    inflate_cache: &mut StatusListInflateCache,
) -> Option<StatusOutcome>
where
    F: FnOnce(&SignerKeyMaterial) -> Result<VerifyingKey, ()>,
{
    // REQUIRE a TAGGED `COSE_Sign1` (CBOR tag 18): `from_tagged_slice` checks the tag, so a `COSE_Mac0`
    // (tag 17 — no third-party verifiability) OR an untagged array is rejected here, and trailing bytes
    // after the item are rejected as extraneous data (coset).
    let sign1 = CoseSign1::from_tagged_slice(token).ok()?;
    cose_header_ok(&sign1)?;

    // Parse the signer hint, let the caller authorize + resolve the key, THEN verify the `COSE_Sign1`
    // ES256 signature over the `Sig_structure` (built by coset, no external AAD).
    let material = cose_signer_material(&sign1)?;
    let key = resolve_key(&material).ok()?;
    sign1
        .verify_signature(&[], |sig, tbs| {
            crate::crypto::p256_verify_es256(&key, tbs, sig)
        })
        .ok()?;

    // Only now (authenticated) decode the CWT Claims Set payload + evaluate.
    let payload = sign1.payload.as_ref()?;
    let claims_cbor: CborValue = ciborium::from_reader(payload.as_slice()).ok()?;
    let claims = cwt_status_claims(&claims_cbor)?;
    evaluate_status_claims(&claims, expected_uri, idx, now_unix, inflate_cache)
}

/// Enforce the CWT Status List Token protected-header gates: `alg` MUST be ES256 (COSE −7); `crit` MUST
/// list nothing beyond `alg` (any other critical header is unprocessed → fatal, RFC 9052 §3.1); and the
/// `typ` parameter (label 16) MUST be present in the PROTECTED header holding [`COSE_TYP_VALUE`].
///
/// The `alg`==ES256 gate and the `crit` enforcement are the crate's shared
/// [`crate::mdoc::cose_alg_is_es256`] + [`crate::mdoc::reject_unprocessed_crit`] (DRY — the mdoc
/// `IssuerAuth`/`DeviceSignature` verifiers gate identically); only the status-list-specific `typ`
/// check is local.
fn cose_header_ok(sign1: &CoseSign1) -> Option<()> {
    if !crate::mdoc::cose_alg_is_es256(sign1) {
        return None;
    }
    // RFC 9052 §3.1: any critical header beyond the understood `alg` is fatal (the shared predicate).
    if !crate::mdoc::cose_crit_all_understood(sign1) {
        return None;
    }
    let typ = sign1
        .protected
        .header
        .rest
        .iter()
        .find_map(|(l, v)| (*l == Label::Int(COSE_HEADER_TYP_LABEL)).then_some(v));
    match typ.and_then(CborValue::as_text) {
        Some(t) if t == COSE_TYP_VALUE => Some(()),
        _ => None,
    }
}

/// Parse the COSE signer hint: the `x5chain` (label 33, protected or unprotected). A present-but-
/// malformed `x5chain` → `None`; an absent one yields an empty chain (a chain-less token — the closure
/// resolves against the credential's own issuer key). No `kid` is surfaced (see [`SignerKeyMaterial`]).
fn cose_signer_material(sign1: &CoseSign1) -> Option<SignerKeyMaterial> {
    let x5chain = cose_x5chain(sign1)?;
    Some(SignerKeyMaterial { x5chain })
}

/// Resolve the `x5chain` (DER, leaf-first) from a `COSE_Sign1` header — a single `bstr`, or a non-empty
/// array of `bstr`. `Some(empty)` when absent, `Some(chain)` when well-formed, `None` when present-but-
/// malformed. The `bstr`|array-of-`bstr` parse is the shared [`crate::mdoc::x5chain_entries_from_cbor`]
/// (DRY — the mdoc DS `x5chain` reader uses the same); this status reader additionally scans BOTH the
/// protected and unprotected headers and treats absent as an empty chain (the mdoc DS path is
/// unprotected-only and treats absent as malformed).
fn cose_x5chain(sign1: &CoseSign1) -> Option<Vec<Vec<u8>>> {
    let label = Label::Int(crate::mdoc::COSE_HEADER_X5CHAIN);
    let value = sign1
        .protected
        .header
        .rest
        .iter()
        .chain(sign1.unprotected.rest.iter())
        .find_map(|(l, v)| (*l == label).then_some(v));
    value.map_or(Some(Vec::new()), crate::mdoc::x5chain_entries_from_cbor)
}

/// Parse the CWT Claims Set (a CBOR map, optionally `#6.61`-tagged) into [`StatusListClaims`]. `sub`
/// (key 2, tstr) and `status_list` (key 65533) are REQUIRED; `iat` (key 6) is a REQUIRED integer;
/// `exp` (key 4) / `ttl` (key 65534) are OPTIONAL integers. The `status_list` value is a CBOR map with
/// TEXT keys `bits` (uint) and `lst` (raw compressed `bstr` — NOT base64url in the COSE form).
fn cwt_status_claims(value: &CborValue) -> Option<StatusListClaims> {
    let claims_value = match value {
        CborValue::Tag(CWT_CBOR_TAG, inner) => inner.as_ref(),
        other => other,
    };
    let map = claims_value.as_map()?;
    let sub = cbor_int_key(map, CWT_CLAIM_SUB)?.as_text()?.to_owned();
    // `iat`/`exp`/`ttl` accept a FRACTIONAL NumericDate (RFC 8392) — a CBOR float — and round to whole
    // seconds through the shared core, all UP ([`DateRounding::Up`]) for the same reason as the JOSE
    // path (exclusive-upper `exp`; a non-prematurely-stale `iat + ttl` freshness deadline).
    let iat = cbor_numeric_seconds(cbor_int_key(map, CWT_CLAIM_IAT)?, DateRounding::Up)?;
    let exp = optional_numeric_date(cbor_int_key(map, CWT_CLAIM_EXP), |v| {
        cbor_numeric_seconds(v, DateRounding::Up)
    })
    .ok()?;
    let ttl = optional_numeric_date(cbor_int_key(map, CWT_CLAIM_TTL), |v| {
        cbor_numeric_seconds(v, DateRounding::Up)
    })
    .ok()?;
    let status_list = cbor_int_key(map, CWT_CLAIM_STATUS_LIST)?;
    // The `status_list` sub-map uses TEXT keys — read via the shared [`crate::mdoc::get_map_entry`] (3a).
    let bits = crate::mdoc::get_map_entry(status_list, "bits")
        .and_then(cbor_u64)
        .and_then(validate_bits)?;
    let lst = crate::mdoc::get_map_entry(status_list, "lst")?
        .as_bytes()?
        .clone();
    Some(StatusListClaims {
        sub,
        iat,
        exp,
        ttl,
        bits,
        lst,
    })
}

/// Reduce a present CBOR NumericDate value to whole `i64` seconds (RFC 8392 permits a FRACTIONAL
/// NumericDate): a CBOR integer that fits `i64` is taken verbatim; a CBOR float is rounded in
/// `rounding`'s direction through the shared [`round_numeric_date_seconds`] core; any other CBOR type
/// (or a value that rounds outside `i64`) → `None` (the caller fails closed).
fn cbor_numeric_seconds(value: &CborValue, rounding: DateRounding) -> Option<i64> {
    match value {
        // The integer→`i64` read is the crate's shared [`crate::mdoc::integer_label`] (DRY).
        CborValue::Integer(_) => crate::mdoc::integer_label(value),
        CborValue::Float(f) => round_numeric_date_seconds(*f, rounding),
        _ => None,
    }
}

/// Find an INTEGER-keyed entry in a CBOR association-list map (the CWT claim keys are integers — RFC
/// 8392; distinct from the text-keyed [`crate::mdoc::get_map_entry`] used for the `status_list` sub-map).
fn cbor_int_key(map: &[(CborValue, CborValue)], label: i128) -> Option<&CborValue> {
    map.iter().find_map(|(k, v)| match k {
        CborValue::Integer(i) if i128::from(*i) == label => Some(v),
        _ => None,
    })
}

/// A CBOR integer value as `u64`, or `None` if it is not an integer / out of `u64` range. (The `i64`
/// counterpart is the shared [`crate::mdoc::integer_label`]; a `u64` reader is kept local because
/// `integer_label` is `i64`-typed and a status `idx`/`bits` is an unsigned CBOR uint whose full `u64`
/// range must be preserved — narrowing it to `i64` would reclassify a huge-but-valid `idx`.)
fn cbor_u64(value: &CborValue) -> Option<u64> {
    match value {
        CborValue::Integer(i) => u64::try_from(i128::from(*i)).ok(),
        _ => None,
    }
}

/// The shared post-authentication evaluator (both forms): subject binding (D.2), freshness (D.3), then
/// the bit read + status-registry mapping (B/C). Returns `None` for any hard failure (→ `Unavailable`)
/// or `Some(outcome)` — where the outcome is itself `Unavailable` for an unknown status value (unknown
/// is NEVER coerced to `Good`).
fn evaluate_status_claims(
    claims: &StatusListClaims,
    expected_uri: &str,
    idx: u64,
    now_unix: i64,
    inflate_cache: &mut StatusListInflateCache,
) -> Option<StatusOutcome> {
    // D.2 — bind THIS signed list to THIS credential: `sub` MUST byte-exactly equal the credential's
    // `status_list.uri`. A validly-signed list for a different URI is rejected (defeats a swap attack).
    if claims.sub != expected_uri {
        return None;
    }
    // D.3 — temporal validity of the token itself.
    check_status_token_time(claims.iat, claims.exp, claims.ttl, now_unix)?;
    // B — inflate the zlib bitstring (memoized per URI within this verify — see the cache's soundness
    // note; the sub-binding + freshness above are re-checked per document, so the memo is only consulted
    // for a token THIS document already authenticated), then read the `bits`-wide LSB-first entry at `idx`.
    let bytes = decompress_status_list_memoized(expected_uri, &claims.lst, inflate_cache)?;
    let value = extract_status_value(bytes, idx, claims.bits)?;
    // C — status registry → canonical outcome.
    Some(status_value_to_outcome(value))
}

/// Return the zlib-inflated status-list bytes for `uri`, inflating (through
/// [`decompress_status_list`]) at most ONCE per URI within a single verify and caching the result — a
/// success (`Some(bytes)`) or a fail-closed failure (`None`, e.g. cap-exceeding/corrupt `lst`) — in
/// `inflate_cache`. The compressed `lst` is invariant for a given URI (the host supplies ONE token per
/// URI), so the memo is keyed by URI alone. See [`StatusListInflateCache`] for why this preserves exact
/// per-document semantics (each document re-runs signature/`sub`/freshness before reaching here).
fn decompress_status_list_memoized<'a>(
    uri: &str,
    compressed: &[u8],
    inflate_cache: &'a mut StatusListInflateCache,
) -> Option<&'a [u8]> {
    inflate_cache
        .entry(uri.to_owned())
        .or_insert_with(|| decompress_status_list(compressed))
        .as_deref()
}

/// Enforce the Status List Token's own temporal validity (draft-ietf-oauth-status-list-21 §5): a present
/// `exp` MUST be strictly after `now` (RFC 7519 §4.1.4 exclusive upper bound); a present `ttl` requires
/// `iat + ttl >= now` (past that instant the cached token is stale and MUST be refetched). A negative
/// `ttl`, or an `iat + ttl` overflow, is malformed → `None`.
///
/// **Residual (spec-permitted):** `exp` and `ttl` are both RECOMMENDED, not REQUIRED (draft §5), so a
/// token carrying NEITHER has unbounded validity — a MITM/poisoned-cache replay of a stale pre-revocation
/// token would then authenticate. This is an issuer-configuration / transport-freshness concern, NOT a
/// verifier defect: enforcing "exp-or-ttl required" here would false-reject conformant tokens. The host
/// owns transport freshness (it fetched the token); the issuer SHOULD set `exp`/`ttl`. Documented in
/// `standards-conformance.md`.
fn check_status_token_time(iat: i64, exp: Option<i64>, ttl: Option<i64>, now: i64) -> Option<()> {
    if let Some(exp) = exp {
        if now >= exp {
            return None; // expired
        }
    }
    if let Some(ttl) = ttl {
        if ttl < 0 {
            return None; // a TTL is a non-negative number of seconds
        }
        let freshness_deadline = iat.checked_add(ttl)?;
        if freshness_deadline < now {
            return None; // stale cached token
        }
    }
    Some(())
}

/// zlib-inflate (RFC 1950) the `lst` bitstring with a [`MAX_STATUS_LIST_BYTES`] output cap; `None` on
/// any decompression failure or if the output would exceed the cap (fail-closed).
fn decompress_status_list(compressed: &[u8]) -> Option<Vec<u8>> {
    miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(compressed, MAX_STATUS_LIST_BYTES).ok()
}

/// Read the `bits`-wide status entry at `idx` from the decompressed bitstring, LSB-first within each
/// byte (draft-ietf-oauth-status-list-21 §4): `bit_pos = idx*bits`, `value = (byte[bit_pos/8] >>
/// (bit_pos%8)) & ((1<<bits)-1)`. For `bits ∈ {1,2,4,8}` an entry never straddles a byte. `None` when
/// `idx*bits` is out of range (short/malformed list) — an out-of-range `idx` is NEVER treated as valid.
fn extract_status_value(bytes: &[u8], idx: u64, bits: u8) -> Option<u8> {
    let bit_pos = idx.checked_mul(u64::from(bits))?;
    // `bytes.get(byte_index)` is the authoritative bound: `byte_index = idx*bits/8 >= bytes.len()`
    // means `idx*bits` is outside `bytes.len()*8`, i.e. this entry is not covered by the list.
    let byte_index = usize::try_from(bit_pos / 8).ok()?;
    let bit_offset = u32::try_from(bit_pos % 8).ok()?;
    let byte = *bytes.get(byte_index)?;
    let mask = ((1u16 << bits) - 1) as u8; // u16 shift so `bits == 8` yields 0xFF without overflow
    Some((byte >> bit_offset) & mask)
}

/// Map a Token Status List status value to the canonical [`StatusOutcome`]
/// (draft-ietf-oauth-status-list-21 §7.1 registry): `0x00` VALID → [`StatusOutcome::Good`]; `0x01`
/// INVALID (revoked) and `0x02` SUSPENDED → [`StatusOutcome::Revoked`] (a suspended credential is
/// currently invalid, so the always-on bar fails it like revoked); any OTHER value (application-
/// specific / reserved) → [`StatusOutcome::Unavailable`] — an unknown status is NEVER coerced to
/// `Good`.
const fn status_value_to_outcome(value: u8) -> StatusOutcome {
    match value {
        0x00 => StatusOutcome::Good,
        0x01 | 0x02 => StatusOutcome::Revoked,
        _ => StatusOutcome::Unavailable,
    }
}

/// Validate the Status List `bits` field (entry width): only `1`, `2`, `4`, `8` are defined
/// (draft-ietf-oauth-status-list-21 §4); any other value → `None` (malformed).
fn validate_bits(n: u64) -> Option<u8> {
    matches!(n, 1 | 2 | 4 | 8).then_some(n as u8)
}

/// Parse the Token Status List reference an **SD-JWT VC** declares, from its already-parsed `status`
/// claim value (draft-ietf-oauth-status-list-21 §8): `status → status_list → { idx, uri }`. Note the
/// wire key is **`idx`** (not `index`); it maps onto [`StatusReference::StatusList`]'s `index` field.
/// Returns [`StatusReference::None`] when NO `status_list` object is present at all (genuinely no Token
/// Status List mechanism — the caller applies its own policy to the absent reference), but
/// [`StatusReference::Malformed`] when a `status_list` object IS present yet unusable (empty/absent
/// `uri`, absent/non-integer `idx`, or wrong types): a declared-but-uninterpretable reference MUST fail
/// closed, never fall through to a positional `Good`. This is a pure parser — it reaches into no other
/// module (layer 2 threads the claim in).
#[must_use]
pub fn status_reference_from_sd_jwt_claim(status_claim: &serde_json::Value) -> StatusReference {
    let Some(status_list) = status_claim.get("status_list") else {
        return StatusReference::None;
    };
    match (
        status_list.get("idx").and_then(JsonValue::as_u64),
        status_list.get("uri").and_then(JsonValue::as_str),
    ) {
        (Some(index), Some(uri)) if !uri.is_empty() => StatusReference::StatusList {
            index,
            uri: uri.to_owned(),
        },
        // A `status_list` object IS present but its `idx`/`uri` are absent/ill-typed/empty — a declared
        // status mechanism the core cannot evaluate → fail closed (never a positional `Good` fall-through).
        _ => StatusReference::Malformed,
    }
}

/// Parse the Token Status List reference an **mdoc** declares, from the already-parsed MSO `status`
/// element (draft-ietf-oauth-status-list-21 §8): a CBOR map `status_list → { idx (uint), uri (tstr) }`
/// with TEXT keys. As with the SD-JWT VC form the wire key is **`idx`**; it maps onto
/// [`StatusReference::StatusList`]'s `index`. Returns [`StatusReference::None`] when NO `status_list`
/// element is present at all, but [`StatusReference::Malformed`] when a `status_list` element IS present
/// yet unusable (empty/absent `uri`, absent/non-integer `idx`, or wrong types): a declared-but-
/// uninterpretable reference MUST fail closed, never fall through to a positional `Good`. Pure parser —
/// reaches into no other module (layer 2 threads the element in).
#[must_use]
pub fn status_reference_from_mdoc_status(status_cbor: &ciborium::value::Value) -> StatusReference {
    // The MSO `status` element uses TEXT keys — read via the shared [`crate::mdoc::get_map_entry`] (3a).
    let Some(status_list) = crate::mdoc::get_map_entry(status_cbor, "status_list") else {
        return StatusReference::None;
    };
    match (
        crate::mdoc::get_map_entry(status_list, "idx").and_then(cbor_u64),
        crate::mdoc::get_map_entry(status_list, "uri").and_then(CborValue::as_text),
    ) {
        (Some(index), Some(uri)) if !uri.is_empty() => StatusReference::StatusList {
            index,
            uri: uri.to_owned(),
        },
        // A `status_list` element IS present but its `idx`/`uri` are absent/ill-typed/empty → fail closed.
        _ => StatusReference::Malformed,
    }
}

#[cfg(test)]
mod tests;
