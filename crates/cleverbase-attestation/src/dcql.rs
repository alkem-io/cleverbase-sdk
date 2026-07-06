//! In-core OpenID4VP 1.0 **DCQL** (Digital Credentials Query Language) model + evaluator.
//!
//! This module is the "did I get what I requested" gate the verifier was missing (conformance-audit
//! Theme 4 / T4.1): the always-on bar proves a presentation is cryptographically sound, trusted, and
//! request-bound, but it never checked that the credential **matches the DCQL request** — so a
//! trusted, freshly-bound credential of the **wrong** `vct`/`docType`, or one missing a requested
//! claim, used to pass as VALID (a false-trust). The DCQL is no longer carried opaquely: it is parsed
//! and evaluated **in-core** (the explicit product decision — full DCQL evaluation in-core, not
//! delegated to the wallet, per OpenID4VP 1.0 §"Security Checks on the Returned Credentials and
//! Presentations": *"the Verifier MUST NOT rely on the Wallet to enforce these constraints"*).
//!
//! ## Specification (verified online, not from training data)
//!
//! OpenID4VP **1.0** — <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html>; source
//! `openid/OpenID4VP` `1.0/openid-4-verifiable-presentations-1_0.md`:
//!
//! - **§6 Digital Credentials Query Language (DCQL)** — top-level `credentials` (REQUIRED, non-empty
//!   array of Credential Queries) + `credential_sets` (OPTIONAL); *"Implementations MUST ignore any
//!   unknown properties."*
//! - **§6.1 Credential Query** — `id` (REQUIRED), `format` (REQUIRED), `multiple` (default `false`),
//!   `meta` (REQUIRED; format-specific), `claims` (OPTIONAL), `claim_sets` (OPTIONAL),
//!   `require_cryptographic_holder_binding` (default `true`).
//! - **§6.2 Credential Set Query** — `options` (REQUIRED, array of arrays of credential `id`s),
//!   `required` (default `true`).
//! - **§6.3 Claims Query** — `id` (REQUIRED iff `claim_sets` present), `path` (REQUIRED, a Claims Path
//!   Pointer), `values` (OPTIONAL, non-empty array of strings/integers/booleans).
//! - **§"Claims Path Pointer"** — a non-empty array of strings (object key), non-negative integers
//!   (array index), and `null` (all array elements) for JSON-based credentials (SD-JWT VC); exactly two
//!   string components `[namespace, dataElementIdentifier]` for ISO mdoc credentials.
//! - **§"Selecting Claims"** — `claims` absent ⇒ no SD claims requested; `claims` present and
//!   `claim_sets` absent ⇒ all listed claims requested; both present ⇒ one `claim_sets` option (the
//!   first satisfiable); `claim_sets` MUST NOT be present if `claims` is absent.
//! - **§"Selecting Credentials"** — no `credential_sets` ⇒ all `credentials` requested; otherwise all
//!   `required` (or `required`-omitted) Credential Set Queries + optionally any non-required ones.
//! - **§"VP Token Validation"** — step 2.2: *"Validate that the returned Credential(s) meet all
//!   criteria defined in the query in the Authorization Request (e.g., Claims included in the
//!   presentation)."*; step 3: *"Check that the set of Presentations returned satisfies all
//!   requirements defined in the Verifier's request as described in [Selecting Claims and
//!   Credentials]."*
//! - Format meta — SD-JWT VC `vct_values` (§"Parameter in the `meta` parameter ... `vct_values`"); mdoc
//!   `doctype_value` (§"Parameter in the `meta` parameter ... `doctype_value`").
//!
//! ## What this module enforces (and what it deliberately does not)
//!
//! It parses the DCQL query and, against a presentation the always-on bar already accepted, checks
//! (a) **format**, (b) **meta** (SD-JWT VC `vct` ∈ `vct_values`; mdoc `docType` == `doctype_value`),
//! (c) every requested **claim path** resolves in the **claims present in the verified presentation**
//! (honoring `claim_sets`), and (d) a claim's presented value ∈ its `values`. The set-level check
//! (§"VP Token Validation" step 3 + §"Selecting Credentials") is [`crate::openid4vp::verify_vp_token`].
//!
//! Value matching follows §6.3: for an ISO mdoc the CBOR value is matched after conversion to JSON
//! (RFC 8949 §6.1) — the SDK's [`AttributeValue`] is already that decoded JSON-shaped value, so a
//! `Text`/`Integer`/`Boolean` is matched against a string/integer/boolean respectively.
//!
//! Claim paths resolve against the **full set of claims present in the verified presentation** — the
//! claims the holder actually presented, whether **selectively disclosed** OR carried in the **clear**
//! (non-selectively-disclosable). Per OpenID4VP 1.0 §8.6 "VP Token Validation" step 2.2 a Verifier
//! validates the query against the "Claims included in the presentation", and §6.4 notes a presentation
//! legitimately carries non-selectively-disclosable claims — so a clear subject claim satisfies a query
//! exactly as a disclosed one does. For SD-JWT VC this is the clear issuer-signed payload claims MERGED
//! with the disclosed claims (the caller passes `crate::sdjwtvc::presented_claims`); for mdoc the
//! namespace-grouped `disclosed_attributes` is already the full presented set (the `IssuerSignedItems`).
//! This is broader than the privacy-minimal [`crate::types::VerificationResult::disclosed_attributes`]
//! the verifier reports to the host, which omits the clear claims.
//!
//! `trusted_authorities` (§6.1.1) is not evaluated here (issuer trust is the always-on bar's per-role
//! anchoring); `require_cryptographic_holder_binding:false` is not honored (the SDK always requires
//! holder binding — a documented secure default).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::types::{AttributeValue, Format, IssuerRole};

/// The EUDI **PID** type identifiers used for role derivation (conformance-audit T4.3). Verified
/// online against the EUDI ARF PID Rulebook: the mdoc PID `docType` / namespace is
/// `eu.europa.ec.eudi.pid.1`, and the SD-JWT VC PID base `vct` is `urn:eudi:pid:1` (the older
/// `eu.europa.ec.eudi.pid.1` form is also recognized for the transition). Source:
/// <https://eudi.dev/1.7.1/annexes/annex-3/annex-3.01-pid-rulebook/>.
const SD_JWT_VC_PID_VCTS: &[&str] = &["urn:eudi:pid:1", "eu.europa.ec.eudi.pid.1"];
/// The ISO mdoc EUDI **PID** `docType` (EUDI ARF PID Rulebook). See [`SD_JWT_VC_PID_VCTS`].
const MDOC_PID_DOCTYPE: &str = "eu.europa.ec.eudi.pid.1";

/// The OpenID4VP 1.0 Credential Format Identifier for SD-JWT VC (Appendix B). `vc+sd-jwt` is the legacy
/// value accepted transitionally (mirrors the issuer-JWS `typ` transition in [`crate::sdjwtvc`]).
const FORMAT_SD_JWT_VC: &[&str] = &["dc+sd-jwt", "vc+sd-jwt"];
/// The OpenID4VP 1.0 Credential Format Identifier for ISO mdoc (Appendix B).
const FORMAT_MSO_MDOC: &str = "mso_mdoc";

/// A parsed OpenID4VP 1.0 DCQL query (§6). Carries only the credential/claim/set constraints this SDK
/// evaluates; unknown top-level and per-object properties are ignored (§6 *"Implementations MUST ignore
/// any unknown properties"*).
///
/// [`parse`](Self::parse) is **lenient** about entries it cannot enforce, but only up to the point that
/// leniency stays fail-closed. A Credential Query whose `format` this SDK does not support (or that
/// lacks an `id`/`format`) is dropped from [`Self::credentials`] — it cannot be satisfied by either
/// supported format, so it imposes no enforceable in-core constraint on a presentation of a supported
/// format. But once the `format` IS supported, a structurally-malformed `claims`/`path`/`values`/
/// `claim_sets` does NOT drop the query: dropping it would collapse `credentials` toward empty and
/// silently disable the "did I get what I requested" gate (`evaluate_single` → `Inactive`) — a
/// fail-OPEN. Such a query is kept ALIVE but UNSATISFIABLE (via the never-resolving
/// [`PathComponent::Unrepresentable`] / [`ClaimValue::Unrepresentable`] sentinels and never-matching
/// `claim_sets` options), so the gate runs and returns `NotSatisfied` (fail closed). A single bad entry
/// thus never disables the gate for the rest. `parse` errors only on a non-JSON / non-object input or a
/// duplicate credential `id`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DcqlQuery {
    /// The Credential Queries this SDK can evaluate (supported format + well-formed), in request order.
    pub credentials: Vec<CredentialQuery>,
    /// The Credential Set Queries (§6.2) constraining which combinations of credentials are required.
    pub credential_sets: Vec<CredentialSetQuery>,
}

/// One OpenID4VP 1.0 Credential Query (§6.1): a request for a presentation of a matching credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialQuery {
    /// The `id` identifying this credential in the `vp_token` response and in `credential_sets`.
    pub id: String,
    /// The requested credential format.
    pub format: Format,
    /// The format-specific `meta` constraint (SD-JWT VC `vct_values`; mdoc `doctype_value`).
    pub meta: CredentialMeta,
    /// The requested claims (§6.3); empty when the query lists no selectively-disclosable claims.
    pub claims: Vec<ClaimsQuery>,
    /// The `claim_sets`: alternative combinations of claim `id`s, in Verifier preference order. Empty
    /// when absent (then all of [`Self::claims`] are requested — §"Selecting Claims").
    pub claim_sets: Vec<Vec<String>>,
    /// Whether more than one Presentation may be returned for this query (§6.1 `multiple`, default
    /// `false`).
    pub multiple: bool,
}

/// The format-specific `meta` constraint of a [`CredentialQuery`] (§6.1 `meta`). A `None` constraint
/// means the `meta` placed no type restriction (`meta` absent/empty — §6.1 *"If empty, no specific
/// constraints are placed on the metadata"*).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialMeta {
    /// SD-JWT VC `meta.vct_values` (§"... `vct_values`"): the allowed `vct` values. `None` ⇒ no `vct`
    /// constraint.
    SdJwtVc {
        /// The allowed `vct` values (a non-empty array when present).
        vct_values: Option<Vec<String>>,
    },
    /// ISO mdoc `meta.doctype_value` (§"... `doctype_value`"): the allowed `docType`. `None` ⇒ no
    /// `docType` constraint.
    Mdoc {
        /// The single allowed `docType`.
        doctype_value: Option<String>,
    },
}

/// One OpenID4VP 1.0 Claims Query (§6.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimsQuery {
    /// The claim `id` (REQUIRED iff the owning query has `claim_sets`; OPTIONAL otherwise).
    pub id: Option<String>,
    /// The Claims Path Pointer to the claim (§"Claims Path Pointer"); always non-empty.
    pub path: Vec<PathComponent>,
    /// The expected values (§6.3 `values`): a present, non-empty set the disclosed value must be in.
    pub values: Option<Vec<ClaimValue>>,
}

/// One component of a Claims Path Pointer (§"Claims Path Pointer").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathComponent {
    /// A string component: select the value at this object key.
    Key(String),
    /// A non-negative-integer component: select this 0-based index of an array.
    Index(u64),
    /// A `null` component: select all elements of the currently selected array(s).
    AllElements,
    /// A path component that is NOT a valid Claims Path Pointer element (§"Claims Path Pointer"
    /// admits only strings, non-negative integers, and `null`) — a JSON float, a negative index, or a
    /// nested object/array. Mirrors [`ClaimValue::Unrepresentable`]: it is retained as an explicit
    /// NEVER-resolving sentinel rather than dropped, because dropping it would collapse the whole
    /// Credential Query (via the lenient parse), leaving `evaluate_single` `Inactive` and the "did I
    /// get what I requested" gate silently disabled — a fail-OPEN. Keeping it unresolvable keeps the
    /// query enforced (the claim simply never resolves → `NotSatisfied`, fail closed). Never produced
    /// from a spec-valid path component.
    Unrepresentable,
}

/// An expected claim value (§6.3 `values`: *"an array of strings, integers or boolean values"*).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimValue {
    /// A string value.
    Text(String),
    /// An integer value.
    Integer(i64),
    /// A boolean value.
    Boolean(bool),
    /// A numeric `values` entry that is NOT representable as the comparison type (`i64`) — a JSON
    /// float, or an integer outside `i64` range. Such a value can never equal a disclosed
    /// string/integer/boolean, so it is retained as an explicit NEVER-matching sentinel rather than
    /// dropped: dropping it would collapse the whole Credential Query (via the lenient parse), leaving
    /// `evaluate_single` `Inactive` and the "did I get what I requested" gate silently disabled — a
    /// fail-OPEN. Keeping it as unmatchable keeps the query enforced (the claim simply never resolves →
    /// `NotSatisfied`, fail-closed). Never produced from a spec-valid, representable value.
    Unrepresentable,
}

/// One OpenID4VP 1.0 Credential Set Query (§6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialSetQuery {
    /// The `options`: each is a set of credential `id`s that satisfies this use case (§6.2). One option
    /// is satisfied iff every credential `id` it lists is satisfied.
    pub options: Vec<Vec<String>>,
    /// Whether this set is required to satisfy the request (§6.2 `required`, default `true`).
    pub required: bool,
}

/// A failure parsing the DCQL JSON into a [`DcqlQuery`]. Only a truly unusable input (non-JSON, or a
/// JSON value that is not an object) errors; malformed/unsupported sub-entries are dropped leniently.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DcqlError {
    /// The query text is not valid JSON.
    #[error("DCQL query is not valid JSON")]
    Json,
    /// The query is valid JSON but not a JSON object (§6: a DCQL query is a JSON object).
    #[error("DCQL query is not a JSON object")]
    NotAnObject,
    /// Two Credential Queries share the same `id` (§6.1: credential `id`s MUST be unique). A duplicate
    /// is rejected rather than silently last-wins — otherwise the set-level `by_id` lookup
    /// ([`crate::openid4vp::verify_vp_token`]) would evaluate a presentation against the WRONG query.
    #[error("DCQL query has duplicate credential ids")]
    DuplicateCredentialId,
}

impl DcqlQuery {
    /// Parse a DCQL query from its JSON text (§6).
    ///
    /// Lenient by contract (see the type docs): unsupported-format or malformed Credential Queries /
    /// Credential Set Queries are dropped rather than failing the whole parse, so one bad entry never
    /// disables enforcement for the rest. Errors only on a non-JSON / non-object input.
    ///
    /// # Errors
    ///
    /// [`DcqlError::Json`] if the text is not JSON; [`DcqlError::NotAnObject`] if it is not a JSON
    /// object.
    pub fn parse(json: &str) -> Result<Self, DcqlError> {
        let value: Value = serde_json::from_str(json).map_err(|_| DcqlError::Json)?;
        let object = value.as_object().ok_or(DcqlError::NotAnObject)?;
        let credentials: Vec<CredentialQuery> = object
            .get("credentials")
            .and_then(Value::as_array)
            .map(|entries| entries.iter().filter_map(CredentialQuery::parse).collect())
            .unwrap_or_default();
        // §6.1: credential `id`s MUST be unique. Reject a duplicate rather than silently last-wins in
        // the set-level `by_id` map (which would apply one query's constraints to another credential).
        let mut seen_ids = BTreeSet::new();
        if credentials.iter().any(|c| !seen_ids.insert(c.id.as_str())) {
            return Err(DcqlError::DuplicateCredentialId);
        }
        let credential_sets = object
            .get("credential_sets")
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(CredentialSetQuery::parse)
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self {
            credentials,
            credential_sets,
        })
    }
}

impl CredentialQuery {
    /// Parse one Credential Query (§6.1), returning `None` to drop an entry this SDK cannot evaluate:
    /// a non-object, a missing/empty `id` (unreferenceable), or an unsupported/absent `format` (no
    /// supported presentation could satisfy it, so it imposes no enforceable in-core constraint).
    ///
    /// Once the `format` IS supported, a structurally-malformed `claims`/`path`/`values`/`claim_sets`
    /// must NOT drop the query — that would collapse [`DcqlQuery::credentials`] toward empty and leave
    /// `evaluate_single` `Inactive` (fail-OPEN). Such a query is kept ALIVE but UNSATISFIABLE (via the
    /// never-resolving [`PathComponent::Unrepresentable`] / [`ClaimValue::Unrepresentable`] sentinels)
    /// so the gate runs and returns `NotSatisfied` (fail closed).
    fn parse(value: &Value) -> Option<Self> {
        let object = value.as_object()?;
        let id = object
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())?
            .to_owned();
        let format = format_from_identifier(object.get("format").and_then(Value::as_str)?)?;
        let meta = CredentialMeta::parse(format, object.get("meta"));
        let multiple = object
            .get("multiple")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        // `claims` (§6.3): absent ⇒ no claim constraint (KEEP, no constraint). A present non-empty
        // array ⇒ one claim per entry (parse is infallible — a malformed entry becomes an unsatisfiable
        // claim, never dropped). A present EMPTY array or NON-array is itself malformed (§6.3 requires a
        // non-empty array) ⇒ keep the query with a single unsatisfiable claim so it fails CLOSED, rather
        // than dropping it to a fail-open `Inactive`.
        let claims = match object.get("claims") {
            None => Vec::new(),
            Some(Value::Array(entries)) if !entries.is_empty() => {
                entries.iter().map(ClaimsQuery::parse).collect()
            }
            Some(_) => vec![ClaimsQuery::unsatisfiable()],
        };
        // `claim_sets` (§6.1): a malformed value must NOT drop the query (fail-open) — `parse_claim_sets`
        // is infallible and yields never-matching options for malformed input, so the query stays
        // enforceable and fails closed.
        let claim_sets = object
            .get("claim_sets")
            .map_or_else(Vec::new, parse_claim_sets);
        // §"Selecting Claims": `claim_sets` MUST NOT be present if `claims` is absent (it would
        // reference nothing). A present `claim_sets` with no `claims` legitimately drops.
        if !claim_sets.is_empty() && claims.is_empty() {
            return None;
        }
        Some(Self {
            id,
            format,
            meta,
            claims,
            claim_sets,
            multiple,
        })
    }
}

impl CredentialMeta {
    /// Parse the format-specific `meta` constraint. An absent/empty `meta` (or a `meta` lacking the
    /// type field) yields a `None` constraint (§6.1 *"If empty, no specific constraints"*) rather than a
    /// parse failure, so the gate degrades to a format+claims check instead of disabling itself.
    fn parse(format: Format, meta: Option<&Value>) -> Self {
        let object = meta.and_then(Value::as_object);
        match format {
            Format::SdJwtVc => {
                let vct_values = object
                    .and_then(|map| map.get("vct_values"))
                    .and_then(Value::as_array)
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(|v| v.as_str().map(str::to_owned))
                            .collect::<Vec<_>>()
                    })
                    .filter(|values| !values.is_empty());
                Self::SdJwtVc { vct_values }
            }
            Format::Mdoc => {
                let doctype_value = object
                    .and_then(|map| map.get("doctype_value"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                Self::Mdoc { doctype_value }
            }
        }
    }
}

impl ClaimsQuery {
    /// Parse one Claims Query (§6.3). Infallible by contract: a structurally-malformed entry (a
    /// non-object, a missing / non-array / empty `path`, an invalid path component, or a
    /// present-but-malformed `values`) is kept as an UNSATISFIABLE claim — via the never-resolving
    /// [`PathComponent::Unrepresentable`] / [`ClaimValue::Unrepresentable`] sentinels — rather than
    /// dropped, so it cannot collapse the owning Credential Query into a fail-open `Inactive` (see the
    /// sentinel docs). A missing `id` stays `None` (only `claim_sets` references need one).
    fn parse(value: &Value) -> Self {
        let Some(object) = value.as_object() else {
            // A non-object claim entry is malformed → unsatisfiable, never dropped.
            return Self::unsatisfiable();
        };
        let id = object
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .map(str::to_owned);
        // A present `path` is parsed (a malformed one becomes `[Unrepresentable]`); an ABSENT `path`
        // (REQUIRED §6.3) is likewise malformed → the same never-resolving sentinel, not a drop.
        let path = object
            .get("path")
            .map_or_else(|| vec![PathComponent::Unrepresentable], parse_path);
        // An absent `values` ⇒ no value restriction (`None`); a present `values` is parsed (a malformed
        // one becomes `[Unrepresentable]`, never dropped — see `parse_values`).
        let values = object.get("values").map(parse_values);
        Self { id, path, values }
    }

    /// An UNSATISFIABLE claim: a never-resolving path ([`PathComponent::Unrepresentable`]), no `id`, no
    /// `values`. Used where a present but structurally-malformed `claims` (a non-array or empty array —
    /// §6.3 requires a non-empty array of Claims Queries) must keep the Credential Query ALIVE but
    /// unsatisfiable rather than dropping it into a fail-open `Inactive`.
    fn unsatisfiable() -> Self {
        Self {
            id: None,
            path: vec![PathComponent::Unrepresentable],
            values: None,
        }
    }
}

impl CredentialSetQuery {
    /// Parse one Credential Set Query (§6.2), returning `None` for a malformed entry.
    fn parse(value: &Value) -> Option<Self> {
        let object = value.as_object()?;
        let options = object
            .get("options")?
            .as_array()?
            .iter()
            .map(parse_id_list)
            .collect::<Option<Vec<_>>>()?;
        if options.is_empty() {
            return None;
        }
        let required = object
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        Some(Self { options, required })
    }
}

/// Map an OpenID4VP 1.0 Credential Format Identifier (Appendix B) to the SDK [`Format`]; `None` for a
/// format this SDK does not support (the entry is then dropped from the evaluable set).
fn format_from_identifier(identifier: &str) -> Option<Format> {
    if FORMAT_SD_JWT_VC.contains(&identifier) {
        Some(Format::SdJwtVc)
    } else if identifier == FORMAT_MSO_MDOC {
        Some(Format::Mdoc)
    } else {
        None
    }
}

/// Parse a Claims Path Pointer array (§"Claims Path Pointer"): a non-empty array of strings, `null`s,
/// and non-negative integers. Infallible: a non-array OR an empty array is a present-but-malformed
/// `path` (§6.3 `path` is REQUIRED and non-empty) and yields a single never-resolving
/// [`PathComponent::Unrepresentable`] — never dropped, so a bad path cannot collapse the owning
/// Credential Query into a fail-open `Inactive`. A non-empty array maps each component.
fn parse_path(value: &Value) -> Vec<PathComponent> {
    match value.as_array() {
        Some(array) if !array.is_empty() => array.iter().map(parse_path_component).collect(),
        _ => vec![PathComponent::Unrepresentable],
    }
}

/// Parse one Claims Path Pointer component (§"Claims Path Pointer"): a string ⇒ object key, a `null` ⇒
/// all array elements, a non-negative integer ⇒ array index. Anything else (a float, a negative index,
/// a nested object/array) ⇒ [`PathComponent::Unrepresentable`] — retained (not dropped) so it cannot
/// collapse the whole Credential Query and silently disable the claims gate (it just never resolves).
fn parse_path_component(value: &Value) -> PathComponent {
    match value {
        Value::String(key) => PathComponent::Key(key.clone()),
        Value::Null => PathComponent::AllElements,
        Value::Number(number) => number
            .as_u64()
            .map_or(PathComponent::Unrepresentable, PathComponent::Index),
        _ => PathComponent::Unrepresentable,
    }
}

/// Parse a `values` array (§6.3): a non-empty array of strings/integers/booleans. Infallible: a
/// non-array OR an empty array is a present-but-malformed `values` and yields a single never-matching
/// [`ClaimValue::Unrepresentable`] — never dropped, so it cannot collapse the owning Credential Query
/// into a fail-open `Inactive`. A non-empty array maps each element.
fn parse_values(value: &Value) -> Vec<ClaimValue> {
    match value.as_array() {
        Some(array) if !array.is_empty() => array.iter().map(parse_claim_value).collect(),
        _ => vec![ClaimValue::Unrepresentable],
    }
}

/// Parse one expected value (§6.3): a string, integer, or boolean. A non-scalar (array/object/null), or
/// a numeric value not representable as `i64` (a float, or an out-of-`i64`-range integer), is retained
/// as [`ClaimValue::Unrepresentable`] — NOT dropped — so it cannot collapse the whole Credential Query
/// and silently disable the claims gate (it just never matches; see the variant).
fn parse_claim_value(value: &Value) -> ClaimValue {
    match value {
        Value::String(text) => ClaimValue::Text(text.clone()),
        Value::Bool(boolean) => ClaimValue::Boolean(*boolean),
        Value::Number(number) => number
            .as_i64()
            .map_or(ClaimValue::Unrepresentable, ClaimValue::Integer),
        _ => ClaimValue::Unrepresentable,
    }
}

/// Parse `claim_sets` (§6.1): an array of arrays of claim-`id` strings. Infallible: a non-array value,
/// or a malformed element (a non-array, or a list containing a non-string id — where `parse_id_list`
/// returns `None`), yields an option referencing the impossible empty id (real claim ids are
/// parser-guaranteed non-empty in `claims_satisfied`'s `by_id`, so `""` can never match) instead of
/// dropping the whole Credential Query to a fail-open `Inactive`. Such an option is non-empty (so it is
/// not silently satisfied by the empty-option guard) yet unsatisfiable → the query fails CLOSED.
fn parse_claim_sets(value: &Value) -> Vec<Vec<String>> {
    value.as_array().map_or_else(
        || vec![vec![String::new()]],
        |entries| {
            entries
                .iter()
                .map(|entry| parse_id_list(entry).unwrap_or_else(|| vec![String::new()]))
                .collect()
        },
    )
}

/// Parse one array of identifier strings (a `claim_sets` element or a `credential_sets` option).
fn parse_id_list(value: &Value) -> Option<Vec<String>> {
    value
        .as_array()?
        .iter()
        .map(|id| id.as_str().map(str::to_owned))
        .collect()
}

// =================================================================================================
// Evaluation — the "did I get what I requested" satisfaction logic (§"VP Token Validation" step 2.2).
// =================================================================================================

/// The verified credential type surfaced from the always-on bar, the input the DCQL `meta` match keys
/// on: the SD-JWT VC `vct` (signature-verified clear-payload claim) or the ISO mdoc `docType`(s) (the
/// signed MSO `docType`, one per verified document).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CredentialType {
    /// The verified SD-JWT VC `vct` (`None` when unreadable).
    Vct(Option<String>),
    /// The verified ISO mdoc `docType`(s), one per document in the `DeviceResponse`.
    DocTypes(Vec<String>),
}

/// The outcome of the in-core single-presentation DCQL gate (§"VP Token Validation" step 2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DcqlGate {
    /// No enforceable DCQL constraint (empty/legacy/unparseable query, or no supported Credential
    /// Query) — the gate imposes nothing, preserving the prior opaque behavior.
    Inactive,
    /// The presentation satisfies at least one Credential Query of its format.
    Satisfied,
    /// The presentation satisfies no Credential Query — the verifier did not get what it requested.
    NotSatisfied,
}

/// Derive the EUDI **PID** trust-anchoring role from a credential's claimed type, or `None` when the
/// type has no standardized role mapping (conformance-audit T4.3). See [`SD_JWT_VC_PID_VCTS`].
pub(crate) fn role_from_type(format: Format, type_id: &str) -> Option<IssuerRole> {
    let is_pid = match format {
        Format::SdJwtVc => SD_JWT_VC_PID_VCTS.contains(&type_id),
        Format::Mdoc => type_id == MDOC_PID_DOCTYPE,
    };
    is_pid.then_some(IssuerRole::Pid)
}

/// Reconcile the caller-supplied role with the credential's claimed type (conformance-audit T4.3): when
/// the type maps to a known role (EUDI PID), return that **derived** role and reject a caller role that
/// contradicts it (`Err(())` ⇒ [`crate::types::ReasonCode::RoleMismatch`]); otherwise keep the
/// caller-supplied role (no standardized mapping ⇒ nothing to validate against). The returned role is
/// the one threaded into the trust [`crate::trust::TrustAnchorSource::resolve`] call.
pub(crate) fn reconcile_role(
    caller: IssuerRole,
    format: Format,
    type_id: &str,
) -> Result<IssuerRole, ()> {
    match role_from_type(format, type_id) {
        Some(derived) if derived != caller => Err(()),
        Some(derived) => Ok(derived),
        None => Ok(caller),
    }
}

/// Derive the per-credential anchoring role from a [`CredentialQuery`]'s `meta` (its EXPECTED type) for
/// the multi-credential evaluator: a query whose `meta` names a EUDI PID type anchors under
/// [`IssuerRole::Pid`]. `None` when no PID mapping applies (the caller's default role is used).
pub(crate) fn role_from_meta(meta: &CredentialMeta) -> Option<IssuerRole> {
    match meta {
        CredentialMeta::SdJwtVc { vct_values } => {
            // Derive a role only when EVERY listed `vct` maps to the SAME role. A heterogeneous list
            // (e.g. one PID vct plus an unmapped/other type) is AMBIGUOUS — the presented credential
            // could be either — so a `find_map` that fires on the first PID member would anchor a
            // presented non-PID credential under `IssuerRole::Pid` (conformance-audit T4.3). Ambiguous
            // (or all-unmapped) ⇒ `None` ⇒ the caller's default role. `vct_values` is parser-guaranteed
            // non-empty, so `next()` yields the first entry's mapping.
            let mut roles = vct_values
                .as_ref()?
                .iter()
                .map(|vct| role_from_type(Format::SdJwtVc, vct));
            let first = roles.next()?;
            roles.all(|role| role == first).then_some(first).flatten()
        }
        CredentialMeta::Mdoc { doctype_value } => {
            role_from_type(Format::Mdoc, doctype_value.as_deref()?)
        }
    }
}

/// Evaluate the in-core single-presentation DCQL gate: does the verified presentation satisfy at least
/// one Credential Query of its format (§"VP Token Validation" step 2.2)? Run only on a presentation the
/// always-on bar already accepted. See [`DcqlGate`].
pub(crate) fn evaluate_single(
    query_json: &str,
    format: Format,
    credential_type: &CredentialType,
    presented: &BTreeMap<String, AttributeValue>,
) -> DcqlGate {
    // Empty/absent DCQL: the verifier imposed no query → Inactive (the always-on bar's verdict stands).
    if query_json.trim().is_empty() {
        return DcqlGate::Inactive;
    }
    // A NON-EMPTY query that fails to parse (malformed JSON/object, or a duplicate credential id) is a
    // verifier-authored constraint we cannot understand. It MUST NOT silently drop to Inactive
    // (fail-OPEN — the "did I get what I requested" gate would be disabled); fail closed to
    // NotSatisfied. (Contrast: a well-formed query with only unsupported-FORMAT entries parses OK to
    // empty `credentials` → Inactive below — the documented lenient case, which imposes no enforceable
    // constraint on THIS format's presentation; a supported-format entry with a bad value is kept
    // enforceable by the parsers, e.g. `ClaimValue::Unrepresentable`, so it fails closed here.)
    let Ok(query) = DcqlQuery::parse(query_json) else {
        return DcqlGate::NotSatisfied;
    };
    if query.credentials.is_empty() {
        return DcqlGate::Inactive;
    }
    if query
        .credentials
        .iter()
        .any(|candidate| query_satisfied_by(candidate, format, credential_type, presented))
    {
        DcqlGate::Satisfied
    } else {
        DcqlGate::NotSatisfied
    }
}

/// Whether a verified presentation satisfies one specific Credential Query: format + `meta` +
/// `claims`/`claim_sets`/`values` (§6.1 / §6.3 / §"Selecting Claims"; §"VP Token Validation" step 2.2).
/// `presented` is the full set of claims present in the verified presentation (clear + disclosed).
pub(crate) fn query_satisfied_by(
    query: &CredentialQuery,
    format: Format,
    credential_type: &CredentialType,
    presented: &BTreeMap<String, AttributeValue>,
) -> bool {
    format_and_meta_match(query, format, credential_type) && claims_satisfied(query, presented)
}

/// Whether the set of satisfied credential `id`s meets the request's set-level requirements
/// (§"Selecting Credentials"; §"VP Token Validation" step 3): with no `credential_sets`, every
/// `credentials` entry must be satisfied; otherwise every **required** Credential Set Query must have at
/// least one fully-satisfied `option` (non-required sets are optional).
pub(crate) fn credential_sets_satisfied(query: &DcqlQuery, satisfied: &BTreeSet<&str>) -> bool {
    if query.credential_sets.is_empty() {
        // No `credential_sets`: every listed Credential Query must be satisfied. An EMPTY `credentials`
        // list has nothing to satisfy, but "nothing requested" MUST NOT read as "request satisfied":
        // `[].all()` is vacuously true, so an unparseable/empty DCQL (the `unwrap_or_default()` a parse
        // error yields), or one whose every query was dropped as unsupported-format, would otherwise be
        // reported satisfied for any (even empty) vp_token. Fail closed — no credentials ⇒ not satisfied.
        return !query.credentials.is_empty()
            && query
                .credentials
                .iter()
                .all(|candidate| satisfied.contains(candidate.id.as_str()));
    }
    query
        .credential_sets
        .iter()
        .filter(|set| set.required)
        .all(|set| {
            set.options.iter().any(|option| {
                // An EMPTY option ("combination") requests zero credentials — `[].all()` is vacuously
                // true, which would satisfy a required set with nothing presented. Fail closed.
                !option.is_empty() && option.iter().all(|id| satisfied.contains(id.as_str()))
            })
        })
}

/// Whether the query's `format` and `meta` type constraint match the verified credential (§6.1 `meta`):
/// SD-JWT VC `vct` ∈ `vct_values`; mdoc every verified `docType` == `doctype_value`. A `None` `meta`
/// constraint matches any credential of the format. A multi-document mdoc must have EVERY document's
/// `docType` equal to `doctype_value` (so no off-type document rides along under one Credential Query).
fn format_and_meta_match(
    query: &CredentialQuery,
    format: Format,
    credential_type: &CredentialType,
) -> bool {
    if query.format != format {
        return false;
    }
    match (&query.meta, credential_type) {
        // SD-JWT VC: the verified `vct` must be one of `vct_values` (a `None` constraint matches any).
        (CredentialMeta::SdJwtVc { vct_values }, CredentialType::Vct(vct)) => {
            vct_values.as_ref().is_none_or(|allowed| {
                vct.as_deref()
                    .is_some_and(|vct| allowed.iter().any(|value| value == vct))
            })
        }
        // mdoc: EVERY verified `docType` must equal `doctype_value` (a `None` constraint matches any
        // non-empty document set) — so no off-type document rides along under one Credential Query.
        (CredentialMeta::Mdoc { doctype_value }, CredentialType::DocTypes(doc_types)) => {
            !doc_types.is_empty()
                && doctype_value
                    .as_ref()
                    .is_none_or(|expected| doc_types.iter().all(|doc_type| doc_type == expected))
        }
        // A type kind that does not match the meta kind (a format/type mix-up) never matches.
        _ => false,
    }
}

/// Whether the query's requested claims are satisfied by the claims present in the verified
/// presentation (§"Selecting Claims"): no `claims` ⇒ trivially satisfied; `claims` without `claim_sets`
/// ⇒ all must resolve; with `claim_sets` ⇒ at least one option's claims must all resolve.
fn claims_satisfied(query: &CredentialQuery, presented: &BTreeMap<String, AttributeValue>) -> bool {
    if query.claims.is_empty() {
        return true;
    }
    if query.claim_sets.is_empty() {
        return query
            .claims
            .iter()
            .all(|claim| claim_resolves(claim, presented));
    }
    // §6.3: a claim `id` referenced by `claim_sets` MUST be unique. Building `by_id` with a
    // `collect()` would silently LAST-WINS a duplicate — dropping the earlier claim's constraint (e.g.
    // its `values` restriction), a fail-OPEN. Detect the duplicate and fail CLOSED: a query whose
    // `claim_sets`-referenced claims have a duplicate id is not satisfiable (we will not honor only one
    // of two conflicting constraints).
    let mut by_id: BTreeMap<&str, &ClaimsQuery> = BTreeMap::new();
    for claim in &query.claims {
        let Some(id) = claim.id.as_deref() else {
            continue;
        };
        if by_id.insert(id, claim).is_some() {
            return false;
        }
    }
    query.claim_sets.iter().any(|set| {
        // An EMPTY claim-set option requests zero claims — `[].all()` is vacuously true, which would
        // satisfy the claims requirement with NONE of the requested claims disclosed. Fail closed.
        !set.is_empty()
            && set.iter().all(|id| {
                by_id
                    .get(id.as_str())
                    .is_some_and(|claim| claim_resolves(claim, presented))
            })
    })
}

/// Whether a single Claims Query resolves against the claims present in the presentation: its `path`
/// selects a non-empty set, and — if `values` is present (§6.3) — at least one selected value matches.
fn claim_resolves(claim: &ClaimsQuery, presented: &BTreeMap<String, AttributeValue>) -> bool {
    let selected = resolve_path(presented, &claim.path);
    if selected.is_empty() {
        return false;
    }
    // No `values` ⇒ presence is enough; with `values` ⇒ at least one selected value must match (§6.3).
    claim
        .values
        .as_ref()
        .is_none_or(|expected| selected.iter().any(|value| value_matches(value, expected)))
}

/// Process a Claims Path Pointer against the presented-claims object (§"Claims Path Pointer"
/// processing), returning the selected values. The root is the presented-claims object (clear +
/// disclosed), so the first component MUST be a key (an object root). A type mismatch (a key into a
/// non-object, an index / `null` into a non-array, or a missing key/index) drops that branch from the
/// selection — the spec's "abort with error" and this "empty selection" are verdict-equivalent for the
/// gate (both ⇒ the claim does not resolve). For an ISO mdoc the path is
/// `[namespace, dataElementIdentifier]`, i.e. a key (the namespace) into the namespace-grouped result,
/// then a key (the element identifier).
fn resolve_path<'a>(
    root: &'a BTreeMap<String, AttributeValue>,
    path: &[PathComponent],
) -> Vec<&'a AttributeValue> {
    let Some((PathComponent::Key(first), rest)) = path.split_first() else {
        // An empty path, or a path whose first component is an index/`null`/`Unrepresentable`, cannot
        // apply to the object root (§"Claims Path Pointer": the root is the top-level object) — so a
        // malformed path (first component `Unrepresentable`) selects nothing → the claim never
        // resolves (fail closed).
        return Vec::new();
    };
    let mut selected: Vec<&AttributeValue> = root.get(first).into_iter().collect();
    for component in rest {
        if selected.is_empty() {
            break;
        }
        selected = select(&selected, component);
    }
    selected
}

/// Apply one Claims Path Pointer component to the current selection (§"Claims Path Pointer"
/// processing). A type-mismatched element is dropped (verdict-equivalent to the spec's abort — see
/// [`resolve_path`]).
fn select<'a>(
    current: &[&'a AttributeValue],
    component: &PathComponent,
) -> Vec<&'a AttributeValue> {
    match component {
        PathComponent::Key(key) => current
            .iter()
            .filter_map(|value| match value {
                AttributeValue::Map(map) => map.get(key),
                _ => None,
            })
            .collect(),
        PathComponent::Index(index) => current
            .iter()
            .filter_map(|value| match value {
                AttributeValue::Array(items) => usize::try_from(*index)
                    .ok()
                    .and_then(|index| items.get(index)),
                _ => None,
            })
            .collect(),
        PathComponent::AllElements => current
            .iter()
            .flat_map(|value| match value {
                AttributeValue::Array(items) => items.iter().collect::<Vec<_>>(),
                _ => Vec::new(),
            })
            .collect(),
        // A never-resolving sentinel (an unsupported/malformed path component) selects nothing, so a
        // claim whose path contains it never resolves → `NotSatisfied` (fail closed). See
        // [`PathComponent::Unrepresentable`].
        PathComponent::Unrepresentable => Vec::new(),
    }
}

/// Whether a disclosed [`AttributeValue`] matches one of a claim's expected `values` (§6.3 value
/// matching; for ISO mdoc the CBOR value is matched as its JSON form per RFC 8949 §6.1, which the SDK's
/// already-decoded [`AttributeValue`] is). Only scalar string/integer/boolean values can match.
fn value_matches(value: &AttributeValue, expected: &[ClaimValue]) -> bool {
    expected.iter().any(|candidate| match (candidate, value) {
        (ClaimValue::Text(text), AttributeValue::Text(actual)) => text == actual,
        (ClaimValue::Integer(integer), AttributeValue::Integer(actual)) => integer == actual,
        (ClaimValue::Boolean(boolean), AttributeValue::Boolean(actual)) => boolean == actual,
        _ => false,
    })
}

#[cfg(test)]
mod tests;
